from pathlib import Path
from datetime import datetime
import json
import os
import threading
import time

BASE_DIR = Path(__file__).resolve().parents[3]


def _get_events_file() -> Path:
    """Resolve events log path: MINIFW_LOG env var → project logs/ fallback."""
    env_path = os.environ.get("MINIFW_LOG")
    if env_path:
        return Path(env_path)
    return BASE_DIR / "logs" / "events.jsonl"


# ---------------------------------------------------------------------------
# File-mtime cache — re-parses events.jsonl only when the file changes.
# Shared across all callers in the same process (dashboard, live-blocks,
# datatable, IoMT alerts), so a burst of simultaneous requests pays one
# parse cost instead of N.
# ---------------------------------------------------------------------------

class _EventsCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._mtime: float = -1.0
        self._events: list = []

    def get(self, limit: int) -> list:
        path = _get_events_file()
        if not path.exists():
            return []

        try:
            current_mtime = path.stat().st_mtime
        except OSError:
            return []

        with self._lock:
            if current_mtime != self._mtime:
                self._events = _parse_events_file(path)
                self._mtime = current_mtime

            return self._events[:limit]


_cache = _EventsCache()


def _parse_events_file(path: Path) -> list:
    """Read, parse, and sort all events. Called only when the file changes."""
    events = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(_format_event(json.loads(line)))
                except (json.JSONDecodeError, Exception):
                    continue
        events.sort(key=lambda x: x.get("time", ""), reverse=True)
    except (IOError, OSError) as e:
        print(f"Error reading events file: {e}")
    return events


def get_recent_events(limit: int = 100):
    """
    Return recent security events from the JSONL log.

    Results are served from an in-process file-mtime cache; the file is
    re-parsed only when its modification time changes, making repeated
    calls (dashboard render, 2-second live-block poll, datatable query)
    effectively free until the engine writes a new event.
    """
    return _cache.get(limit)


def _format_event(event: dict) -> dict:
    timestamp = event.get("ts", "")
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        time_str = timestamp

    action = event.get("action", "unknown")
    reasons = event.get("reasons", [])
    event_type = _determine_event_type(action, reasons, event)
    type_color = _get_action_color(action)

    domain = event.get("domain", "")
    client_ip = event.get("client_ip", "")
    source = f"{domain} ({client_ip})" if domain else client_ip

    if action == "allow":
        status = "allowed"
    elif action == "monitor":
        status = "monitor"
    else:
        status = "blocked"

    score = event.get("score", 0)
    threat_detected = (score > 0) or (action != "allow") or (len(reasons) > 0)
    reason_text = ", ".join(reasons) if reasons else "Normal traffic"

    return {
        "time": time_str,
        "type": event_type,
        "type_color": type_color,
        "source": source,
        "status": status,
        "threat_detected": threat_detected,
        "reason": reason_text,
        "score": score,
        "segment": event.get("segment", "default"),
        "client_ip": client_ip,
        "domain": domain,
    }


def _determine_event_type(action: str, reasons: list, event: dict) -> str:
    if reasons:
        r = str(reasons).lower()
        if "ip" in r:
            return "IP Block"
        if "domain" in r:
            return "Domain Block"
        if "asn" in r:
            return "ASN Block"
        if "burst" in r or "rate" in r:
            return "Rate Limit"
        return "Security Block"

    if action == "allow":
        return "Domain Allow" if event.get("domain") else "Traffic Allow"
    if action in ("block", "deny"):
        return "Traffic Block"
    return "Unknown"


def _get_action_color(action: str) -> str:
    return {"allow": "success", "block": "danger", "deny": "danger",
            "warn": "warning"}.get(action.lower(), "secondary")


def _get_sample_events():
    return []


def get_event_statistics(events=None):
    if events is None:
        events = get_recent_events(limit=500)
    stats = {"total_allowed": 0, "total_blocked": 0, "threats_detected": 0}
    for ev in events:
        s = ev.get("status")
        if s == "allowed":
            stats["total_allowed"] += 1
        elif s == "blocked":
            stats["total_blocked"] += 1
        if ev.get("threat_detected"):
            stats["threats_detected"] += 1
    return stats


def get_detection_counters(events=None):
    if events is None:
        events = get_recent_events(limit=500)
    counters = {
        "hard_gate": 0, "ai_scored": 0, "yara": 0,
        "dns_tunnel": 0, "port_scan": 0, "tor_anon": 0, "sni_hits": 0,
    }
    for ev in events:
        r = ev.get("reason", "").lower()
        if "hard_threat_gate" in r:   counters["hard_gate"]  += 1
        if "mlp_threat_score" in r:   counters["ai_scored"]  += 1
        if "yara" in r:               counters["yara"]       += 1
        if "dns_tunnel" in r:         counters["dns_tunnel"] += 1
        if "port_scan" in r or "pps" in r: counters["port_scan"] += 1
        if "tor" in r or "anonymizer" in r: counters["tor_anon"] += 1
        if "tls_sni" in r or "sni_deny" in r or "sni" in r: counters["sni_hits"] += 1
    return counters


# ---------------------------------------------------------------------------
# Collector status — TTL cache (10 s).  Reads policy.json + 3 stat() calls;
# not worth repeating on every dashboard render or live-blocks poll.
# ---------------------------------------------------------------------------

class _TTLCache:
    """Generic TTL cache for a single computed value."""
    def __init__(self, ttl: float):
        self._ttl = ttl
        self._value = None
        self._expires = 0.0
        self._lock = threading.Lock()

    def get_or_compute(self, fn):
        now = time.monotonic()
        with self._lock:
            if now < self._expires:
                return self._value
            self._value = fn()
            self._expires = now + self._ttl
            return self._value


_collector_cache = _TTLCache(ttl=10.0)


def get_collector_status():
    """
    Check live status of data collectors: Zeek TLS, DNS (dnsmasq), flow tracking.
    Result is cached for 10 seconds to avoid repeated policy.json reads.
    """
    return _collector_cache.get_or_compute(_compute_collector_status)


def _compute_collector_status() -> dict:
    _default_dns_log = "/var/log/dnsmasq.log"
    policy_path = os.environ.get("MINIFW_POLICY", "/opt/minifw_ai/config/policy.json")
    try:
        with open(policy_path) as _f:
            _policy = json.load(_f)
        _default_dns_log = _policy.get("collectors", {}).get(
            "dnsmasq_log_path", _default_dns_log
        )
    except Exception:
        pass

    def _status(active: bool) -> dict:
        return {"active": active,
                "label": "Active" if active else "Inactive",
                "color": "success" if active else "secondary"}

    return {
        "zeek":     _status(Path("/var/log/zeek/ssl.log").exists()),
        "dns":      _status(Path(_default_dns_log).exists()),
        "conntrack": _status(Path("/proc/net/nf_conntrack").exists()),
    }


def get_system_uptime() -> str:
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
        pct = min(uptime_seconds / (30 * 24 * 3600) * 100, 100.0)
        return f"{pct:.1f}%"
    except Exception:
        return "N/A"
