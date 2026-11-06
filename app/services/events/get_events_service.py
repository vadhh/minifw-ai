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
        "decision_owner": event.get("decision_owner", "Policy Engine"),
        "trigger": _trigger_label(status, reasons),
        "ai_window_mode": event.get("ai_window_mode", "not_run"),
        "ai_window_n60": event.get("ai_window_n60"),
        "ai_window_probability": event.get("ai_window_probability"),
    }


def _trigger_label(status: str, reasons: list) -> str:
    """What decided this event, from exact engine reason tokens (precedence as in main.py)."""
    if status == "allowed":
        return "Allowed"
    toks = set(reasons)
    if "ai_window_rate" in toks:
        return "AI connection-rate isolation (15 min)"
    if "hard_threat_gate_override" in toks:
        return "Hard gate (packet rate/burst/port scan)"
    if any(str(t).startswith("sector_rule:") for t in toks):
        return "Sector rule"
    if toks & {"dns_denied_domain", "tls_sni_denied_domain", "deny_domain_client_ipv4_isolation"}:
        return "Deny-list domain match"
    if "ip_denied_tor_anonymizer" in toks:
        return "Deny-list IP/Tor match"
    if "asn_denied" in toks:
        return "ASN deny-list match"
    if status == "monitor":
        return "Monitored"
    if any(str(t).startswith(("tls_version_below_minimum:", "vpn_tunnel:")) for t in toks):
        return "Protocol policy (TLS version/VPN)"
    # Remaining blocks: summed score (DNS tunnel, burst, MLP, YARA) reached the block threshold.
    # Not decision_owner: it names MLP/YARA, which only add score.
    return "Score threshold"


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
    stats = {"total_allowed": 0, "total_blocked": 0, "total_monitored": 0, "threats_detected": 0}
    for ev in events:
        s = ev.get("status")
        if s == "allowed":
            stats["total_allowed"] += 1
        elif s == "blocked":
            stats["total_blocked"] += 1
        elif s == "monitor":
            stats["total_monitored"] += 1
        if ev.get("threat_detected"):
            stats["threats_detected"] += 1
    return stats


def get_detection_counters(events=None):
    if events is None:
        events = get_recent_events(limit=500)
    counters = {
        "hard_gate": 0, "ai_window": 0, "ai_scored": 0, "yara": 0,
        "dns_tunnel": 0, "port_scan": 0, "tor_anon": 0, "sni_hits": 0,
    }
    for ev in events:
        # Exact engine reason tokens: substrings would count "tor" in "sector_rule:", "ip" in "ipv6_...".
        toks = ev.get("reason", "").split(", ")
        if "hard_threat_gate_override" in toks: counters["hard_gate"] += 1
        if "ai_window_rate" in toks: counters["ai_window"] += 1
        if any(t.startswith("mlp_threat_score") for t in toks): counters["ai_scored"] += 1
        if any(t.startswith("yara_") for t in toks): counters["yara"] += 1
        if any(t.startswith("dns_tunnel_") for t in toks): counters["dns_tunnel"] += 1
        if {"port_scan", "pps_saturation", "burst_flood"} & set(toks): counters["port_scan"] += 1
        if "ip_denied_tor_anonymizer" in toks: counters["tor_anon"] += 1
        if "tls_sni_denied_domain" in toks: counters["sni_hits"] += 1
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
            uptime_seconds = int(float(f.read().split()[0]))
        return f"{uptime_seconds // 86400}d {uptime_seconds % 86400 // 3600}h"
    except Exception:
        return "N/A"
