from pathlib import Path
from datetime import datetime
import json
import os

BASE_DIR = Path(__file__).resolve().parents[3]

def _get_events_file() -> Path:
    """Resolve events log path: MINIFW_LOG env var → project logs/ fallback."""
    env_path = os.environ.get("MINIFW_LOG")
    if env_path:
        return Path(env_path)
    return BASE_DIR / "logs" / "events.jsonl"


def get_recent_events(limit: int = 100):
    """
    Get recent security events from JSONL file.
    Returns an empty list when the file does not exist (clean-start / demo reset).
    """
    events_file = _get_events_file()
    if not events_file.exists():
        return []

    try:
        events = []
        with open(events_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append(_format_event(event))
                except json.JSONDecodeError:
                    continue

        events.sort(key=lambda x: x.get("time", ""), reverse=True)
        return events[:limit]

    except (IOError, Exception) as e:
        print(f"Error reading events file: {e}")
        return []


def _format_event(event: dict) -> dict:
    """
    Format event from JSONL to display format

    Log format:
    {
        "ts": "2025-12-17T06:32:51.298337+00:00",
        "segment": "default",
        "client_ip": "127.0.0.1",
        "domain": "chatgpt.com",
        "action": "allow",
        "score": 0,
        "reasons": []
    }

    Args:
        event: Raw event dict from JSONL

    Returns:
        Formatted event dict for DataTable
    """
    # Parse timestamp
    timestamp = event.get("ts", "")
    try:
        # Parse ISO format timestamp
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        time_str = timestamp

    # Get action (allow/block/deny)
    action = event.get("action", "unknown")

    # Determine event type based on action and reasons
    reasons = event.get("reasons", [])
    event_type = _determine_event_type(action, reasons, event)

    # Get color based on action
    type_color = _get_action_color(action)

    # Get source (domain or IP)
    domain = event.get("domain", "")
    client_ip = event.get("client_ip", "")
    source = f"{domain} ({client_ip})" if domain else client_ip

    # Get status
    if action == "allow":
        status = "allowed"
    elif action == "monitor":
        status = "monitor"
    else:
        status = "blocked"

    # Check if threat detected
    score = event.get("score", 0)
    threat_detected = (score > 0) or (action != "allow") or (len(reasons) > 0)

    # Format reasons
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
    """
    Determine event type based on action and reasons
    """
    # If has reasons, it's a specific block
    if reasons:
        if "ip" in str(reasons).lower():
            return "IP Block"
        elif "domain" in str(reasons).lower():
            return "Domain Block"
        elif "asn" in str(reasons).lower():
            return "ASN Block"
        elif "burst" in str(reasons).lower() or "rate" in str(reasons).lower():
            return "Rate Limit"
        else:
            return "Security Block"

    # Based on action
    if action == "allow":
        domain = event.get("domain", "")
        if domain:
            return "Domain Allow"
        else:
            return "Traffic Allow"
    elif action in ["block", "deny"]:
        return "Traffic Block"
    else:
        return "Unknown"


def _get_action_color(action: str) -> str:
    """
    Get Bootstrap color class based on action
    """
    color_map = {
        "allow": "success",
        "block": "danger",
        "deny": "danger",
        "warn": "warning",
    }
    return color_map.get(action.lower(), "secondary")


def _get_sample_events():
    return []


def get_event_statistics(events=None):
    """
    Get event statistics from a pre-loaded events list or by reading the file.
    Pass ``events`` from a prior get_recent_events() call to avoid a second read.
    """
    if events is None:
        events = get_recent_events(limit=500)

    stats = {"total_allowed": 0, "total_blocked": 0, "threats_detected": 0}
    for event in events:
        if event.get("status") == "allowed":
            stats["total_allowed"] += 1
        elif event.get("status") == "blocked":
            stats["total_blocked"] += 1
        if event.get("threat_detected", False):
            stats["threats_detected"] += 1
    return stats


def get_detection_counters(events=None):
    """
    Get detection type counters from a pre-loaded events list or by reading the file.
    Pass ``events`` from a prior get_recent_events() call to avoid a second read.
    """
    if events is None:
        events = get_recent_events(limit=500)

    counters = {
        "hard_gate": 0,
        "ai_scored": 0,
        "yara": 0,
        "dns_tunnel": 0,
        "port_scan": 0,
        "tor_anon": 0,
        "sni_hits": 0,
    }
    for event in events:
        reason = event.get("reason", "").lower()
        if "hard_threat_gate" in reason:
            counters["hard_gate"] += 1
        if "mlp_threat_score" in reason:
            counters["ai_scored"] += 1
        if "yara" in reason:
            counters["yara"] += 1
        if "dns_tunnel" in reason:
            counters["dns_tunnel"] += 1
        if "port_scan" in reason or "pps" in reason:
            counters["port_scan"] += 1
        if "tor" in reason or "anonymizer" in reason:
            counters["tor_anon"] += 1
        if "tls_sni" in reason or "sni_deny" in reason or "sni" in reason:
            counters["sni_hits"] += 1
    return counters


def get_collector_status():
    """
    Check live status of data collectors: Zeek TLS, DNS (dnsmasq), and flow tracking (conntrack).

    DNS log path is resolved from policy.json (collectors.dnsmasq_log_path) so it works
    regardless of deployment layout — bare-metal (/var/log/dnsmasq.log) or Docker
    (/opt/minifw_ai/logs/dnsmasq.log). Falls back to the hardcoded default if the policy
    cannot be read.

    Returns a dict with active flag and label for each collector.
    """
    from pathlib import Path

    # Resolve dnsmasq log path from policy.json; fall back to OS default
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

    zeek_log = Path("/var/log/zeek/ssl.log")
    dns_log = Path(_default_dns_log)
    conntrack = Path("/proc/net/nf_conntrack")

    def _status(active: bool) -> dict:
        return {"active": active, "label": "Active" if active else "Inactive",
                "color": "success" if active else "secondary"}

    return {
        "zeek": _status(zeek_log.exists()),
        "dns": _status(dns_log.exists()),
        "conntrack": _status(conntrack.exists()),
    }


def get_system_uptime():
    """
    Calculate system uptime as a percentage based on /proc/uptime.
    Returns uptime relative to a 30-day reference window.
    Falls back to "N/A" if /proc/uptime is unavailable.
    """
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
        reference = 30 * 24 * 3600  # 30-day window
        pct = min(uptime_seconds / reference * 100, 100.0)
        return f"{pct:.1f}%"
    except Exception:
        return "N/A"
