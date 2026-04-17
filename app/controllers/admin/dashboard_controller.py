from fastapi import Request
from datetime import datetime
import subprocess
import json
import os
import threading
import time

from app.services.allow_domain.get_allow_domains_service import get_allow_domains
from app.services.deny_ip.get_deny_ips_service import get_deny_ips
from app.services.deny_asn.get_deny_asns_service import get_deny_asns
from app.services.deny_domain.get_deny_domains_service import get_deny_domains
from app.services.events.get_events_service import (
    get_recent_events,
    get_event_statistics,
    get_system_uptime,
    get_detection_counters,
    get_collector_status,
)

from app.web.templates_config import templates


# ---------------------------------------------------------------------------
# TTL cache for service_status — avoids a pgrep subprocess + file read on
# every dashboard page load.  5-second TTL keeps the display responsive.
# ---------------------------------------------------------------------------

class _TTLCache:
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


_service_status_cache = _TTLCache(ttl=5.0)


def _compute_service_status() -> dict:
    """
    Check if the minifw_ai engine is running and get its mode.

    Two-stage detection:
      Stage 1 — pgrep (same-host / bare-metal installs)
      Stage 2 — audit log sentinel (Docker; engine writes audit.jsonl at
                 startup on the shared volume before processing events)
    """
    status = {"label": "Stopped", "color": "danger", "mode": "Unknown"}

    engine_running = False
    try:
        subprocess.check_call(
            ["pgrep", "-f", "python -m minifw_ai"], stdout=subprocess.DEVNULL
        )
        engine_running = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    audit_log = os.environ.get("MINIFW_AUDIT_LOG", "/opt/minifw_ai/logs/audit.jsonl")
    events_log = os.environ.get("MINIFW_LOG", "/opt/minifw_ai/logs/events.jsonl")
    if not engine_running:
        engine_running = os.path.exists(audit_log) or os.path.exists(events_log)

    status["label"] = "Active" if engine_running else "Stopped"
    status["color"] = "success" if engine_running else "danger"

    state_file = "/opt/minifw_ai/logs/deployment_state.json"
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                data = json.load(f)
                dns_status = data.get("dns_telemetry", {}).get("status", "Unknown")
                status["mode"] = dns_status.replace("_", " ").title()
        except Exception:
            status["mode"] = "Error reading state"
    else:
        status["mode"] = "AI Enhanced" if engine_running else "Unknown"

    return status


def get_service_status() -> dict:
    return _service_status_cache.get_or_compute(_compute_service_status)


def dashboard_controller(request: Request):
    allow_domains = len(get_allow_domains())
    deny_ips = len(get_deny_ips())
    deny_asns = len(get_deny_asns())
    deny_domains = len(get_deny_domains())

    all_events = get_recent_events(limit=500)
    events = all_events[:5]
    event_stats = get_event_statistics(events=all_events)
    detection_counters = get_detection_counters(events=all_events)

    uptime = get_system_uptime()
    service_status = get_service_status()
    collector_status = get_collector_status()

    total_rules = allow_domains + deny_ips + deny_asns + deny_domains

    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {
            "user": {"name": "Fahrezi"},
            "detection_counters": detection_counters,
            "collector_status": collector_status,
            "stats": {
                "allow_domains": allow_domains,
                "deny_ips": deny_ips,
                "deny_asns": deny_asns,
                "deny_domains": deny_domains,
                "total_rules": total_rules,
                "total_allowed": event_stats["total_allowed"],
                "total_blocked": event_stats["total_blocked"],
                "threats_detected": event_stats["threats_detected"],
                "uptime": uptime,
            },
            "service_status": service_status,
            "events": events,
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    )


def get_dashboard_stats():
    allow_domains = len(get_allow_domains())
    deny_ips = len(get_deny_ips())
    deny_asns = len(get_deny_asns())
    deny_domains = len(get_deny_domains())
    _evts = get_recent_events(limit=500)
    event_stats = get_event_statistics(events=_evts)
    service_status = get_service_status()

    return {
        "firewall_rules": {
            "allow_domains": allow_domains,
            "deny_ips": deny_ips,
            "deny_asns": deny_asns,
            "deny_domains": deny_domains,
            "total_rules": allow_domains + deny_ips + deny_asns + deny_domains,
        },
        "events": {
            "total_allowed": event_stats["total_allowed"],
            "total_blocked": event_stats["total_blocked"],
            "threats_detected": event_stats["threats_detected"],
        },
        "system": {"uptime": get_system_uptime(), "status": service_status},
    }
