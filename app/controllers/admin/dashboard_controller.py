from fastapi import Request
from datetime import datetime
import subprocess
import json
import os
import threading
from pathlib import Path
import time

DEMO_MODE = os.environ.get("DEMO_MODE", "")

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
from minifw_ai.mode_context import get_mode_ui
from minifw_ai.runtime_health import assess


# One honest label set for every sector: each counter names the exact engine
# reason it counts (see get_detection_counters).
LABELS = {
    "total_blocked_label": "BLOCKED EVENTS",
    "allowed_label": "ALLOWED EVENTS",
    "monitor_label": "MONITORED EVENTS",
    "card_1_label": "HARD GATE BLOCKS",
    "card_1_sub": "Packet rate / burst / port scan",
    "card_2_label": "AI ISOLATIONS (connection rate)",
    "card_2_sub": "Client-window AI, 15 min",
    "card_8_label": "MLP SCORE ADDED (score only)",
    "card_8_sub": "Adds up to 30; cannot block alone",
    "card_3_label": "YARA MATCHES (score only)",
    "card_3_sub": "Adds up to 35; cannot block alone",
    "card_4_label": "DNS TUNNEL HEURISTIC",
    "card_4_sub": "Long or encoded DNS names",
    "card_5_label": "PORT SCAN / PACKET RATE",
    "card_5_sub": "Hard-gate trigger",
    "card_6_label": "TOR / DENY-IP MATCHES",
    "card_6_sub": "Destination on IP deny-list",
    "card_7_label": "SNI DENY-LIST MATCHES",
    "card_7_sub": "TLS SNI on domain deny-list",
}
INTELLIGENCE_TITLES = {
    "finance": "Financial Operations Intelligence",
    "legal": "Legal Operations Intelligence",
    "education": "Educational Operations Intelligence",
    "hospital": "Healthcare Operations Intelligence",
    "government": "Government Operations Intelligence",
    "establishment": "Business Operations Intelligence",
}



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
      Stage 2 — a fresh heartbeat in runtime-health.json (Docker / shared volume).
                 Old log files existing does not mean the engine is running.
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

    status["mode"], status["ai_window"] = _engine_modes()
    if not engine_running:
        engine_running = not status["mode"].startswith("Unknown")

    status["label"] = "Active" if engine_running else "Stopped"
    status["color"] = "success" if engine_running else "danger"
    return status


def _engine_modes() -> tuple[str, str]:
    """Detection mode and client-window AI status from the engine's runtime-health.json."""
    unknown = "Unknown (engine not reporting)"
    path = Path(os.environ.get("MINIFW_HEALTH_FILE", "/opt/minifw_ai/logs/runtime-health.json"))
    try:
        snapshot = json.loads(path.read_text())
        # Fresh heartbeat from the live engine process. Not assess()'s "ready": that also needs
        # every source active within 30 s, which a baseline engine with a quiet DNS log never is.
        if "heartbeat_age_seconds" not in assess(snapshot):
            return unknown, "Unknown"
    except (OSError, ValueError):
        return unknown, "Unknown"
    state, ai = snapshot.get("protection_state"), snapshot.get("ai_window")
    if state == "BASELINE_PROTECTION":
        return "Baseline (AI off: DNS log not healthy)", "Off (baseline)"
    if state != "AI_ENHANCED_PROTECTION":
        return unknown, "Unknown"
    if not isinstance(ai, dict):
        return "AI enhanced", "Unknown"
    if not ai.get("model_sha256"):
        return "AI enhanced", "Model missing"
    if not ai.get("approved"):
        return "AI enhanced", "Shadow only (model not approved)"
    if not ai.get("segments"):
        return "AI enhanced", "Shadow only (approved, no segments in policy)"
    return "AI enhanced", "Enforcing in " + ", ".join(map(str, ai["segments"]))


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

    # Resolve active sector and labels
    mode_ui = get_mode_ui()
    sector = mode_ui.sector or "establishment"
    lbls = {**LABELS, "intelligence_title": INTELLIGENCE_TITLES.get(sector, INTELLIGENCE_TITLES["establishment"])}

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
                "total_monitored": event_stats["total_monitored"],
                "threats_detected": event_stats["threats_detected"],
                "uptime": uptime,
            },
            "service_status": service_status,
            "events": events,
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "demo_mode": DEMO_MODE,
            "lbls": lbls,
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
