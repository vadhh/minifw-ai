from fastapi import Request
from datetime import datetime
import subprocess
import json
import os

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


def get_service_status():
    """
    Check if the minifw_ai engine is running and get its mode.

    Process detection uses a two-stage approach so it works both on a single
    host (systemd) and in a containerised deployment where the engine and web
    run in separate containers and pgrep cannot see cross-container processes:

      Stage 1 — pgrep (works on bare-metal / single-host installs)
      Stage 2 — audit log sentinel (works in Docker; engine writes audit.jsonl
                 at startup via audit_daemon_start(), visible on the shared volume)

    Returns a dict with label, color, and mode.
    """
    status = {"label": "Stopped", "color": "danger", "mode": "Unknown"}

    # Stage 1: same-host process check
    engine_running = False
    try:
        subprocess.check_call(
            ["pgrep", "-f", "python -m minifw_ai"], stdout=subprocess.DEVNULL
        )
        engine_running = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Stage 2: cross-container / shared-volume check — engine writes audit.jsonl
    # at startup (audit_daemon_start) and events.jsonl on every processed event.
    audit_log = os.environ.get("MINIFW_AUDIT_LOG", "/opt/minifw_ai/logs/audit.jsonl")
    events_log = os.environ.get("MINIFW_LOG", "/opt/minifw_ai/logs/events.jsonl")
    if not engine_running:
        engine_running = os.path.exists(audit_log) or os.path.exists(events_log)

    status["label"] = "Active" if engine_running else "Stopped"
    status["color"] = "success" if engine_running else "danger"

    # Deployment mode from state file (written by state_manager on transitions)
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


def dashboard_controller(request: Request):
    """
    Dashboard controller for Minifw-AI
    Shows statistics and recent events
    """

    # Get counts from all firewall rules
    allow_domains = len(get_allow_domains())
    deny_ips = len(get_deny_ips())
    deny_asns = len(get_deny_asns())
    deny_domains = len(get_deny_domains())

    # Read events once — reuse the same list for stats and counters.
    all_events = get_recent_events(limit=500)
    events = all_events[:5]
    event_stats = get_event_statistics(events=all_events)
    detection_counters = get_detection_counters(events=all_events)

    uptime = get_system_uptime()

    # Get service status
    service_status = get_service_status()

    # Get collector status (Zeek, DNS, conntrack)
    collector_status = get_collector_status()

    # Calculate total rules
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
    """
    Helper function to get dashboard statistics
    Can be called from API endpoints
    """
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
