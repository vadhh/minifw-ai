from fastapi import Request
from datetime import datetime
import subprocess
import json
import os
import threading
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


SECTOR_LABELS = {
    "finance": {
        "intelligence_title": "Financial Operations Intelligence",
        "total_blocked_label": "FRAUD BLOCKED",
        "allowed_label": "VERIFIED TRANSACTIONS",
        "monitor_label": "SUSPICIOUS ACTIVITY",
        "card_1_label": "APIs Protected",
        "card_1_sub": "Secured",
        "card_2_label": "AI FRAUD BLOCKS",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "MALWARE HITS",
        "card_3_sub": "Banking Trojans",
        "card_4_label": "EXFILTRATION",
        "card_4_sub": "Data Hiding Detected",
        "card_5_label": "ERP NODE SCANS",
        "card_5_sub": "Vulnerability Scanning",
        "card_6_label": "ANON TRAFFIC",
        "card_6_sub": "Anonymous Blocked",
        "card_7_label": "FAKE SITES",
        "card_7_sub": "Phishing Blocked",
        "map_yara": "Banking trojan detected",
        "map_dns": "Financial API abuse intercepted",
        "map_port": "ERP credential misuse detected",
        "map_tor": "Unauthorized wire transfer blocked",
        "map_sni": "Invoice fraud attempt prevented",
        "map_block": "Ransomware attack blocked",
        "map_default": "Client financial records secured",
    },
    "legal": {
        "intelligence_title": "Legal Operations Intelligence",
        "total_blocked_label": "EXFIL BLOCKED",
        "allowed_label": "PRIVILEGED REQUESTS",
        "monitor_label": "CONFIDENTIALITY ALERTS",
        "card_1_label": "Case Files Protected",
        "card_1_sub": "Secured",
        "card_2_label": "AI PRIVILEGE BLOCKS",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "RANSOMWARE HITS",
        "card_3_sub": "C2 Connections",
        "card_4_label": "EXFILTRATION",
        "card_4_sub": "Privilege Leaks",
        "card_5_label": "COUNSEL SCANS",
        "card_5_sub": "Harvesting Blocked",
        "card_6_label": "ANON TRAFFIC",
        "card_6_sub": "Tor Exits Blocked",
        "card_7_label": "PHISHING SITES",
        "card_7_sub": "Spoof Sites Blocked",
        "map_yara": "Ransomware C2 detected",
        "map_dns": "Privilege breach thwarted",
        "map_port": "Case-data harvest blocked",
        "map_tor": "Anonymous exfiltration blocked",
        "map_sni": "Phishing case files blocked",
        "map_block": "Ransomware attack blocked",
        "map_default": "Attorney-client privilege secured",
    },
    "education": {
        "intelligence_title": "Educational Operations Intelligence",
        "total_blocked_label": "BYPASS BLOCKED",
        "allowed_label": "CURRICULUM REQUESTS",
        "monitor_label": "CONTENT VIOLATIONS",
        "card_1_label": "Curriculum Portals",
        "card_1_sub": "Secured",
        "card_2_label": "AI BYPASS BLOCKS",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "PROXY HITS",
        "card_3_sub": "VPN Proxies",
        "card_4_label": "TUNNEL DETECTED",
        "card_4_sub": "Data Hiding Detected",
        "card_5_label": "STUDENT SCANS",
        "card_5_sub": "Network Scans Blocked",
        "card_6_label": "UNBLOCK SERVICES",
        "card_6_sub": "Proxy Sites Blocked",
        "card_7_label": "ADULT CONTENT",
        "card_7_sub": "Content Filter Hits",
        "map_yara": "Proxy bypass attempt",
        "map_dns": "SafeSearch bypass blocked",
        "map_port": "Student network scan blocked",
        "map_tor": "VPN bypass tunnel blocked",
        "map_sni": "Adult content filter hit",
        "map_block": "Filter bypass attempt blocked",
        "map_default": "Student network access secured",
    },
    "hospital": {
        "intelligence_title": "Healthcare Operations Intelligence",
        "total_blocked_label": "EXPLOITS BLOCKED",
        "allowed_label": "CLINICAL TRAFFIC",
        "monitor_label": "DEVICE ANOMALIES",
        "card_1_label": "EHR Systems",
        "card_1_sub": "Secured",
        "card_2_label": "AI EHR PROTECTION",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "IoMT MALWARE",
        "card_3_sub": "Medical Backdoors",
        "card_4_label": "DATA LEAKS",
        "card_4_sub": "Patient Data Leaks",
        "card_5_label": "DEVICE SCANS",
        "card_5_sub": "Vulnerability Scanning",
        "card_6_label": "CLINICAL ANONYMOUS",
        "card_6_sub": "Anonymous Blocked",
        "card_7_label": "SPOOF APDATES",
        "card_7_sub": "Spoof Sites Blocked",
        "map_yara": "IoMT backdoor detected",
        "map_dns": "Patient record leak blocked",
        "map_port": "Medical device port scan blocked",
        "map_tor": "Anonymous clinical access blocked",
        "map_sni": "Spoof update server blocked",
        "map_block": "IoMT ransomware blocked",
        "map_default": "Patient health records secured",
    },
    "government": {
        "intelligence_title": "Government Operations Intelligence",
        "total_blocked_label": "APT ATTACKS BLOCKED",
        "allowed_label": "SOVEREIGN TRAFFIC",
        "monitor_label": "RECONNAISSANCE SCANS",
        "card_1_label": "Sovereign Nodes",
        "card_1_sub": "Secured",
        "card_2_label": "AI APT DETECTION",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "APT MALWARE",
        "card_3_sub": "Adversary Payload",
        "card_4_label": "SOVEREIGN EXFIL",
        "card_4_sub": "State Secret Tunnel",
        "card_5_label": "RECON SCANS",
        "card_5_sub": "Reconnaissance Blocked",
        "card_6_label": "COVERT COMMS",
        "card_6_sub": "Covert Comms Blocked",
        "card_7_label": "ADVERSARY PHISH",
        "card_7_sub": "Phishing Blocked",
        "map_yara": "APT malware detected",
        "map_dns": "Sovereign DNS tunnel blocked",
        "map_port": "State secrets harvest blocked",
        "map_tor": "Covert comms channel blocked",
        "map_sni": "Adversary phishing blocked",
        "map_block": "APT exploit payload blocked",
        "map_default": "Sovereign network perimeter secured",
    },
    "establishment": {
        "intelligence_title": "Business Operations Intelligence",
        "total_blocked_label": "THREATS BLOCKED",
        "allowed_label": "ALLOWED TRAFFIC",
        "monitor_label": "ANOMALOUS EVENTS",
        "card_1_label": "POS Terminal",
        "card_1_sub": "Secured",
        "card_2_label": "AI POS BLOCKS",
        "card_2_sub": "Blocked by AI",
        "card_3_label": "SKIMMER HITS",
        "card_3_sub": "POS Skimmers",
        "card_4_label": "SUPPLY CHAIN",
        "card_4_sub": "Supply Chain Inject",
        "card_5_label": "INTERNAL SCANS",
        "card_5_sub": "Vulnerability Scanning",
        "card_6_label": "BOTNET CMD",
        "card_6_sub": "Botnet Blocked",
        "card_7_label": "PHISHING HITS",
        "card_7_sub": "Phishing Blocked",
        "map_yara": "POS skimmer detected",
        "map_dns": "Supply-chain inject blocked",
        "map_port": "POS network scan blocked",
        "map_tor": "Tor exit node blocked",
        "map_sni": "Retail supply scan blocked",
        "map_block": "Ransomware attack blocked",
        "map_default": "Enterprise network secured",
    }
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

    # Resolve active sector and labels
    mode_ui = get_mode_ui()
    sector = mode_ui.sector or "establishment"
    lbls = SECTOR_LABELS.get(sector, SECTOR_LABELS["establishment"])

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
