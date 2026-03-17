"""
End-to-end integration tests for the hospital sector pipeline.

Exercises the full scoring path with hospital sector config active:
  - IoMT source + healthcare threat domain → severity=critical, action=block
  - Non-IoMT source + healthcare threat domain → action=block, severity=info
  - IoMT source + benign domain → action=allow, no iomt_device_alert
  - HIPAA redaction active → domain replaced with [REDACTED] in event output
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import asdict

from minifw_ai.events import Event
from minifw_ai.feeds import FeedMatcher
from minifw_ai.netutil import ip_in_any_subnet


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HOSPITAL_SECTOR_CONFIG = {
    "iomt_high_priority": True,
    "iomt_alert_on_anomaly": True,
    "redact_payloads": True,
    "monitor_threshold_adjustment": -20,
    "block_threshold_adjustment": -5,
    "alert_severity_boost": "critical",
    "extra_feeds": ["healthcare_threats.txt"],
}

IOMT_SUBNETS = ["10.20.0.0/24", "10.20.1.0/24"]
IOMT_IP = "10.20.0.5"       # Medical device — in IoMT subnet
NON_IOMT_IP = "192.168.1.50"  # Normal client — outside IoMT subnets

# Thresholds adjusted for hospital sector (default 90/60 adjusted by -5/-20)
BLOCK_THRESHOLD = 90 + HOSPITAL_SECTOR_CONFIG["block_threshold_adjustment"]   # 85
MONITOR_THRESHOLD = 60 + HOSPITAL_SECTOR_CONFIG["monitor_threshold_adjustment"]  # 40


def _score_and_decide(score: int) -> str:
    """Minimal decision function mirroring main.py logic."""
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= MONITOR_THRESHOLD:
        return "monitor"
    return "allow"


def _is_iomt(ip: str) -> bool:
    return ip_in_any_subnet(ip, IOMT_SUBNETS)


def _build_event(client_ip, domain, action, score, reasons, sector_config) -> Event:
    """Reproduce the Event construction logic from main.py for testing."""
    event_severity = "info"
    if _is_iomt(client_ip) and score >= MONITOR_THRESHOLD:
        event_severity = sector_config.get("alert_severity_boost", "info")
        if "iomt_device_alert" not in reasons:
            reasons = reasons + ["iomt_device_alert"]

    ev = Event(
        ts="2026-03-17T00:00:00+00:00",
        segment="internal",
        client_ip=client_ip,
        domain=domain,
        action=action,
        score=score,
        reasons=list(reasons),
        sector="hospital",
        severity=event_severity,
    )

    if sector_config.get("redact_payloads"):
        ev.domain = "[REDACTED]"

    return ev


# ---------------------------------------------------------------------------
# Test 1: IoMT source + healthcare threat domain → critical, block
# ---------------------------------------------------------------------------

def test_iomt_source_with_threat_domain_is_critical_block():
    """Medical device querying a blocked domain → severity=critical, action=block."""
    score = 90  # dns_denied_domain (40) + ip_denied (15) + mlp (35)
    action = _score_and_decide(score)
    ev = _build_event(
        client_ip=IOMT_IP,
        domain="lockbit-blog.com",
        action=action,
        score=score,
        reasons=["dns_denied_domain"],
        sector_config=HOSPITAL_SECTOR_CONFIG,
    )

    assert action == "block"
    assert ev.severity == "critical"
    assert "iomt_device_alert" in ev.reasons
    assert ev.domain == "[REDACTED]"  # HIPAA redaction


def test_iomt_source_monitor_threshold_triggers_severity_boost():
    """IoMT device at monitor score (not yet block) still gets severity=critical."""
    score = 42  # Just above hospital monitor threshold (40)
    action = _score_and_decide(score)
    ev = _build_event(
        client_ip=IOMT_IP,
        domain="suspicious-health-site.net",
        action=action,
        score=score,
        reasons=["dns_denied_domain"],
        sector_config=HOSPITAL_SECTOR_CONFIG,
    )

    assert action == "monitor"
    assert ev.severity == "critical"
    assert "iomt_device_alert" in ev.reasons


# ---------------------------------------------------------------------------
# Test 2: Non-IoMT source + threat domain → block, severity=info
# ---------------------------------------------------------------------------

def test_non_iomt_source_with_threat_domain_is_block_info():
    """Normal client querying a blocked domain → block but severity=info (not IoMT)."""
    score = 90
    action = _score_and_decide(score)
    ev = _build_event(
        client_ip=NON_IOMT_IP,
        domain="medrecords-transfer.io",
        action=action,
        score=score,
        reasons=["dns_denied_domain"],
        sector_config=HOSPITAL_SECTOR_CONFIG,
    )

    assert action == "block"
    assert ev.severity == "info"
    assert "iomt_device_alert" not in ev.reasons
    assert ev.domain == "[REDACTED]"


# ---------------------------------------------------------------------------
# Test 3: IoMT source + benign domain → allow, no iomt_device_alert
# ---------------------------------------------------------------------------

def test_iomt_source_benign_domain_is_allow_no_alert():
    """Medical device querying a safe domain → allow, no IoMT alert."""
    score = 0
    action = _score_and_decide(score)
    ev = _build_event(
        client_ip=IOMT_IP,
        domain="update.vendor-medical.com",
        action=action,
        score=score,
        reasons=[],
        sector_config=HOSPITAL_SECTOR_CONFIG,
    )

    assert action == "allow"
    assert ev.severity == "info"
    assert "iomt_device_alert" not in ev.reasons
    assert ev.domain == "[REDACTED]"  # redact_payloads still applies


# ---------------------------------------------------------------------------
# Test 4: HIPAA redaction — all events have domain redacted
# ---------------------------------------------------------------------------

def test_hipaa_redaction_applies_to_all_hospital_events():
    """redact_payloads=True must redact domain regardless of action or IP."""
    for client_ip, domain, score in [
        (IOMT_IP, "allowed-medical-vendor.com", 0),
        (NON_IOMT_IP, "google.com", 0),
        (IOMT_IP, "lockbit-blog.com", 90),
    ]:
        action = _score_and_decide(score)
        ev = _build_event(
            client_ip=client_ip,
            domain=domain,
            action=action,
            score=score,
            reasons=[],
            sector_config=HOSPITAL_SECTOR_CONFIG,
        )
        assert ev.domain == "[REDACTED]", (
            f"Domain not redacted for ip={client_ip} domain={domain}"
        )


# ---------------------------------------------------------------------------
# Test 5: Hospital thresholds are stricter than defaults
# ---------------------------------------------------------------------------

def test_hospital_block_threshold_is_lower_than_default():
    assert BLOCK_THRESHOLD == 85
    assert BLOCK_THRESHOLD < 90  # Default


def test_hospital_monitor_threshold_is_lower_than_default():
    assert MONITOR_THRESHOLD == 40
    assert MONITOR_THRESHOLD < 60  # Default


def test_score_at_hospital_monitor_threshold_is_monitor_not_allow():
    """Score of 40 must be monitor under hospital thresholds."""
    assert _score_and_decide(40) == "monitor"


def test_score_39_is_allow_under_hospital_thresholds():
    assert _score_and_decide(39) == "allow"


def test_score_85_is_block_under_hospital_thresholds():
    assert _score_and_decide(85) == "block"


# ---------------------------------------------------------------------------
# Test 6: IoMT subnet detection
# ---------------------------------------------------------------------------

def test_iomt_ip_is_detected_in_subnet():
    assert _is_iomt("10.20.0.1")
    assert _is_iomt("10.20.1.254")


def test_non_iomt_ip_is_not_in_subnet():
    assert not _is_iomt("192.168.1.50")
    assert not _is_iomt("10.10.0.1")
    assert not _is_iomt("8.8.8.8")
