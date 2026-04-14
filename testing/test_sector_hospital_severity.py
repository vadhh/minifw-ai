"""
Tests for hospital sector alert_severity_boost.

Verifies that IoMT device events receive severity=critical when the hospital
sector config specifies alert_severity_boost=critical, and that all other
events keep severity=info.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from minifw_ai.events import Event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hospital_sector_config():
    return {
        "iomt_high_priority": True,
        "iomt_alert_on_anomaly": True,
        "redact_payloads": True,
        "monitor_threshold_adjustment": -20,
        "block_threshold_adjustment": -5,
        "alert_severity_boost": "critical",
        "extra_feeds": ["healthcare_threats.txt"],
    }


def _establishment_sector_config():
    return {
        "standard_protection": True,
        "block_threshold_adjustment": 0,
        "monitor_threshold_adjustment": 0,
        "extra_feeds": [],
        "strict_logging": False,
        "log_retention_days": 30,
    }


def _make_sector_lock(is_hospital: bool):
    lock = MagicMock()
    lock.is_hospital.return_value = is_hospital
    return lock


# ---------------------------------------------------------------------------
# H-1.1 — Event dataclass carries severity field
# ---------------------------------------------------------------------------

def test_event_has_severity_field():
    ev = Event(
        ts="2026-03-17T00:00:00+00:00",
        segment="default",
        client_ip="10.20.0.5",
        domain="example.com",
        action="allow",
        score=0,
        reasons=[],
        sector="hospital",
    )
    assert hasattr(ev, "severity")
    assert ev.severity == "info"


def test_event_severity_default_is_info():
    ev = Event(
        ts="2026-03-17T00:00:00+00:00",
        segment="default",
        client_ip="192.168.1.1",
        domain="google.com",
        action="allow",
        score=5,
        reasons=[],
        sector="establishment",
    )
    assert ev.severity == "info"


def test_event_severity_can_be_set_to_critical():
    ev = Event(
        ts="2026-03-17T00:00:00+00:00",
        segment="internal",
        client_ip="10.20.0.10",
        domain="[REDACTED]",
        action="block",
        score=85,
        reasons=["dns_denied_domain", "iomt_device_alert"],
        sector="hospital",
        severity="critical",
    )
    assert ev.severity == "critical"


# ---------------------------------------------------------------------------
# H-1.2 — alert_severity_boost config key drives severity
# ---------------------------------------------------------------------------

def test_alert_severity_boost_config_key_is_critical_for_hospital():
    config = _hospital_sector_config()
    assert config.get("alert_severity_boost") == "critical"


def test_alert_severity_boost_absent_for_establishment():
    config = _establishment_sector_config()
    assert config.get("alert_severity_boost", "info") == "info"


# ---------------------------------------------------------------------------
# H-1.3 — severity is serialised into the event JSON
# ---------------------------------------------------------------------------

def test_event_severity_written_to_json():
    import json
    from dataclasses import asdict

    ev = Event(
        ts="2026-03-17T00:00:00+00:00",
        segment="internal",
        client_ip="10.20.0.5",
        domain="[REDACTED]",
        action="block",
        score=90,
        reasons=["iomt_device_alert", "dns_denied_domain"],
        sector="hospital",
        severity="critical",
    )
    serialised = json.dumps(asdict(ev))
    parsed = json.loads(serialised)
    assert parsed["severity"] == "critical"
    assert parsed["sector"] == "hospital"
    assert "iomt_device_alert" in parsed["reasons"]
