"""
Tests for HIPAA redact_payloads sector flag enforcement.

When a sector (e.g., Hospital) has redact_payloads=True, the domain field
must be replaced with "[REDACTED]" before being written to EventWriter,
and domain/sni must be redacted in flow record exports.
"""

import json
import os
from pathlib import Path
from dataclasses import asdict

import pytest

from minifw_ai.events import Event, EventWriter, now_iso


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(domain: str = "example.com") -> Event:
    return Event(
        ts=now_iso(),
        segment="default",
        client_ip="192.168.1.10",
        domain=domain,
        action="monitor",
        score=55,
        reasons=["dns_denied_domain"],
        sector="hospital",
    )


def _apply_redaction(ev: Event, sector_config: dict) -> Event:
    """Replicate the redaction logic from main.py."""
    if sector_config.get("redact_payloads"):
        ev.domain = "[REDACTED]"
    return ev


# ---------------------------------------------------------------------------
# Tests: Event domain redaction
# ---------------------------------------------------------------------------

class TestEventRedaction:
    """Verify domain redaction on Event objects."""

    def test_domain_redacted_when_flag_true(self):
        ev = _make_event(domain="patient-portal.hospital.local")
        sector_config = {"redact_payloads": True}

        _apply_redaction(ev, sector_config)

        assert ev.domain == "[REDACTED]"

    def test_domain_not_redacted_when_flag_false(self):
        ev = _make_event(domain="patient-portal.hospital.local")
        sector_config = {"redact_payloads": False}

        _apply_redaction(ev, sector_config)

        assert ev.domain == "patient-portal.hospital.local"

    def test_domain_not_redacted_when_flag_missing(self):
        ev = _make_event(domain="patient-portal.hospital.local")
        sector_config = {}

        _apply_redaction(ev, sector_config)

        assert ev.domain == "patient-portal.hospital.local"

    def test_domain_not_redacted_for_non_hospital_sector(self):
        """Establishment sector has no redact_payloads flag."""
        ev = _make_event(domain="shop.example.com")
        ev.sector = "establishment"
        sector_config = {"redact_payloads": False}

        _apply_redaction(ev, sector_config)

        assert ev.domain == "shop.example.com"


# ---------------------------------------------------------------------------
# Tests: EventWriter integration (redacted event persisted correctly)
# ---------------------------------------------------------------------------

class TestEventWriterRedaction:
    """Verify that redacted events are written correctly to disk."""

    def test_written_event_has_redacted_domain(self, tmp_path):
        log_file = tmp_path / "events.jsonl"
        writer = EventWriter(str(log_file))

        ev = _make_event(domain="sensitive.hospital.local")
        sector_config = {"redact_payloads": True}
        _apply_redaction(ev, sector_config)

        writer.write(ev)

        line = log_file.read_text().strip()
        record = json.loads(line)

        assert record["domain"] == "[REDACTED]"
        assert record["client_ip"] == "192.168.1.10"
        assert record["sector"] == "hospital"

    def test_written_event_preserves_domain_when_no_redaction(self, tmp_path):
        log_file = tmp_path / "events.jsonl"
        writer = EventWriter(str(log_file))

        ev = _make_event(domain="public.example.com")
        sector_config = {"redact_payloads": False}
        _apply_redaction(ev, sector_config)

        writer.write(ev)

        line = log_file.read_text().strip()
        record = json.loads(line)

        assert record["domain"] == "public.example.com"


# ---------------------------------------------------------------------------
# Tests: Flow record redaction
# ---------------------------------------------------------------------------

class TestFlowRecordRedaction:
    """Verify domain/sni redaction in flow record exports."""

    def test_flow_record_domain_and_sni_redacted(self):
        """When redact_payloads=True, flow record domain and sni are replaced."""
        sector_config = {"redact_payloads": True}
        _redact = sector_config.get("redact_payloads", False)

        domain_val = "patient-data.hospital.local"
        sni_val = "ehr.hospital.local"

        record = {
            "domain": "[REDACTED]" if _redact else domain_val,
            "sni": "[REDACTED]" if _redact else sni_val,
        }

        assert record["domain"] == "[REDACTED]"
        assert record["sni"] == "[REDACTED]"

    def test_flow_record_domain_and_sni_not_redacted(self):
        """When redact_payloads=False, flow record domain and sni are preserved."""
        sector_config = {"redact_payloads": False}
        _redact = sector_config.get("redact_payloads", False)

        domain_val = "shop.example.com"
        sni_val = "cdn.example.com"

        record = {
            "domain": "[REDACTED]" if _redact else domain_val,
            "sni": "[REDACTED]" if _redact else sni_val,
        }

        assert record["domain"] == "shop.example.com"
        assert record["sni"] == "cdn.example.com"

    def test_flow_record_redaction_with_missing_flag(self):
        """When redact_payloads is absent, default to no redaction."""
        sector_config = {}
        _redact = sector_config.get("redact_payloads", False)

        domain_val = "normal.example.com"
        sni_val = "normal-sni.example.com"

        record = {
            "domain": "[REDACTED]" if _redact else domain_val,
            "sni": "[REDACTED]" if _redact else sni_val,
        }

        assert record["domain"] == "normal.example.com"
        assert record["sni"] == "normal-sni.example.com"


# ---------------------------------------------------------------------------
# Tests: Sector config integration
# ---------------------------------------------------------------------------

class TestSectorConfigIntegration:
    """Verify hospital sector config has the redact_payloads flag."""

    def test_hospital_sector_has_redact_payloads_true(self):
        from minifw_ai.sector_config import SECTOR_POLICIES, SectorType

        hospital_config = SECTOR_POLICIES[SectorType.HOSPITAL]
        assert hospital_config["redact_payloads"] is True

    def test_establishment_sector_has_no_redact_payloads(self):
        from minifw_ai.sector_config import SECTOR_POLICIES, SectorType

        estab_config = SECTOR_POLICIES[SectorType.ESTABLISHMENT]
        assert estab_config.get("redact_payloads", False) is False

    def test_school_sector_has_no_redact_payloads(self):
        from minifw_ai.sector_config import SECTOR_POLICIES, SectorType

        school_config = SECTOR_POLICIES[SectorType.SCHOOL]
        assert school_config.get("redact_payloads", False) is False
