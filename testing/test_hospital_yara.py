"""
Tests for hospital_rules.yar — medical ransomware, IoMT exploit, and
medical data exfiltration YARA rules.
"""

import pytest
from pathlib import Path

try:
    from minifw_ai.utils.yara_scanner import YARAScanner
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not YARA_AVAILABLE, reason="yara-python not installed"
)

RULES_DIR = Path(__file__).parent.parent / "yara_rules"


@pytest.fixture(scope="module")
def scanner():
    return YARAScanner(rules_dir=str(RULES_DIR))


# ---------------------------------------------------------------------------
# Rule file existence
# ---------------------------------------------------------------------------

def test_hospital_rules_file_exists():
    assert (RULES_DIR / "hospital_rules.yar").exists()


def test_scanner_loads_with_hospital_rules(scanner):
    assert scanner.rules_loaded


# ---------------------------------------------------------------------------
# MedicalRansomware rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "Your network has been encrypted. Pay the ransom to recover your files.",
    "All your files have been encrypted by CONTI ransomware",
    "RyukReadMe — to recover contact us",
    "vssadmin delete shadows /all /quiet",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog -quiet",
    "Files encrypted with extension .lockbit",
    "your data has been stolen and will be published",
])
def test_medical_ransomware_rule_matches(scanner, payload):
    matches = scanner.scan_payload(payload)
    rule_names = [m.rule for m in matches]
    assert "MedicalRansomware" in rule_names, (
        f"MedicalRansomware did not match payload: {payload!r}"
    )


def test_medical_ransomware_severity_is_critical(scanner):
    matches = scanner.scan_payload("vssadmin delete shadows /all /quiet")
    ransomware_matches = [m for m in matches if m.rule == "MedicalRansomware"]
    assert ransomware_matches
    assert ransomware_matches[0].get_severity() == "critical"


def test_medical_ransomware_category(scanner):
    matches = scanner.scan_payload("All your files have been encrypted")
    ransomware_matches = [m for m in matches if m.rule == "MedicalRansomware"]
    assert ransomware_matches
    assert ransomware_matches[0].get_category() == "medical_ransomware"


# ---------------------------------------------------------------------------
# IoMTExploit rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "GET /api/v1/device/config HTTP/1.1",
    "POST /infusion/rate/set",
    "PUT /pump/bolus",
    "GET /monitor/alarm/disable",
    "GET /GEHealthcare/api/status",
    "POST /Philips/patient-monitor/config",
    "firmware_upgrade version=2.3.1",
    "/bin/sh -c id",
])
def test_iomt_exploit_rule_matches(scanner, payload):
    matches = scanner.scan_payload(payload)
    rule_names = [m.rule for m in matches]
    assert "IoMTExploit" in rule_names, (
        f"IoMTExploit did not match payload: {payload!r}"
    )


def test_iomt_exploit_severity_is_critical(scanner):
    matches = scanner.scan_payload("POST /infusion/rate/set")
    iomt_matches = [m for m in matches if m.rule == "IoMTExploit"]
    assert iomt_matches
    assert iomt_matches[0].get_severity() == "critical"


def test_iomt_exploit_category(scanner):
    matches = scanner.scan_payload("GET /api/v1/device/config")
    iomt_matches = [m for m in matches if m.rule == "IoMTExploit"]
    assert iomt_matches
    assert iomt_matches[0].get_category() == "iomt_exploit"


# ---------------------------------------------------------------------------
# MedicalDataExfil rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "MSH|^~\\&|SENDING|RECV|20260317||ADT^A01|",
    "PID|||12345^^^MRN|",
    "GET /Patient/$everything",
    "GET /Patient/123/$export",
    "_outputFormat=application/fhir+ndjson",
    "C-STORE SCP",
    "C-MOVE destination=REMOTE_AE",
    "1.2.840.10008.5.1.4.1.1.2",
    "patient_export_2026.zip",
    "phi_archive_backup.tar.gz",
])
def test_medical_data_exfil_rule_matches(scanner, payload):
    matches = scanner.scan_payload(payload)
    rule_names = [m.rule for m in matches]
    assert "MedicalDataExfil" in rule_names, (
        f"MedicalDataExfil did not match payload: {payload!r}"
    )


def test_medical_data_exfil_severity_is_high(scanner):
    matches = scanner.scan_payload("patient_export_2026.zip")
    exfil_matches = [m for m in matches if m.rule == "MedicalDataExfil"]
    assert exfil_matches
    assert exfil_matches[0].get_severity() == "high"


def test_medical_data_exfil_category(scanner):
    matches = scanner.scan_payload("phi_archive_backup.tar.gz")
    exfil_matches = [m for m in matches if m.rule == "MedicalDataExfil"]
    assert exfil_matches
    assert exfil_matches[0].get_category() == "medical_data_exfil"


# ---------------------------------------------------------------------------
# Benign payloads — no false positives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "Hello, this is a normal web page.",
    "GET /index.html HTTP/1.1",
    "User-Agent: Mozilla/5.0",
    "Content-Type: application/json",
    "200 OK",
    "appointment scheduled for Monday",
    "blood pressure reading: 120/80",
])
def test_benign_payload_no_hospital_match(scanner, payload):
    matches = scanner.scan_payload(payload)
    hospital_rules = {"MedicalRansomware", "IoMTExploit", "MedicalDataExfil"}
    matched_hospital = [m.rule for m in matches if m.rule in hospital_rules]
    assert not matched_hospital, (
        f"False positive — hospital rules matched benign payload {payload!r}: {matched_hospital}"
    )
