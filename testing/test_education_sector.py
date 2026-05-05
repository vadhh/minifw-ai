import pytest
import yara
from minifw_ai.events import Event


def _compile_education_rules():
    with open("yara_rules/education_rules.yar", "r") as f:
        src = f.read()
    return yara.compile(sources={"education": src})


def test_education_yara_compiles():
    rules = _compile_education_rules()
    assert rules is not None


def test_education_vpn_proxy_rule_matches():
    rules = _compile_education_rules()
    matches = rules.match(data=b"nordvpn-bypass.proxy.io")
    assert any(m.rule == "EducationVpnProxy" for m in matches)


def test_education_safesearch_bypass_rule_matches():
    rules = _compile_education_rules()
    matches = rules.match(data=b"safesearch-bypass.proxy.ru")
    assert any(m.rule == "EducationSafeSearchBypass" for m in matches)


def test_education_content_filter_rule_matches():
    rules = _compile_education_rules()
    matches = rules.match(data=b"filter-bypass.student.io")
    assert any(m.rule == "EducationContentFilter" for m in matches)


def test_education_benign_no_match():
    rules = _compile_education_rules()
    matches = rules.match(data=b"khanacademy.org")
    assert len(matches) == 0


# ── Task 1: Event dataclass fields ───────────────────────────────────────────

def test_event_has_student_flagged_field():
    """Event must have student_flagged=False by default."""
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="student",
        client_ip="10.10.0.1",
        domain="example.com",
        action="allow",
        score=0,
        reasons=[],
    )
    assert ev.student_flagged is False


def test_event_has_vpn_block_enforced_field():
    """Event must have vpn_block_enforced=False by default."""
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="student",
        client_ip="10.10.0.1",
        domain="example.com",
        action="block",
        score=80,
        reasons=["yara_EducationVpnProxy"],
    )
    assert ev.vpn_block_enforced is False


def test_event_has_audit_mode_field():
    """Event must have audit_mode=False by default."""
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="staff",
        client_ip="192.168.1.1",
        domain="example.com",
        action="allow",
        score=0,
        reasons=[],
    )
    assert ev.audit_mode is False


# ── Task 2: _ip_in_subnets helper ────────────────────────────────────────────

def test_ip_in_subnets_returns_true_for_student_ip():
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("10.10.0.5", ["10.10.0.0/16"]) is True


def test_ip_in_subnets_returns_false_for_staff_ip():
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("192.168.1.5", ["10.10.0.0/16"]) is False


def test_ip_in_subnets_returns_false_for_invalid_ip():
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("not-an-ip", ["10.10.0.0/16"]) is False


def test_ip_in_subnets_returns_false_for_empty_subnet_list():
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("10.10.0.5", []) is False


def test_ip_in_subnets_returns_false_for_ipv6_against_ipv4_subnet():
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("::1", ["10.10.0.0/16"]) is False
