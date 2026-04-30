import pytest
import yara


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
