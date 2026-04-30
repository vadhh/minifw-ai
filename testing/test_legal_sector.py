import importlib


def test_mode_context_resolves_minifw_legal(monkeypatch):
    monkeypatch.setenv("PRODUCT_MODE", "minifw_legal")
    monkeypatch.delenv("MINIFW_SECTOR", raising=False)
    import minifw_ai.mode_context as mode_context
    importlib.reload(mode_context)
    ui = mode_context.get_mode_ui()
    assert ui.product_mode == "minifw_legal"
    assert ui.sector == "legal"
    assert ui.label == "Legal"


def test_attack_simulator_has_legal_domains():
    import services.demo.attack_simulator as sim
    assert "legal" in sim._DOMAINS
    assert "malicious" in sim._DOMAINS["legal"]
    assert "benign" in sim._DOMAINS["legal"]
    assert len(sim._DOMAINS["legal"]["malicious"]) >= 4
    assert len(sim._DOMAINS["legal"]["benign"]) >= 4


def test_attack_simulator_has_legal_reasons():
    import services.demo.attack_simulator as sim
    assert "legal" in sim._REASONS
    assert len(sim._REASONS["legal"]) >= 3


def test_attack_simulator_product_mode_maps_legal():
    import services.demo.attack_simulator as sim
    assert sim._PRODUCT_MODE_TO_SECTOR.get("minifw_legal") == "legal"


def test_sector_to_mode_maps_legal(monkeypatch):
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    monkeypatch.setenv("MINIFW_SECTOR", "legal")
    import minifw_ai.mode_context as mode_context
    importlib.reload(mode_context)
    ui = mode_context.get_mode_ui()
    assert ui.product_mode == "minifw_legal"
    assert ui.sector == "legal"


import yara
from pathlib import Path

_RULES_PATH = Path(__file__).parent.parent / "yara_rules" / "legal_rules.yar"


def _compile_legal_rules():
    return yara.compile(sources={"legal": _RULES_PATH.read_text()})


def test_legal_yara_compiles():
    rules = _compile_legal_rules()
    assert rules is not None


def test_legal_ransomware_c2_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"clio-encrypt.c2-server.ru")
    assert any(m.rule == "LegalRansomwareC2" for m in matches)


def test_legal_privilege_violation_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"opposing-counsel.harvest.io")
    assert any(m.rule == "LegalPrivilegeViolation" for m in matches)


def test_legal_tor_exit_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"tor-exit-relay.onion-gw.net")
    assert any(m.rule == "LegalTorExitRelay" for m in matches)


def test_legal_data_exfil_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"gdrive-exfil.upload.io")
    assert any(m.rule == "LegalDataExfiltration" for m in matches)


def test_legal_benign_no_match():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"westlaw.com")
    assert len(matches) == 0


def test_legal_wetransfer_not_in_yara():
    # wetransfer-legal.io scores via feed-only (+40) to land in MONITOR (not BLOCK)
    rules = _compile_legal_rules()
    matches = rules.match(data=b"wetransfer-legal.io")
    assert len(matches) == 0
