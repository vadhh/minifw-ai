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
