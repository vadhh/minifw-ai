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


def test_sector_to_mode_maps_legal(monkeypatch):
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    monkeypatch.setenv("MINIFW_SECTOR", "legal")
    import minifw_ai.mode_context as mode_context
    importlib.reload(mode_context)
    ui = mode_context.get_mode_ui()
    assert ui.product_mode == "minifw_legal"
    assert ui.sector == "legal"
