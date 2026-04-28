import importlib

import pytest
from minifw_ai.events import Event, EventWriter, now_iso


def test_event_has_trace_id_and_decision_owner():
    ev = Event(
        ts=now_iso(), segment="staff", client_ip="10.0.0.1",
        domain="evil.com", action="block", score=92, reasons=["hard_threat_gate"],
    )
    assert hasattr(ev, "trace_id")
    assert hasattr(ev, "decision_owner")


def test_event_trace_id_defaults_empty():
    ev = Event(
        ts=now_iso(), segment="staff", client_ip="10.0.0.1",
        domain="evil.com", action="block", score=92, reasons=[],
    )
    assert ev.trace_id == ""
    assert ev.decision_owner == "Policy Engine"


def test_resolve_decision_owner_hard_gate():
    from minifw_ai.main import _resolve_decision_owner
    assert _resolve_decision_owner(["hard_threat_gate", "dns_denied_domain"]) == "Hard Gate"


def test_resolve_decision_owner_mlp():
    from minifw_ai.main import _resolve_decision_owner
    assert _resolve_decision_owner(["mlp_threat_score"]) == "AI Engine (MLP)"


def test_resolve_decision_owner_yara():
    from minifw_ai.main import _resolve_decision_owner
    assert _resolve_decision_owner(["yara_match"]) == "YARA Scanner"


def test_resolve_decision_owner_default():
    from minifw_ai.main import _resolve_decision_owner
    assert _resolve_decision_owner(["tls_sni_denied_domain"]) == "Policy Engine"


def _reload_simulator():
    import app.services.demo.attack_simulator as m
    importlib.reload(m)
    return m


def test_simulator_resolves_hospital_sector(monkeypatch):
    monkeypatch.setenv("MINIFW_SECTOR", "hospital")
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    m = _reload_simulator()
    assert m._active_sector() == "hospital"


def test_simulator_resolves_financial_from_product_mode(monkeypatch):
    monkeypatch.setenv("PRODUCT_MODE", "minifw_financial")
    monkeypatch.delenv("MINIFW_SECTOR", raising=False)
    m = _reload_simulator()
    assert m._active_sector() == "financial"


def test_simulator_make_event_sets_correct_sector(monkeypatch):
    monkeypatch.setenv("MINIFW_SECTOR", "establishment")
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    m = _reload_simulator()
    ev = m._make_event("block")
    assert ev["sector"] == "establishment"


def test_simulator_event_has_trace_id(monkeypatch):
    monkeypatch.setenv("MINIFW_SECTOR", "hospital")
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    m = _reload_simulator()
    ev = m._make_event("block")
    assert ev["trace_id"] != ""
    assert len(ev["trace_id"]) == 8


def test_simulator_event_has_decision_owner(monkeypatch):
    monkeypatch.setenv("MINIFW_SECTOR", "hospital")
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    m = _reload_simulator()
    ev = m._make_event("block")
    assert ev["decision_owner"] in ("Hard Gate", "AI Engine (MLP)", "YARA Scanner", "Policy Engine")
