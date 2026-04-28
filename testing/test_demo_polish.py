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
