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
