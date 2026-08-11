"""Endpoint bridge: shape translation + the threat-counter contract."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from endpoint_bridge import RSS_WARN_BYTES, flow_to_event, scan_once, stats_to_event  # noqa: E402

from app.services.events.get_events_service import _format_event  # noqa: E402


def test_quiet_agent_produces_no_event():
    assert stats_to_event({"RSS": 90 * 1024 * 1024, "ClientId": "C.1"}, "hospital") is None


def test_bloated_agent_is_flagged_as_a_threat():
    ev = stats_to_event({"RSS": RSS_WARN_BYTES + 1, "ClientId": "C.1"}, "hospital")
    assert ev is not None
    assert _format_event(json.loads(json.dumps(ev.__dict__)))["threat_detected"] is True


def test_routine_collection_does_not_inflate_threat_counters():
    """A collection finishing normally must not read as a detection."""
    ev = flow_to_event(
        {"Timestamp": 1786439693, "Flow": {"client_id": "C.1", "session_id": "F.X",
                                           "artifacts_with_results": ["Generic.Client.Info"]}},
        "hospital",
    )
    formatted = _format_event(json.loads(json.dumps(ev.__dict__)))
    assert formatted["threat_detected"] is False
    assert formatted["domain"] == "Generic.Client.Info"


def test_scan_once_is_incremental(tmp_path):
    """Second pass over an unchanged file must not re-emit rows."""
    mon = tmp_path / "clients" / "C.1" / "monitoring" / "System.Flow.Completion"
    mon.mkdir(parents=True)
    (mon / "day.json").write_text(
        json.dumps({"Timestamp": 1786439693,
                    "Flow": {"client_id": "C.1", "artifacts_with_results": ["A"]}}) + "\n"
    )

    class _Sink:
        def __init__(self):
            self.rows = []

        def write(self, ev):
            self.rows.append(ev)

    sink, offsets = _Sink(), {}
    assert scan_once(tmp_path, sink, offsets, "hospital") == 1
    assert scan_once(tmp_path, sink, offsets, "hospital") == 0
    assert len(sink.rows) == 1
