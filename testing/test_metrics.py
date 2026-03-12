"""
Prometheus Metrics Tests

Tests that update_metrics() correctly increments counters and records histograms
using prometheus_client test utilities.
"""
import pytest
from dataclasses import dataclass

from prometheus_client import REGISTRY, CollectorRegistry

# Use a fresh registry per test to avoid cross-test pollution
import prometheus_client


@dataclass
class _FakeEvent:
    action: str
    score: int


@pytest.fixture(autouse=True)
def _reset_metrics():
    """Reset all metric values between tests by re-importing the module."""
    # Unregister existing collectors from the default registry so
    # re-import doesn't raise "already registered" errors.
    import importlib
    import prometheus.metrics as mod

    # Collect names of collectors registered by our module
    our_collectors = []
    for collector in list(REGISTRY._names_to_collectors.values()):
        desc = getattr(collector, "_name", None)
        if desc and desc.startswith("minifw_ai_"):
            our_collectors.append(collector)

    for c in our_collectors:
        try:
            REGISTRY.unregister(c)
        except Exception:
            pass

    # Re-import to get fresh metric objects
    importlib.reload(mod)
    yield


def _get_counter_value(name: str, labels: dict | None = None) -> float:
    """Read current value of a counter from the default registry."""
    import prometheus.metrics as mod
    metric = getattr(mod, name, None)
    if metric is None:
        raise ValueError(f"No metric named {name}")
    if labels:
        return metric.labels(**labels)._value.get()
    return metric._value.get()


def _get_metric(name: str):
    import prometheus.metrics as mod
    return getattr(mod, name)


class TestUpdateMetrics:
    def test_flows_processed_increments(self):
        import prometheus.metrics as mod
        ev = _FakeEvent(action="allow", score=10)
        mod.update_metrics(ev, flow_count=5)
        assert mod.flows_processed_total._value.get() == 1.0

        mod.update_metrics(ev, flow_count=5)
        assert mod.flows_processed_total._value.get() == 2.0

    def test_decisions_counter_by_action(self):
        import prometheus.metrics as mod
        mod.update_metrics(_FakeEvent(action="allow", score=0))
        mod.update_metrics(_FakeEvent(action="block", score=100))
        mod.update_metrics(_FakeEvent(action="monitor", score=60))
        mod.update_metrics(_FakeEvent(action="block", score=95))

        assert mod.decisions_total.labels(decision="allow")._value.get() == 1.0
        assert mod.decisions_total.labels(decision="block")._value.get() == 2.0
        assert mod.decisions_total.labels(decision="monitor")._value.get() == 1.0

    def test_threat_score_histogram_observes(self):
        import prometheus.metrics as mod
        mod.update_metrics(_FakeEvent(action="allow", score=15))
        mod.update_metrics(_FakeEvent(action="block", score=95))

        # Histogram sum should equal total of observed scores
        assert mod.threat_score_histogram._sum.get() == 110.0

    def test_active_flows_gauge_set(self):
        import prometheus.metrics as mod
        mod.update_metrics(_FakeEvent(action="allow", score=0), flow_count=42)
        assert mod.active_flows._value.get() == 42.0

    def test_hard_gate_reason_recorded(self):
        import prometheus.metrics as mod
        mod.update_metrics(
            _FakeEvent(action="block", score=100),
            hard_gate_reason="pps_saturation",
        )
        assert (
            mod.hard_gate_blocks_total.labels(gate_type="pps_saturation")._value.get()
            == 1.0
        )

    def test_no_hard_gate_reason_does_not_increment(self):
        import prometheus.metrics as mod
        mod.update_metrics(_FakeEvent(action="allow", score=0))
        # No label created for hard_gate_blocks_total
        # Accessing a non-existent label would create it at 0, so just check
        # the metric has no samples
        samples = list(mod.hard_gate_blocks_total.collect())
        # Only the _created and _total samples should exist (no label combos)
        label_samples = [
            s for metric in samples for s in metric.samples if s.labels
        ]
        assert len(label_samples) == 0


class TestStartMetricsServer:
    def test_start_metrics_server_does_not_raise(self):
        """start_metrics_server should not raise even if port is in use."""
        import prometheus.metrics as mod
        # Using port 0 lets the OS pick a free port
        mod.start_metrics_server(port=0)
