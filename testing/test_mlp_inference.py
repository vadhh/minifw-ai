"""
MLP Inference Tests

Tests the MLPThreatDetector inference pipeline: single-flow inference,
batch prediction, threshold behaviour, and graceful handling of an
unloaded model.

No external model file required — uses the synthetic_mlp_model_path fixture
defined in conftest.py which trains a minimal classifier in-memory.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

try:
    from minifw_ai.utils.mlp_engine import MLPThreatDetector
    from minifw_ai.collector_flow import FlowStats
    MLP_AVAILABLE = True
except ImportError:
    MLP_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not MLP_AVAILABLE, reason="scikit-learn not installed"
)


def _make_flow(client_ip="192.168.1.1", pkt_count=50, bytes_sent=5000) -> "FlowStats":
    flow = FlowStats(
        client_ip=client_ip,
        dst_ip="8.8.8.8",
        dst_port=443,
        proto="tcp",
    )
    flow.pkt_count = pkt_count
    flow.bytes_sent = bytes_sent
    return flow


@pytest.fixture
def detector(synthetic_mlp_model_path):
    return MLPThreatDetector(model_path=synthetic_mlp_model_path, threshold=0.5)


# ---------------------------------------------------------------------------
# Single inference
# ---------------------------------------------------------------------------

def test_single_inference_returns_tuple(detector):
    flow = _make_flow()
    result = detector.is_suspicious(flow, return_probability=True)
    assert isinstance(result, tuple) and len(result) == 2
    is_threat, proba = result
    # Engine may return numpy.bool_ — check value is boolean-like, not strict type
    assert is_threat in (True, False)
    assert 0.0 <= proba <= 1.0


def test_proba_consistent_with_threshold(detector):
    """is_threat must equal (proba >= threshold)."""
    flow = _make_flow()
    is_threat, proba = detector.is_suspicious(flow, return_probability=True)
    assert is_threat == (proba >= detector.threshold)


# ---------------------------------------------------------------------------
# Unloaded model — graceful fallback
# ---------------------------------------------------------------------------

def test_unloaded_model_returns_false_zero():
    """When model_loaded=False, inference must return (False, 0.0)."""
    d = MLPThreatDetector.__new__(MLPThreatDetector)
    d.model = None
    d.scaler = None
    d.model_loaded = False
    d.threshold = 0.5
    d.total_inferences = 0
    d.total_threats_detected = 0
    assert d.is_suspicious(_make_flow(), return_probability=True) == (False, 0.0)
    assert d.is_suspicious(_make_flow()) is False


# ---------------------------------------------------------------------------
# Batch prediction
# ---------------------------------------------------------------------------

def test_batch_predict_length_matches_input(detector):
    flows = [_make_flow(client_ip=f"10.0.0.{i}") for i in range(6)]
    results = detector.batch_predict(flows)
    assert len(results) == 6


def test_batch_predict_all_valid_tuples(detector):
    flows = [_make_flow(client_ip=f"10.0.1.{i}") for i in range(4)]
    for is_threat, proba in detector.batch_predict(flows):
        assert is_threat in (True, False)
        assert 0.0 <= proba <= 1.0


def test_batch_predict_empty_input(detector):
    assert detector.batch_predict([]) == []


# ---------------------------------------------------------------------------
# Threshold boundary
# ---------------------------------------------------------------------------

def test_threshold_respected_is_consistent_with_proba(detector):
    """is_threat must equal (proba >= threshold) for any threshold value."""
    for threshold in (0.0, 0.3, 0.5, 0.7, 1.0):
        detector.threshold = threshold
        flow = _make_flow()
        is_threat, proba = detector.is_suspicious(flow, return_probability=True)
        assert bool(is_threat) == (proba >= threshold), (
            f"threshold={threshold}: is_threat={is_threat} inconsistent with proba={proba}"
        )
    detector.threshold = 0.5  # restore


def test_threshold_0_always_classifies_as_threat(detector):
    """With threshold=0.0, every flow with a non-zero proba should be a threat."""
    original = detector.threshold
    detector.threshold = 0.0
    try:
        flow = _make_flow()
        is_threat, proba = detector.is_suspicious(flow, return_probability=True)
        # proba >= 0.0 is always true, so is_threat must be True
        assert is_threat
    finally:
        detector.threshold = original


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_model_info_structure(detector):
    stats = detector.get_stats()
    assert stats["model_loaded"] is True
    assert stats["has_scaler"] is True
    assert isinstance(stats["total_inferences"], int)
    assert isinstance(stats["total_threats_detected"], int)
    assert isinstance(stats["threat_rate"], float)


def test_reset_stats_zeroes_counters(detector):
    flow = _make_flow()
    detector.is_suspicious(flow)
    detector.reset_stats()
    assert detector.total_inferences == 0
    assert detector.total_threats_detected == 0
