"""
MLP Integration Tests

Verifies the MLPThreatDetector engine: model loading, feature extraction,
inference correctness, sklearn warning suppression, and hard-gate override logic.

No external model file required — uses the synthetic_mlp_model_path fixture
defined in conftest.py which trains a minimal classifier in-memory.
"""
import sys
import warnings
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

try:
    from minifw_ai.utils.mlp_engine import MLPThreatDetector, FEATURE_NAMES
    from minifw_ai.collector_flow import FlowTracker, build_feature_vector_24
    MLP_AVAILABLE = True
except ImportError:
    MLP_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not MLP_AVAILABLE, reason="scikit-learn not installed"
)


@pytest.fixture
def detector(synthetic_mlp_model_path):
    return MLPThreatDetector(model_path=synthetic_mlp_model_path, threshold=0.5)


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def test_model_loads_successfully(synthetic_mlp_model_path):
    d = MLPThreatDetector(model_path=synthetic_mlp_model_path, threshold=0.5)
    assert d.model_loaded
    assert d.threshold == 0.5
    assert d.scaler is not None


def test_model_not_found_leaves_model_unloaded(tmp_path):
    d = MLPThreatDetector(model_path=str(tmp_path / "nonexistent.pkl"), threshold=0.5)
    assert not d.model_loaded


# ---------------------------------------------------------------------------
# Feature contract
# ---------------------------------------------------------------------------

def test_feature_names_has_24_entries():
    assert len(FEATURE_NAMES) == 24


def test_build_feature_vector_returns_24_values():
    tracker = FlowTracker()
    flow = tracker.update_flow("192.168.1.1", "8.8.8.8", 443, "tcp", pkt_size=1500)
    for _ in range(50):
        flow.update(pkt_size=1500, direction="out")
    features = build_feature_vector_24(flow)
    assert len(features) == 24


# ---------------------------------------------------------------------------
# Inference output contract
# ---------------------------------------------------------------------------

def test_inference_returns_bool_and_float(detector):
    tracker = FlowTracker()
    flow = tracker.update_flow("192.168.1.1", "8.8.8.8", 443, "tcp", pkt_size=1500)
    for _ in range(20):
        flow.update(pkt_size=1500, direction="out")
    is_threat, proba = detector.is_suspicious(flow, return_probability=True)
    # Engine may return numpy.bool_ — check value is boolean-like, not strict type
    assert is_threat in (True, False)
    assert isinstance(proba, float)
    assert 0.0 <= proba <= 1.0


def test_inference_without_probability_returns_bool(detector):
    tracker = FlowTracker()
    flow = tracker.update_flow("192.168.1.1", "8.8.8.8", 443, "tcp", pkt_size=1500)
    for _ in range(20):
        flow.update(pkt_size=1500, direction="out")
    result = detector.is_suspicious(flow)
    assert result in (True, False)


def test_inference_increments_stats(detector):
    tracker = FlowTracker()
    flow = tracker.update_flow("10.0.0.1", "1.2.3.4", 80, "tcp", pkt_size=512)
    for _ in range(10):
        flow.update(pkt_size=512, direction="out")
    before = detector.total_inferences
    detector.is_suspicious(flow)
    assert detector.total_inferences == before + 1


# ---------------------------------------------------------------------------
# sklearn feature-name warning suppression (CRITICAL FIX)
# Inference must use pd.DataFrame with FEATURE_NAMES to avoid
# "X does not have valid feature names" warnings from sklearn.
# ---------------------------------------------------------------------------

def test_no_sklearn_feature_name_warnings(detector):
    tracker = FlowTracker()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        flow = tracker.update_flow("192.168.1.10", "8.8.8.8", 443, "tcp", pkt_size=1500)
        for _ in range(50):
            flow.update(pkt_size=1500, direction="out")
        detector.is_suspicious(flow, return_probability=True)

    feature_name_warnings = [
        w for w in caught if "feature names" in str(w.message).lower()
    ]
    assert not feature_name_warnings, (
        f"sklearn feature-name warnings fired during inference: {feature_name_warnings}"
    )


# ---------------------------------------------------------------------------
# Hard-gate override (score_and_decide integration)
# ---------------------------------------------------------------------------

def test_hard_gate_override_forces_block_and_score_100():
    from minifw_ai.main import score_and_decide

    class _Thresholds:
        monitor_threshold = 60
        block_threshold = 90

    score, reasons, action = score_and_decide(
        domain="example.com",
        denied=False,
        sni_denied=False,
        asn_denied=False,
        burst_hit=0,
        weights={},
        thresholds=_Thresholds(),
        mlp_score=0,
        yara_score=0,
        hard_threat_override=True,
        hard_threat_reason="pps_saturation",
    )
    assert action == "block"
    assert score == 100
    assert "hard_threat_gate_override" in reasons
    assert "pps_saturation" in reasons


# ---------------------------------------------------------------------------
# get_stats contract
# ---------------------------------------------------------------------------

def test_get_stats_structure(detector):
    stats = detector.get_stats()
    assert stats["model_loaded"] is True
    assert stats["has_scaler"] is True
    assert stats["threshold"] == 0.5
    assert isinstance(stats["total_inferences"], int)
    assert isinstance(stats["threat_rate"], float)
