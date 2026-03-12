"""
Decision Engine Tests

Boundary-condition tests for score_and_decide() covering:
- allow/monitor/block thresholds
- hard-gate override
- sector threshold adjustments
"""
import pytest

from minifw_ai.main import score_and_decide


class _Thresholds:
    def __init__(self, monitor=60, block=90):
        self.monitor_threshold = monitor
        self.block_threshold = block


# ---------------------------------------------------------------------------
# Boundary conditions: default thresholds (monitor=60, block=90)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("denied,sni_denied,expected_score,expected_action", [
    # No signals → score 0 → allow
    (False, False, 0, "allow"),
    # DNS denied only → +40 → allow (below 60)
    (True, False, 40, "allow"),
    # SNI denied only → +35 → allow (below 60)
    (False, True, 35, "allow"),
    # DNS + SNI → 40+35=75 → monitor (60-89)
    (True, True, 75, "monitor"),
])
def test_signal_combinations(denied, sni_denied, expected_score, expected_action):
    score, reasons, action = score_and_decide(
        domain="example.com",
        denied=denied,
        sni_denied=sni_denied,
        asn_denied=False,
        burst_hit=0,
        weights={},
        thresholds=_Thresholds(),
        mlp_score=0,
        yara_score=0,
        hard_threat_override=False,
        hard_threat_reason=None,
    )
    assert score == expected_score
    assert action == expected_action


def test_score_59_is_allow():
    """Score just below monitor threshold → allow."""
    score, _, action = score_and_decide(
        domain="x.com", denied=False, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
        pre_reasons=["test_inject_59"],
    )
    # With no signals the score is 0 → allow
    assert action == "allow"


def test_monitor_threshold_boundary():
    """DNS(40) + burst(10) + ASN(15) = 65 → monitor."""
    score, reasons, action = score_and_decide(
        domain="bad.com", denied=True, sni_denied=False, asn_denied=True,
        burst_hit=1, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    assert score == 65
    assert action == "monitor"
    assert "dns_denied_domain" in reasons
    assert "asn_denied" in reasons
    assert "burst_behavior" in reasons


def test_block_threshold_boundary():
    """DNS(40) + SNI(35) + ASN(15) = 90 → block."""
    score, reasons, action = score_and_decide(
        domain="evil.com", denied=True, sni_denied=True, asn_denied=True,
        burst_hit=0, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    assert score == 90
    assert action == "block"


def test_score_89_is_monitor():
    """Score just below block threshold → monitor."""
    # DNS(40) + SNI(35) + burst(10) = 85 → monitor
    score, _, action = score_and_decide(
        domain="x.com", denied=True, sni_denied=True, asn_denied=False,
        burst_hit=1, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    assert score == 85
    assert action == "monitor"


# ---------------------------------------------------------------------------
# Hard gate override
# ---------------------------------------------------------------------------

def test_hard_gate_override_forces_block_100():
    score, reasons, action = score_and_decide(
        domain="safe.com", denied=False, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=True,
        hard_threat_reason="pps_saturation",
    )
    assert score == 100
    assert action == "block"
    assert "hard_threat_gate_override" in reasons
    assert "pps_saturation" in reasons


def test_hard_gate_override_ignores_all_other_signals():
    """Hard gate sets score=100 regardless of other signals being zero."""
    score, _, action = score_and_decide(
        domain="clean.com", denied=False, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={}, thresholds=_Thresholds(),
        mlp_score=0, yara_score=0,
        hard_threat_override=True,
        hard_threat_reason="burst_flood",
    )
    assert score == 100
    assert action == "block"


# ---------------------------------------------------------------------------
# MLP and YARA score contributions
# ---------------------------------------------------------------------------

def test_mlp_score_contribution():
    """MLP score contributes mlp_score * mlp_weight // 100."""
    score, reasons, action = score_and_decide(
        domain="x.com", denied=False, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={"mlp_weight": 30},
        thresholds=_Thresholds(),
        mlp_score=80, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    # 80 * 30 // 100 = 24
    assert score == 24
    assert action == "allow"


def test_yara_score_contribution():
    """YARA score contributes yara_score * yara_weight // 100."""
    score, reasons, action = score_and_decide(
        domain="x.com", denied=False, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={"yara_weight": 35},
        thresholds=_Thresholds(),
        mlp_score=0, yara_score=100,
        hard_threat_override=False, hard_threat_reason=None,
    )
    # 100 * 35 // 100 = 35
    assert score == 35
    assert action == "allow"


def test_combined_all_signals_capped_at_100():
    """Score is capped at 100 even when all signals fire."""
    score, _, action = score_and_decide(
        domain="x.com", denied=True, sni_denied=True, asn_denied=True,
        burst_hit=1, weights={"mlp_weight": 30, "yara_weight": 35},
        thresholds=_Thresholds(),
        mlp_score=100, yara_score=100,
        hard_threat_override=False, hard_threat_reason=None,
    )
    assert score == 100
    assert action == "block"


# ---------------------------------------------------------------------------
# Sector threshold adjustments
# ---------------------------------------------------------------------------

def test_hospital_lower_monitor_threshold():
    """Hospital sector uses monitor=40, so score 45 → monitor (not allow)."""
    score, _, action = score_and_decide(
        domain="x.com", denied=True, sni_denied=False, asn_denied=False,
        burst_hit=0, weights={}, thresholds=_Thresholds(monitor=40, block=90),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    # DNS denied = +40 → score 40, with monitor threshold at 40 → monitor
    assert score == 40
    assert action == "monitor"


def test_finance_lower_block_threshold():
    """Finance sector uses block=80, so score 85 → block (not monitor)."""
    score, _, action = score_and_decide(
        domain="x.com", denied=True, sni_denied=True, asn_denied=False,
        burst_hit=1, weights={}, thresholds=_Thresholds(monitor=60, block=80),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    # DNS(40) + SNI(35) + burst(10) = 85 → with block=80 → block
    assert score == 85
    assert action == "block"


def test_default_thresholds_same_score_is_monitor():
    """Same score (85) with default block=90 → monitor."""
    score, _, action = score_and_decide(
        domain="x.com", denied=True, sni_denied=True, asn_denied=False,
        burst_hit=1, weights={}, thresholds=_Thresholds(monitor=60, block=90),
        mlp_score=0, yara_score=0,
        hard_threat_override=False, hard_threat_reason=None,
    )
    assert score == 85
    assert action == "monitor"
