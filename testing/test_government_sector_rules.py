"""
Tests for government sector detection rules and policy decision logic.
Government rules are stricter than financial — test boundary conditions carefully.
"""
from app.minifw_ai.sector_rules.government_rules import (
    evaluate_government_sector,
    GOVERNMENT_DEFAULTS,
)
from app.minifw_ai.sector_rules.government_policy import decide_government_action


# ── Clean flows ────────────────────────────────────────────────────────────

def test_clean_flow_no_detections():
    flow = {
        "src_ip": "10.0.1.5",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "bytes_out": 512,
        "is_internal": False,
        "tls_used": True,
        "sni_present": True,
        "hour": 10,
    }
    assert evaluate_government_sector(flow) == []


def test_empty_flow_no_detections():
    assert evaluate_government_sector({}) == []


# ── Blocked country (stricter list than financial) ─────────────────────────

def test_blocked_country_triggers():
    for country in ["KP", "IR", "CN", "BY", "RU"]:
        flow = {"dst_country": country, "is_internal": False}
        detections = evaluate_government_sector(flow)
        assert any(d["type"] == "gov_blocked_country" for d in detections), f"Expected block for {country}"


def test_financial_only_country_blocks_in_gov_too():
    # CN is gov-only
    flow = {"dst_country": "CN", "is_internal": False}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_blocked_country" for d in detections)


def test_allowed_country_no_trigger():
    flow = {"dst_country": "FR", "is_internal": False}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_blocked_country" for d in detections)


# ── C2 port detection ──────────────────────────────────────────────────────

def test_c2_port_triggers_block():
    for port in [4444, 5555, 1337, 31337]:
        flow = {"dst_port": port, "dst_ip": "1.2.3.4", "src_ip": "10.0.0.1"}
        detections = evaluate_government_sector(flow)
        assert any(d["type"] == "gov_c2_port" for d in detections), f"Expected C2 for port {port}"
        d = next(d for d in detections if d["type"] == "gov_c2_port")
        assert d["recommended_action"] == "block"
        assert d["severity"] == "critical"


def test_normal_port_no_c2_trigger():
    flow = {"dst_port": 443}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_c2_port" for d in detections)


# ── C2 beacon detection ────────────────────────────────────────────────────

def test_c2_beacon_triggers_on_regular_timing():
    flow = {
        "pkt_count": 50,
        "interarrival_std_ms": 3.0,
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
    }
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_c2_beacon_pattern" for d in detections)


def test_c2_beacon_not_triggered_on_irregular_timing():
    flow = {"pkt_count": 50, "interarrival_std_ms": 500.0}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_c2_beacon_pattern" for d in detections)


def test_c2_beacon_requires_minimum_pkt_count():
    flow = {"pkt_count": 5, "interarrival_std_ms": 1.0}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_c2_beacon_pattern" for d in detections)


# ── Critical service misuse ────────────────────────────────────────────────

def test_critical_service_external_triggers():
    for port in [53, 123, 161, 389, 636]:
        flow = {"dst_port": port, "is_internal": False, "dst_ip": "8.8.8.8"}
        detections = evaluate_government_sector(flow)
        assert any(d["type"] == "gov_critical_service_external" for d in detections), f"Expected alert for port {port}"


def test_critical_service_internal_no_trigger():
    flow = {"dst_port": 53, "is_internal": True}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_critical_service_external" for d in detections)


# ── Large outbound transfer ─────────────────────────────────────────────────

def test_very_large_gov_outbound_triggers():
    flow = {"bytes_out": 150 * 1024 * 1024, "is_internal": False}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_very_large_outbound" for d in detections)


def test_large_gov_outbound_triggers():
    flow = {"bytes_out": 50 * 1024 * 1024, "is_internal": False}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_large_outbound" for d in detections)


def test_gov_large_threshold_stricter_than_financial():
    # 30MB is above gov threshold (20MB) but below financial threshold (50MB)
    from app.minifw_ai.sector_rules.financial_rules import evaluate_financial_sector
    flow = {"bytes_out": 30 * 1024 * 1024, "is_internal": False}
    gov_detections = evaluate_government_sector(flow)
    fin_detections = evaluate_financial_sector(flow)
    assert any(d["type"] in {"gov_large_outbound", "gov_very_large_outbound"} for d in gov_detections)
    assert not any(d["type"] in {"large_outbound_transfer", "very_large_outbound_transfer"} for d in fin_detections)


def test_internal_large_outbound_no_trigger():
    flow = {"bytes_out": 500 * 1024 * 1024, "is_internal": True}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] not in {"gov_large_outbound", "gov_very_large_outbound"} for d in detections)


# ── APT low-and-slow pattern ───────────────────────────────────────────────

def test_apt_pattern_triggers():
    flow = {"connection_count": 50, "avg_bytes_per_connection": 1024}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_apt_low_slow_pattern" for d in detections)


def test_apt_pattern_requires_both_conditions():
    flow = {"connection_count": 50, "avg_bytes_per_connection": 100 * 1024}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_apt_low_slow_pattern" for d in detections)


def test_apt_pattern_missing_fields_no_trigger():
    assert all(d["type"] != "gov_apt_low_slow_pattern" for d in evaluate_government_sector({}))


# ── After-hours (stricter window: 7-20) ───────────────────────────────────

def test_after_hours_gov_triggers_at_0600():
    # 06:00 is outside gov window (7-20) but inside financial window (6-22)
    flow = {"hour": 6, "is_internal": False, "bytes_out": 1024}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_after_hours_external" for d in detections)


def test_after_hours_gov_triggers_at_2100():
    flow = {"hour": 21, "is_internal": False, "bytes_out": 1024}
    detections = evaluate_government_sector(flow)
    assert any(d["type"] == "gov_after_hours_external" for d in detections)


def test_business_hours_no_trigger():
    flow = {"hour": 10, "is_internal": False, "bytes_out": 1024}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_after_hours_external" for d in detections)


def test_after_hours_critical_asset_scores_higher():
    normal = evaluate_government_sector({"hour": 2, "is_internal": False, "asset_tag": "printer"})
    critical = evaluate_government_sector({"hour": 2, "is_internal": False, "asset_tag": "domain-controller"})
    normal_d = next(d for d in normal if d["type"] == "gov_after_hours_external")
    critical_d = next(d for d in critical if d["type"] == "gov_after_hours_external")
    assert critical_d["score"] > normal_d["score"]
    assert critical_d["recommended_action"] == "block"


# ── Missing SNI (government recommends block, not alert) ──────────────────

def test_missing_sni_external_tls_triggers_block():
    flow = {"tls_used": True, "sni_present": False, "known_vendor": False,
            "is_internal": False, "dst_ip": "1.2.3.4"}
    detections = evaluate_government_sector(flow)
    d = next(d for d in detections if d["type"] == "gov_missing_sni_external_tls")
    assert d["recommended_action"] == "block"


def test_internal_tls_no_sni_no_trigger():
    flow = {"tls_used": True, "sni_present": False, "is_internal": True}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_missing_sni_external_tls" for d in detections)


# ── decide_government_action ───────────────────────────────────────────────

def test_no_detections_returns_allow():
    assert decide_government_action([])["final_action"] == "allow"


def test_c2_port_detection_forces_block():
    detections = [{"type": "gov_c2_port", "score": 0.90, "severity": "critical",
                   "reason": "C2 port", "recommended_action": "block",
                   "source": "government_sector_rules", "metadata": {}}]
    result = decide_government_action(detections)
    assert result["final_action"] == "block"
    assert result["trigger_type"] == "gov_c2_port"


def test_single_high_severity_triggers_block():
    """Government blocks on single high-severity, financial requires two."""
    detections = [{"type": "gov_large_outbound", "score": 0.84, "severity": "high",
                   "reason": "large outbound", "recommended_action": "block",
                   "source": "government_sector_rules", "metadata": {}}]
    result = decide_government_action(detections)
    assert result["final_action"] == "block"


def test_medium_severity_below_threshold_returns_monitor():
    detections = [{"type": "some_medium_type", "score": 0.50, "severity": "medium",
                   "reason": "medium concern", "recommended_action": "alert",
                   "source": "government_sector_rules", "metadata": {}}]
    result = decide_government_action(detections)
    assert result["final_action"] == "monitor"


def test_medium_severity_above_threshold_returns_alert():
    detections = [{"type": "some_medium_type", "score": 0.70, "severity": "medium",
                   "reason": "medium concern", "recommended_action": "alert",
                   "source": "government_sector_rules", "metadata": {}}]
    result = decide_government_action(detections)
    assert result["final_action"] == "alert"
