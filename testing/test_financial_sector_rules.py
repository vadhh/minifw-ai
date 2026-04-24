import pytest
from app.minifw_ai.sector_rules.financial_rules import (
    evaluate_financial_sector,
    FINANCIAL_DEFAULTS,
)
from app.minifw_ai.sector_rules.financial_policy import decide_financial_action


def test_clean_flow_no_detections():
    flow = {
        "src_ip": "192.168.1.5",
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "bytes_out": 1024,
        "is_internal": False,
        "tls_used": True,
        "sni_present": True,
        "hour": 14,
    }
    assert evaluate_financial_sector(flow) == []


def test_empty_flow_no_detections():
    assert evaluate_financial_sector({}) == []


def test_high_risk_country_triggers():
    flow = {"dst_country": "KP", "dst_ip": "1.2.3.4", "is_internal": False}
    detections = evaluate_financial_sector(flow)
    types = [d["type"] for d in detections]
    assert "high_risk_country" in types
    d = next(d for d in detections if d["type"] == "high_risk_country")
    assert d["recommended_action"] == "block"
    assert d["score"] >= 0.80


def test_country_not_in_list_no_trigger():
    flow = {"dst_country": "DE", "is_internal": False}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "high_risk_country" for d in detections)


def test_missing_dst_country_no_trigger():
    detections = evaluate_financial_sector({"is_internal": False})
    assert all(d["type"] != "high_risk_country" for d in detections)


def test_blocked_asn_triggers():
    flow = {"dst_asn": "AS1234", "dst_ip": "5.5.5.5"}
    detections = evaluate_financial_sector(flow, custom_cfg={"blocked_asns": {"AS1234"}})
    types = [d["type"] for d in detections]
    assert "blocked_asn" in types
    d = next(d for d in detections if d["type"] == "blocked_asn")
    assert d["score"] >= 0.90
    assert d["recommended_action"] == "block"


def test_asn_not_in_blocklist_no_trigger():
    flow = {"dst_asn": "AS5678"}
    detections = evaluate_financial_sector(flow, custom_cfg={"blocked_asns": {"AS9999"}})
    assert all(d["type"] != "blocked_asn" for d in detections)


def test_suspicious_port_triggers():
    flow = {"dst_port": 4444, "dst_ip": "10.0.0.1"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "suspicious_port" for d in detections)


def test_normal_port_no_trigger():
    flow = {"dst_port": 443}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "suspicious_port" for d in detections)


def test_missing_dst_port_no_trigger():
    detections = evaluate_financial_sector({})
    assert all(d["type"] != "suspicious_port" for d in detections)


def test_very_large_transfer_triggers():
    flow = {"bytes_out": 250 * 1024 * 1024, "is_internal": False}
    detections = evaluate_financial_sector(flow)
    types = [d["type"] for d in detections]
    assert "very_large_outbound_transfer" in types
    d = next(d for d in detections if d["type"] == "very_large_outbound_transfer")
    assert d["recommended_action"] == "block"


def test_large_transfer_triggers():
    flow = {"bytes_out": 100 * 1024 * 1024, "is_internal": False}
    detections = evaluate_financial_sector(flow)
    types = [d["type"] for d in detections]
    assert "large_outbound_transfer" in types
    d = next(d for d in detections if d["type"] == "large_outbound_transfer")
    assert d["recommended_action"] == "alert"


def test_internal_large_transfer_no_trigger():
    flow = {"bytes_out": 500 * 1024 * 1024, "is_internal": True}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] not in {"large_outbound_transfer", "very_large_outbound_transfer"} for d in detections)


def test_small_transfer_no_trigger():
    flow = {"bytes_out": 1024, "is_internal": False}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "large_outbound_transfer" for d in detections)


def test_after_hours_triggers():
    flow = {"hour": 2, "is_internal": False, "bytes_out": 1024}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "after_hours_external_activity" for d in detections)


def test_business_hours_no_trigger():
    flow = {"hour": 10, "is_internal": False, "bytes_out": 1024}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "after_hours_external_activity" for d in detections)


def test_after_hours_large_volume_scores_higher():
    small = evaluate_financial_sector({"hour": 2, "is_internal": False, "bytes_out": 1024})
    large = evaluate_financial_sector({"hour": 2, "is_internal": False, "bytes_out": 100 * 1024 * 1024})
    small_d = next(d for d in small if d["type"] == "after_hours_external_activity")
    large_d = next(d for d in large if d["type"] == "after_hours_external_activity")
    assert large_d["score"] > small_d["score"]


def test_missing_sni_on_external_tls_triggers():
    flow = {"tls_used": True, "sni_present": False, "known_vendor": False, "dst_ip": "1.2.3.4"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "missing_sni_on_external_tls" for d in detections)


def test_tls_fingerprint_anomaly_triggers():
    flow = {"tls_used": True, "ja3_risk_score": 0.91, "known_vendor": False}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "tls_fingerprint_anomaly" for d in detections)


def test_known_vendor_suppresses_tls_anomaly():
    flow = {"tls_used": True, "sni_present": False, "known_vendor": True, "ja3_risk_score": 0.95}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] not in {"tls_fingerprint_anomaly", "missing_sni_on_external_tls"} for d in detections)


def test_no_tls_skips_tls_rules():
    flow = {"tls_used": False, "sni_present": False}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] not in {"tls_fingerprint_anomaly", "missing_sni_on_external_tls"} for d in detections)


def test_unknown_api_endpoint_triggers():
    flow = {"api_call": True, "unknown_endpoint": True, "http_method": "GET"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "unknown_api_endpoint" for d in detections)


def test_api_schema_violation_triggers_block():
    flow = {"api_call": True, "schema_violation": True, "http_method": "POST"}
    detections = evaluate_financial_sector(flow)
    d = next(d for d in detections if d["type"] == "api_schema_violation")
    assert d["recommended_action"] == "block"


def test_auth_failure_burst_triggers_block():
    flow = {"api_call": True, "auth_failure_burst": True}
    detections = evaluate_financial_sector(flow)
    d = next(d for d in detections if d["type"] == "api_auth_failure_burst")
    assert d["recommended_action"] == "block"


def test_non_api_call_skips_api_rules():
    flow = {"api_call": False, "unknown_endpoint": True, "schema_violation": True}
    detections = evaluate_financial_sector(flow)
    api_types = {"unknown_api_endpoint", "api_schema_violation", "api_auth_failure_burst"}
    assert all(d["type"] not in api_types for d in detections)


def test_connection_burst_triggers():
    flow = {"burst_conn_count": 100, "src_ip": "10.0.0.5"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "burst_connection_pattern" for d in detections)


def test_connection_below_threshold_no_trigger():
    flow = {"burst_conn_count": 79}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "burst_connection_pattern" for d in detections)


def test_custom_cfg_overrides_defaults():
    flow = {"dst_port": 8080, "dst_ip": "1.2.3.4"}
    detections = evaluate_financial_sector(flow, custom_cfg={"suspicious_ports": {8080}})
    assert any(d["type"] == "suspicious_port" for d in detections)


def test_no_detections_returns_allow():
    result = decide_financial_action([])
    assert result["final_action"] == "allow"


def test_critical_block_type_forces_block():
    detections = [{"type": "high_risk_country", "score": 0.86, "severity": "high",
                   "reason": "KP", "recommended_action": "block", "source": "financial_sector_rules", "metadata": {}}]
    result = decide_financial_action(detections)
    assert result["final_action"] == "block"


def test_two_high_severity_detections_forces_block():
    detections = [
        {"type": "suspicious_port", "score": 0.68, "severity": "high",
         "reason": "port 4444", "recommended_action": "alert", "source": "financial_sector_rules", "metadata": {}},
        {"type": "burst_connection_pattern", "score": 0.79, "severity": "high",
         "reason": "burst", "recommended_action": "alert", "source": "financial_sector_rules", "metadata": {}},
    ]
    result = decide_financial_action(detections)
    assert result["final_action"] == "block"


def test_single_high_score_returns_alert():
    detections = [{"type": "suspicious_port", "score": 0.77, "severity": "high",
                   "reason": "port 4444", "recommended_action": "alert", "source": "financial_sector_rules", "metadata": {}}]
    result = decide_financial_action(detections)
    assert result["final_action"] == "alert"


def test_low_score_returns_monitor():
    detections = [{"type": "after_hours_external_activity", "score": 0.60, "severity": "medium",
                   "reason": "after hours", "recommended_action": "alert", "source": "financial_sector_rules", "metadata": {}}]
    result = decide_financial_action(detections)
    assert result["final_action"] == "monitor"
