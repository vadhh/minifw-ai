from __future__ import annotations
import copy
from typing import Any, Dict, List, Optional


FINANCIAL_DEFAULTS: Dict[str, Any] = {
    "high_risk_countries": {"KP", "IR", "SY", "RU"},
    "suspicious_ports": {21, 22, 23, 25, 53, 4444, 5555, 6666, 7777, 8443},
    "approved_business_hours_start": 6,
    "approved_business_hours_end": 22,
    "large_upload_bytes": 50 * 1024 * 1024,
    "very_large_upload_bytes": 200 * 1024 * 1024,
    "burst_connection_threshold": 80,
    "suspicious_ja3_risk_threshold": 0.80,
    "blocked_asns": set(),
    "trusted_asns": set(),
    "sensitive_tags": {"core-banking", "payment", "finance-db", "customer-data-api"},
}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_hour(flow: Dict[str, Any]) -> Optional[int]:
    hour = flow.get("hour")
    if hour is None:
        return None
    try:
        hour = int(hour)
        if 0 <= hour <= 23:
            return hour
    except (TypeError, ValueError):
        pass
    return None


def _add_detection(
    detections: List[Dict[str, Any]],
    *,
    detection_type: str,
    score: float,
    severity: str,
    reason: str,
    recommended_action: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    detections.append({
        "type": detection_type,
        "score": max(0.0, min(1.0, score)),
        "severity": severity,
        "reason": reason,
        "recommended_action": recommended_action,
        "source": "financial_sector_rules",
        "metadata": metadata or {},
    })


def detect_high_risk_country(flow: Dict, cfg: Dict, detections: List) -> None:
    dst_country = str(flow.get("dst_country", "")).upper().strip()
    if not dst_country:
        return
    if dst_country in cfg["high_risk_countries"]:
        _add_detection(
            detections,
            detection_type="high_risk_country",
            score=0.86,
            severity="high",
            reason=f"Outbound connection to high-risk country: {dst_country}",
            recommended_action="block",
            metadata={"dst_country": dst_country, "dst_ip": flow.get("dst_ip"), "dst_host": flow.get("dst_host")},
        )


def detect_blocked_asn(flow: Dict, cfg: Dict, detections: List) -> None:
    asn = str(flow.get("dst_asn", "")).strip()
    if not asn or asn not in cfg["blocked_asns"]:
        return
    _add_detection(
        detections,
        detection_type="blocked_asn",
        score=0.95,
        severity="critical",
        reason=f"Connection to blocked ASN: {asn}",
        recommended_action="block",
        metadata={"dst_asn": asn, "dst_ip": flow.get("dst_ip"), "dst_host": flow.get("dst_host")},
    )


def detect_unknown_external_asn(flow: Dict, cfg: Dict, detections: List) -> None:
    asn = str(flow.get("dst_asn", "")).strip()
    internal = bool(flow.get("is_internal", False))
    known_vendor = bool(flow.get("known_vendor", False))
    if internal or not asn or not cfg["trusted_asns"]:
        return
    if asn not in cfg["trusted_asns"] and not known_vendor:
        _add_detection(
            detections,
            detection_type="unknown_external_asn",
            score=0.72,
            severity="medium",
            reason=f"Connection to non-trusted external ASN: {asn}",
            recommended_action="alert",
            metadata={"dst_asn": asn, "dst_ip": flow.get("dst_ip"), "known_vendor": known_vendor},
        )


def detect_suspicious_port(flow: Dict, cfg: Dict, detections: List) -> None:
    if flow.get("dst_port") is None:
        return
    dst_port = _safe_int(flow.get("dst_port"))
    if dst_port in cfg["suspicious_ports"]:
        _add_detection(
            detections,
            detection_type="suspicious_port",
            score=0.68,
            severity="medium",
            reason=f"Connection to suspicious destination port: {dst_port}",
            recommended_action="alert",
            metadata={"dst_port": dst_port, "dst_ip": flow.get("dst_ip")},
        )


def detect_large_outbound_transfer(flow: Dict, cfg: Dict, detections: List) -> None:
    bytes_out = _safe_int(flow.get("bytes_out"))
    if bool(flow.get("is_internal", False)):
        return
    if bytes_out >= cfg["very_large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="very_large_outbound_transfer",
            score=0.96,
            severity="critical",
            reason=f"Very large outbound transfer detected: {bytes_out} bytes",
            recommended_action="block",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "app_tag": flow.get("app_tag")},
        )
    elif bytes_out >= cfg["large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="large_outbound_transfer",
            score=0.81,
            severity="high",
            reason=f"Large outbound transfer detected: {bytes_out} bytes",
            recommended_action="alert",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "app_tag": flow.get("app_tag")},
        )


def detect_sensitive_asset_exfil(flow: Dict, cfg: Dict, detections: List) -> None:
    asset_tag = str(flow.get("asset_tag", "")).strip().lower()
    bytes_out = _safe_int(flow.get("bytes_out"))
    if bool(flow.get("is_internal", False)) or not asset_tag:
        return
    if asset_tag in cfg["sensitive_tags"] and bytes_out >= 10 * 1024 * 1024:
        _add_detection(
            detections,
            detection_type="sensitive_asset_exfiltration_risk",
            score=0.93,
            severity="critical",
            reason=f"Sensitive financial asset communicated externally with significant outbound volume ({bytes_out} bytes)",
            recommended_action="block",
            metadata={"asset_tag": asset_tag, "bytes_out": bytes_out, "dst_ip": flow.get("dst_ip")},
        )


def detect_after_hours_external_activity(flow: Dict, cfg: Dict, detections: List) -> None:
    if bool(flow.get("is_internal", False)):
        return
    hour = _get_hour(flow)
    if hour is None:
        return
    start = cfg["approved_business_hours_start"]
    end = cfg["approved_business_hours_end"]
    if hour < start or hour > end:
        bytes_out = _safe_int(flow.get("bytes_out"))
        score = 0.60 if bytes_out < 5 * 1024 * 1024 else 0.77
        _add_detection(
            detections,
            detection_type="after_hours_external_activity",
            score=score,
            severity="medium" if score < 0.70 else "high",
            reason=f"External activity outside approved financial operating hours at {hour:02d}:00",
            recommended_action="alert",
            metadata={"hour": hour, "bytes_out": bytes_out, "dst_ip": flow.get("dst_ip")},
        )


def detect_tls_anomaly(flow: Dict, cfg: Dict, detections: List) -> None:
    if not bool(flow.get("tls_used", False)):
        return
    known_vendor = bool(flow.get("known_vendor", False))
    ja3_risk = _safe_float(flow.get("ja3_risk_score"))
    if ja3_risk >= cfg["suspicious_ja3_risk_threshold"] and not known_vendor:
        _add_detection(
            detections,
            detection_type="tls_fingerprint_anomaly",
            score=0.84,
            severity="high",
            reason=f"Suspicious TLS client fingerprint detected (risk={ja3_risk:.2f})",
            recommended_action="alert",
            metadata={"ja3": flow.get("ja3"), "ja3_risk_score": ja3_risk, "dst_ip": flow.get("dst_ip")},
        )
    if not bool(flow.get("sni_present", True)) and not known_vendor:
        _add_detection(
            detections,
            detection_type="missing_sni_on_external_tls",
            score=0.71,
            severity="medium",
            reason="External TLS session without SNI in a financial environment",
            recommended_action="alert",
            metadata={"dst_ip": flow.get("dst_ip"), "dst_port": flow.get("dst_port"), "ja3": flow.get("ja3")},
        )


def detect_api_anomaly(flow: Dict, cfg: Dict, detections: List) -> None:
    if not bool(flow.get("api_call", False)):
        return
    method = str(flow.get("http_method", "")).upper().strip()
    status_code = _safe_int(flow.get("status_code"))
    if bool(flow.get("unknown_endpoint", False)):
        _add_detection(
            detections,
            detection_type="unknown_api_endpoint",
            score=0.74,
            severity="medium",
            reason="API request to unknown or non-approved endpoint",
            recommended_action="alert",
            metadata={"endpoint": flow.get("endpoint"), "method": method, "status_code": status_code},
        )
    if bool(flow.get("schema_violation", False)):
        _add_detection(
            detections,
            detection_type="api_schema_violation",
            score=0.88,
            severity="high",
            reason="API payload/schema anomaly in financial service traffic",
            recommended_action="block",
            metadata={"endpoint": flow.get("endpoint"), "method": method},
        )
    if bool(flow.get("auth_failure_burst", False)):
        _add_detection(
            detections,
            detection_type="api_auth_failure_burst",
            score=0.85,
            severity="high",
            reason="Repeated API authentication failures detected",
            recommended_action="block",
            metadata={"endpoint": flow.get("endpoint"), "method": method, "src_ip": flow.get("src_ip")},
        )


def detect_connection_burst(flow: Dict, cfg: Dict, detections: List) -> None:
    burst_count = _safe_int(flow.get("burst_conn_count"))
    if burst_count >= cfg["burst_connection_threshold"]:
        _add_detection(
            detections,
            detection_type="burst_connection_pattern",
            score=0.79,
            severity="high",
            reason=f"Abnormally high connection burst detected: {burst_count} connections",
            recommended_action="alert",
            metadata={"burst_conn_count": burst_count, "src_ip": flow.get("src_ip"), "dst_ip": flow.get("dst_ip")},
        )


def evaluate_financial_sector(
    flow: Dict[str, Any],
    custom_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    cfg = copy.deepcopy(FINANCIAL_DEFAULTS)
    if custom_cfg:
        cfg.update(custom_cfg)
    detections: List[Dict[str, Any]] = []
    detect_high_risk_country(flow, cfg, detections)
    detect_blocked_asn(flow, cfg, detections)
    detect_unknown_external_asn(flow, cfg, detections)
    detect_suspicious_port(flow, cfg, detections)
    detect_large_outbound_transfer(flow, cfg, detections)
    detect_sensitive_asset_exfil(flow, cfg, detections)
    detect_after_hours_external_activity(flow, cfg, detections)
    detect_tls_anomaly(flow, cfg, detections)
    detect_api_anomaly(flow, cfg, detections)
    detect_connection_burst(flow, cfg, detections)
    return detections
