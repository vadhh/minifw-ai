"""
Government sector detection rules.
Adapted from financial rules. Key differences:
- Extended blocked country list (adds CN, BY)
- C2 beacon detection via interarrival regularity
- Segmentation violation detection
- Critical service (DNS/NTP/SNMP/LDAP) misuse
- APT-pattern: many small outbound connections
- Stricter after-hours window (7-20 vs financial 6-22)
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


GOVERNMENT_DEFAULTS: Dict[str, Any] = {
    "blocked_countries": {"KP", "IR", "SY", "RU", "CN", "BY"},
    "c2_ports": {4444, 5555, 6666, 7777, 1337, 8008, 31337},
    "critical_service_ports": {53, 123, 161, 162, 389, 636},   # DNS, NTP, SNMP, LDAP
    "approved_business_hours_start": 7,
    "approved_business_hours_end": 20,
    "large_upload_bytes": 20 * 1024 * 1024,         # Stricter than financial (50MB)
    "very_large_upload_bytes": 100 * 1024 * 1024,   # Stricter than financial (200MB)
    "burst_connection_threshold": 50,               # Stricter than financial (80)
    "beacon_interarrival_std_ms_max": 10.0,         # Regular callbacks = C2 beacon
    "beacon_min_pkt_count": 20,                     # Sustained, not one-off
    "apt_connection_count": 30,                     # Many small connections = APT dwell
    "apt_small_bytes_per_conn": 2 * 1024,           # Each conn < 2KB (low-slow exfil)
    "blocked_asns": set(),
    "trusted_asns": set(),
    "critical_asset_tags": {"domain-controller", "dns-server", "auth-server", "ntp", "scada", "ics"},
    "internal_subnets": [],
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
        "source": "government_sector_rules",
        "metadata": metadata or {},
    })


def detect_blocked_country(flow: Dict, cfg: Dict, detections: List) -> None:
    dst_country = str(flow.get("dst_country", "")).upper().strip()
    if dst_country and dst_country in cfg["blocked_countries"]:
        _add_detection(
            detections,
            detection_type="gov_blocked_country",
            score=0.95,
            severity="critical",
            reason=f"Outbound connection to geopolitically blocked country: {dst_country}",
            recommended_action="block",
            metadata={"dst_country": dst_country, "dst_ip": flow.get("dst_ip"), "dst_host": flow.get("dst_host")},
        )


def detect_blocked_asn(flow: Dict, cfg: Dict, detections: List) -> None:
    asn = str(flow.get("dst_asn", "")).strip()
    if asn and asn in cfg["blocked_asns"]:
        _add_detection(
            detections,
            detection_type="gov_blocked_asn",
            score=0.97,
            severity="critical",
            reason=f"Connection to restricted ASN: {asn}",
            recommended_action="block",
            metadata={"dst_asn": asn, "dst_ip": flow.get("dst_ip")},
        )


def detect_c2_port(flow: Dict, cfg: Dict, detections: List) -> None:
    dst_port = _safe_int(flow.get("dst_port"))
    if dst_port in cfg["c2_ports"]:
        _add_detection(
            detections,
            detection_type="gov_c2_port",
            score=0.90,
            severity="critical",
            reason=f"Connection to known C2 command port: {dst_port}",
            recommended_action="block",
            metadata={"dst_port": dst_port, "dst_ip": flow.get("dst_ip"), "src_ip": flow.get("src_ip")},
        )


def detect_c2_beacon(flow: Dict, cfg: Dict, detections: List) -> None:
    """Detect C2 beaconing via regular inter-packet timing."""
    pkt_count = _safe_int(flow.get("pkt_count"))
    if pkt_count < cfg["beacon_min_pkt_count"]:
        return
    iat_std = _safe_float(flow.get("interarrival_std_ms"), default=9999.0)
    if iat_std <= cfg["beacon_interarrival_std_ms_max"]:
        _add_detection(
            detections,
            detection_type="gov_c2_beacon_pattern",
            score=0.88,
            severity="critical",
            reason=f"Regular inter-packet timing detected (std={iat_std:.1f}ms, pkts={pkt_count}) — C2 beacon pattern",
            recommended_action="block",
            metadata={"interarrival_std_ms": iat_std, "pkt_count": pkt_count,
                      "dst_ip": flow.get("dst_ip"), "dst_port": flow.get("dst_port")},
        )


def detect_critical_service_misuse(flow: Dict, cfg: Dict, detections: List) -> None:
    """Detect anomalous traffic involving critical infrastructure protocols."""
    dst_port = _safe_int(flow.get("dst_port"))
    if dst_port not in cfg["critical_service_ports"]:
        return
    if bool(flow.get("is_internal", True)):
        return
    _add_detection(
        detections,
        detection_type="gov_critical_service_external",
        score=0.85,
        severity="critical",
        reason=f"Critical infrastructure protocol (port {dst_port}) routed to external destination",
        recommended_action="block",
        metadata={"dst_port": dst_port, "dst_ip": flow.get("dst_ip"), "src_ip": flow.get("src_ip")},
    )


def detect_large_outbound_transfer(flow: Dict, cfg: Dict, detections: List) -> None:
    bytes_out = _safe_int(flow.get("bytes_out"))
    if bool(flow.get("is_internal", False)):
        return
    if bytes_out >= cfg["very_large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="gov_very_large_outbound",
            score=0.98,
            severity="critical",
            reason=f"Very large outbound transfer from sovereign network: {bytes_out} bytes",
            recommended_action="block",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "src_ip": flow.get("src_ip")},
        )
    elif bytes_out >= cfg["large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="gov_large_outbound",
            score=0.84,
            severity="high",
            reason=f"Large outbound transfer from sovereign network: {bytes_out} bytes",
            recommended_action="block",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "src_ip": flow.get("src_ip")},
        )


def detect_apt_pattern(flow: Dict, cfg: Dict, detections: List) -> None:
    """Low-and-slow exfiltration: many connections, each carrying small payloads."""
    conn_count = _safe_int(flow.get("connection_count"))
    bytes_per_conn = _safe_int(flow.get("avg_bytes_per_connection"))
    if conn_count == 0 or bytes_per_conn == 0:
        return
    if conn_count >= cfg["apt_connection_count"] and bytes_per_conn <= cfg["apt_small_bytes_per_conn"]:
        _add_detection(
            detections,
            detection_type="gov_apt_low_slow_pattern",
            score=0.82,
            severity="high",
            reason=f"APT low-and-slow exfiltration pattern: {conn_count} connections averaging {bytes_per_conn} bytes each",
            recommended_action="block",
            metadata={"connection_count": conn_count, "avg_bytes_per_connection": bytes_per_conn,
                      "dst_ip": flow.get("dst_ip"), "src_ip": flow.get("src_ip")},
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
        asset_tag = str(flow.get("asset_tag", "")).strip().lower()
        is_critical_asset = asset_tag in cfg["critical_asset_tags"]
        score = 0.91 if is_critical_asset else 0.72
        severity = "critical" if is_critical_asset else "high"
        _add_detection(
            detections,
            detection_type="gov_after_hours_external",
            score=score,
            severity=severity,
            reason=f"External sovereign network activity outside approved hours at {hour:02d}:00"
                   + (f" from critical asset: {asset_tag}" if is_critical_asset else ""),
            recommended_action="block" if is_critical_asset else "alert",
            metadata={"hour": hour, "asset_tag": asset_tag, "dst_ip": flow.get("dst_ip")},
        )


def detect_missing_sni_on_external_tls(flow: Dict, cfg: Dict, detections: List) -> None:
    if not bool(flow.get("tls_used", False)):
        return
    if bool(flow.get("is_internal", False)):
        return
    if not bool(flow.get("sni_present", True)) and not bool(flow.get("known_vendor", False)):
        _add_detection(
            detections,
            detection_type="gov_missing_sni_external_tls",
            score=0.80,
            severity="high",
            reason="External TLS session without SNI — covert channel risk on sovereign infrastructure",
            recommended_action="block",
            metadata={"dst_ip": flow.get("dst_ip"), "dst_port": flow.get("dst_port")},
        )


def evaluate_government_sector(
    flow: Dict[str, Any],
    custom_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    cfg = dict(GOVERNMENT_DEFAULTS)
    if custom_cfg:
        cfg.update(custom_cfg)
    detections: List[Dict[str, Any]] = []
    detect_blocked_country(flow, cfg, detections)
    detect_blocked_asn(flow, cfg, detections)
    detect_c2_port(flow, cfg, detections)
    detect_c2_beacon(flow, cfg, detections)
    detect_critical_service_misuse(flow, cfg, detections)
    detect_large_outbound_transfer(flow, cfg, detections)
    detect_apt_pattern(flow, cfg, detections)
    detect_after_hours_external_activity(flow, cfg, detections)
    detect_missing_sni_on_external_tls(flow, cfg, detections)
    return detections
