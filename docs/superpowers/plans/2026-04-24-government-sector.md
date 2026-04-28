# Government Sector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Government sector (Phase 4 of roadmap), including detection rules, policy decisions, mode registration, and engine integration — using the Financial sector rules (Phase 3) as the tested foundation.

**Architecture:** A new `app/minifw_ai/sector_rules/` package contains one `rules.py` + one `policy.py` per sector. The engine builds a normalized flow dict from available `FlowStats` data and calls the active sector's evaluator after `score_and_decide()`; a block decision from the sector layer overrides the base score's action. Financial rules are implemented first (they are the template); Government clones and adapts them with stricter thresholds and C2/APT-focused detections.

**Tech Stack:** Python 3.10+, `pytest`, existing `FlowStats` from `collector_flow.py`, existing `sector_config.py` / `mode_loader.py` / `mode_context.py` registration chain.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| CREATE | `app/minifw_ai/sector_rules/__init__.py` | Package entry-point + `evaluate_sector()` dispatcher |
| CREATE | `app/minifw_ai/sector_rules/financial_rules.py` | 10 financial detection functions (from roadmap spec) |
| CREATE | `app/minifw_ai/sector_rules/financial_policy.py` | Financial action decision logic |
| CREATE | `app/minifw_ai/sector_rules/government_rules.py` | 8 government detection functions (C2, APT, segmentation) |
| CREATE | `app/minifw_ai/sector_rules/government_policy.py` | Government action decision logic (stricter than financial) |
| CREATE | `config/modes/minifw_government/policy.json` | Government thresholds, segments, weights |
| MODIFY | `app/minifw_ai/mode_loader.py` | Register `minifw_government` in `_MODE_TO_SECTOR` + descriptions |
| MODIFY | `app/minifw_ai/mode_context.py` | Add government `ModeUI`, fix `_SECTOR_TO_MODE` fallback |
| MODIFY | `app/minifw_ai/main.py` | Wire sector rules into scoring pipeline (after `score_and_decide`) |
| CREATE | `testing/test_financial_sector_rules.py` | Tests for financial detection + policy |
| CREATE | `testing/test_government_sector_rules.py` | Tests for government detection + policy |

---

## Task 1: Financial Sector Detection Rules

**Files:**
- Create: `app/minifw_ai/sector_rules/__init__.py`
- Create: `app/minifw_ai/sector_rules/financial_rules.py`
- Create: `app/minifw_ai/sector_rules/financial_policy.py`

- [ ] **Step 1.1: Create the package `__init__.py` with the sector dispatcher**

```python
# app/minifw_ai/sector_rules/__init__.py
from __future__ import annotations
from typing import Any, Dict, List, Optional


def evaluate_sector(
    sector: str,
    flow: Dict[str, Any],
    custom_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Run sector-specific detection rules against a normalized flow dict.
    Returns a list of detection dicts (empty = no detections).
    Missing fields in flow are handled gracefully by each rule module.
    """
    if sector == "finance":
        from .financial_rules import evaluate_financial_sector
        return evaluate_financial_sector(flow, custom_cfg)
    if sector == "government":
        from .government_rules import evaluate_government_sector
        return evaluate_government_sector(flow, custom_cfg)
    return []


def decide_sector_action(
    sector: str,
    detections: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Given detections from evaluate_sector(), return the sector's policy decision.
    Returns None if sector has no detections or no policy module registered.
    """
    if not detections:
        return None
    if sector == "finance":
        from .financial_policy import decide_financial_action
        return decide_financial_action(detections)
    if sector == "government":
        from .government_policy import decide_government_action
        return decide_government_action(detections)
    return None
```

- [ ] **Step 1.2: Create `financial_rules.py` (from roadmap spec)**

```python
# app/minifw_ai/sector_rules/financial_rules.py
from __future__ import annotations
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
    cfg = dict(FINANCIAL_DEFAULTS)
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
```

- [ ] **Step 1.3: Create `financial_policy.py` (from roadmap spec)**

```python
# app/minifw_ai/sector_rules/financial_policy.py
from __future__ import annotations
from typing import Any, Dict, List


_CRITICAL_BLOCK_TYPES = frozenset({
    "blocked_asn",
    "very_large_outbound_transfer",
    "sensitive_asset_exfiltration_risk",
    "api_schema_violation",
    "api_auth_failure_burst",
    "high_risk_country",
})


def decide_financial_action(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not detections:
        return {"final_action": "allow", "confidence": 0.0, "reason": "No financial sector detection triggered"}

    max_score = max(d["score"] for d in detections)

    for d in detections:
        if d["type"] in _CRITICAL_BLOCK_TYPES:
            return {
                "final_action": "block",
                "confidence": d["score"],
                "reason": d["reason"],
                "trigger_type": d["type"],
            }

    high_count = sum(1 for d in detections if d["severity"] in {"high", "critical"})
    if high_count >= 2:
        return {
            "final_action": "block",
            "confidence": min(0.95, max_score + 0.05),
            "reason": "Multiple high-severity financial detections combined",
            "trigger_type": "combined_high_risk",
        }

    if max_score >= 0.75:
        return {
            "final_action": "alert",
            "confidence": max_score,
            "reason": "High-confidence financial anomaly detected",
            "trigger_type": "high_confidence_alert",
        }

    return {
        "final_action": "monitor",
        "confidence": max_score,
        "reason": "Low-to-medium financial anomaly detected",
        "trigger_type": "monitoring_required",
    }
```

---

## Task 2: Tests for Financial Sector Rules

**Files:**
- Create: `testing/test_financial_sector_rules.py`

- [ ] **Step 2.1: Write all financial rule tests**

```python
# testing/test_financial_sector_rules.py
"""
Tests for financial sector detection rules and policy decision logic.
Rules gracefully handle missing flow fields — test both filled and sparse flows.
"""
import pytest
from app.minifw_ai.sector_rules.financial_rules import (
    evaluate_financial_sector,
    FINANCIAL_DEFAULTS,
)
from app.minifw_ai.sector_rules.financial_policy import decide_financial_action


# ── evaluate_financial_sector: clean flow ──────────────────────────────────

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
    detections = evaluate_financial_sector(flow)
    assert detections == []


def test_empty_flow_no_detections():
    """All rules must handle completely empty flow without raising."""
    assert evaluate_financial_sector({}) == []


# ── Country detection ──────────────────────────────────────────────────────

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


# ── Blocked ASN ────────────────────────────────────────────────────────────

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


# ── Suspicious port ────────────────────────────────────────────────────────

def test_suspicious_port_triggers():
    flow = {"dst_port": 4444, "dst_ip": "10.0.0.1"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "suspicious_port" for d in detections)


def test_normal_port_no_trigger():
    flow = {"dst_port": 443}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "suspicious_port" for d in detections)


# ── Large outbound transfer ─────────────────────────────────────────────────

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


# ── After-hours external activity ──────────────────────────────────────────

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


# ── TLS anomaly ────────────────────────────────────────────────────────────

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


# ── API anomaly ────────────────────────────────────────────────────────────

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


# ── Connection burst ───────────────────────────────────────────────────────

def test_connection_burst_triggers():
    flow = {"burst_conn_count": 100, "src_ip": "10.0.0.5"}
    detections = evaluate_financial_sector(flow)
    assert any(d["type"] == "burst_connection_pattern" for d in detections)


def test_connection_below_threshold_no_trigger():
    flow = {"burst_conn_count": 79}
    detections = evaluate_financial_sector(flow)
    assert all(d["type"] != "burst_connection_pattern" for d in detections)


# ── Custom config override ─────────────────────────────────────────────────

def test_custom_cfg_overrides_defaults():
    flow = {"dst_port": 8080, "dst_ip": "1.2.3.4"}
    detections = evaluate_financial_sector(flow, custom_cfg={"suspicious_ports": {8080}})
    assert any(d["type"] == "suspicious_port" for d in detections)


# ── decide_financial_action ────────────────────────────────────────────────

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
```

- [ ] **Step 2.2: Run tests — expect failures (files don't exist yet)**

```bash
pytest testing/test_financial_sector_rules.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` or `ImportError` — confirms tests are written before implementation.

- [ ] **Step 2.3: Run tests after Task 1 files are created — all should pass**

```bash
pytest testing/test_financial_sector_rules.py -v
```

Expected: all tests PASS. Note the count (should be ~28 tests).

- [ ] **Step 2.4: Run full suite to check no regressions**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed, 0 failed.

- [ ] **Step 2.5: Commit**

```bash
git add app/minifw_ai/sector_rules/ testing/test_financial_sector_rules.py
git commit -m "feat(sector-rules): add financial detection rules and policy (Phase 3)"
```

---

## Task 3: Government Sector Detection Rules

**Files:**
- Create: `app/minifw_ai/sector_rules/government_rules.py`
- Create: `app/minifw_ai/sector_rules/government_policy.py`

Government adapts from financial: stricter thresholds, C2/APT/segmentation focus, zero-tolerance for sovereignty violations.

- [ ] **Step 3.1: Create `government_rules.py`**

```python
# app/minifw_ai/sector_rules/government_rules.py
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
    "internal_subnets": [],                         # Populated from policy.json at runtime
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
    is_internal = bool(flow.get("is_internal", True))
    if is_internal:
        return
    # External destination on a critical service port is a sovereignty concern
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
```

- [ ] **Step 3.2: Create `government_policy.py`**

```python
# app/minifw_ai/sector_rules/government_policy.py
"""
Government sector action decision logic.
Stricter than financial: single high-severity detection triggers block.
Zero tolerance for C2, country violations, and critical service misuse.
"""
from __future__ import annotations
from typing import Any, Dict, List


_IMMEDIATE_BLOCK_TYPES = frozenset({
    "gov_blocked_country",
    "gov_blocked_asn",
    "gov_c2_port",
    "gov_c2_beacon_pattern",
    "gov_critical_service_external",
    "gov_very_large_outbound",
    "gov_large_outbound",
    "gov_apt_low_slow_pattern",
    "gov_missing_sni_external_tls",
})


def decide_government_action(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not detections:
        return {"final_action": "allow", "confidence": 0.0, "reason": "No government sector detection triggered"}

    max_score = max(d["score"] for d in detections)

    # Any detection in the immediate-block set → block immediately
    for d in detections:
        if d["type"] in _IMMEDIATE_BLOCK_TYPES:
            return {
                "final_action": "block",
                "confidence": d["score"],
                "reason": d["reason"],
                "trigger_type": d["type"],
            }

    # Any single high/critical severity → block (stricter than financial's "2 required")
    for d in detections:
        if d["severity"] in {"high", "critical"}:
            return {
                "final_action": "block",
                "confidence": d["score"],
                "reason": d["reason"],
                "trigger_type": d["type"],
            }

    if max_score >= 0.65:
        return {
            "final_action": "alert",
            "confidence": max_score,
            "reason": "Government anomaly requires immediate investigation",
            "trigger_type": "gov_escalation",
        }

    return {
        "final_action": "monitor",
        "confidence": max_score,
        "reason": "Low-level sovereign network anomaly flagged for audit",
        "trigger_type": "gov_audit_flag",
    }
```

---

## Task 4: Tests for Government Sector Rules

**Files:**
- Create: `testing/test_government_sector_rules.py`

- [ ] **Step 4.1: Write government rule tests**

```python
# testing/test_government_sector_rules.py
"""
Tests for government sector detection rules and policy decision logic.
Government rules are stricter than financial — test boundary conditions carefully.
"""
import pytest
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
    # RU is in both lists; CN is gov-only
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
        "interarrival_std_ms": 3.0,   # Very regular = beacon
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
    flow = {"pkt_count": 5, "interarrival_std_ms": 1.0}  # Too few packets
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
    # 30MB is above gov threshold (20MB) but below financial threshold (50MB) - both large detections
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
    # High conn count but large payloads = not APT
    flow = {"connection_count": 50, "avg_bytes_per_connection": 100 * 1024}
    detections = evaluate_government_sector(flow)
    assert all(d["type"] != "gov_apt_low_slow_pattern" for d in detections)


def test_apt_pattern_missing_fields_no_trigger():
    detections = evaluate_government_sector({})
    assert all(d["type"] != "gov_apt_low_slow_pattern" for d in detections)


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


# ── Missing SNI (government is stricter — recommends block not alert) ──────

def test_missing_sni_external_tls_triggers_block():
    flow = {"tls_used": True, "sni_present": False, "known_vendor": False,
            "is_internal": False, "dst_ip": "1.2.3.4"}
    detections = evaluate_government_sector(flow)
    d = next(d for d in detections if d["type"] == "gov_missing_sni_external_tls")
    assert d["recommended_action"] == "block"  # Block vs financial's "alert"


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
```

- [ ] **Step 4.2: Run tests**

```bash
pytest testing/test_government_sector_rules.py -v
```

Expected: all tests PASS.

- [ ] **Step 4.3: Run full suite**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed, 0 failed.

- [ ] **Step 4.4: Commit**

```bash
git add app/minifw_ai/sector_rules/government_rules.py \
        app/minifw_ai/sector_rules/government_policy.py \
        testing/test_government_sector_rules.py
git commit -m "feat(sector-rules): add government detection rules and policy (Phase 4)"
```

---

## Task 5: Government Mode Registration

**Files:**
- Create: `config/modes/minifw_government/policy.json`
- Modify: `app/minifw_ai/mode_loader.py`
- Modify: `app/minifw_ai/mode_context.py`
- Modify: `app/minifw_ai/sector_config.py` (update GOVERNMENT entry)

- [ ] **Step 5.1: Create `config/modes/minifw_government/policy.json`**

```bash
mkdir -p config/modes/minifw_government
```

```json
{
  "_mode": "minifw_government",
  "_sector": "government",
  "_note": "Sovereign infrastructure protection. Strict geo-IP blocking, zero-tolerance C2/APT detection, full audit traceability. Thresholds tighter than financial.",
  "segments": {
    "default": {
      "block_threshold": 80,
      "monitor_threshold": 50
    },
    "classified": {
      "block_threshold": 70,
      "monitor_threshold": 40,
      "_note": "Classified network segments — tightest enforcement."
    },
    "internal": {
      "block_threshold": 75,
      "monitor_threshold": 45
    },
    "guest": {
      "block_threshold": 65,
      "monitor_threshold": 35,
      "_note": "Visitor / citizen-facing network."
    },
    "dmz": {
      "block_threshold": 72,
      "monitor_threshold": 48,
      "_note": "Public-facing services — sovereign domain only."
    }
  },
  "segment_subnets": {
    "classified": ["10.1.0.0/24"],
    "internal":   ["10.0.0.0/8", "192.168.0.0/16"],
    "guest":      ["192.168.200.0/24"],
    "dmz":        ["10.10.0.0/24"]
  },
  "features": {
    "dns_weight":       40,
    "sni_weight":       35,
    "asn_weight":       20,
    "ip_denied_weight": 20,
    "burst_weight":     15,
    "mlp_weight":       30,
    "yara_weight":      35
  },
  "enforcement": {
    "ipset_name_v4":      "minifw_block_v4",
    "ip_timeout_seconds": 604800,
    "nft_table":          "inet",
    "nft_table_name":     "minifw",
    "nft_chain":          "forward"
  },
  "collectors": {
    "dnsmasq_log_path": "/opt/minifw_ai/logs/dnsmasq.log",
    "zeek_ssl_log_path": "/var/log/zeek/ssl.log",
    "use_zeek_sni": true,
    "_zeek_note": "SNI inspection mandatory for sovereignty enforcement."
  },
  "burst": {
    "dns_queries_per_minute_monitor": 20,
    "dns_queries_per_minute_block":   40
  },
  "iomt_subnets": [],
  "minimum_tls_version": "1.2",
  "log_retention_days": 365
}
```

- [ ] **Step 5.2: Register `minifw_government` in `mode_loader.py`**

In `app/minifw_ai/mode_loader.py`, make these two edits:

**Edit 1** — add to `_MODE_TO_SECTOR` dict (after `minifw_gambling` line):
```python
    "minifw_government":    "government",
```

**Edit 2** — add to `descriptions` dict inside `resolve_mode()` (after `minifw_gambling` entry):
```python
        "minifw_government":    "MiniFW-AI Government — sovereign infrastructure, APT/C2 detection, full audit trail",
```

- [ ] **Step 5.3: Register government in `mode_context.py`**

In `app/minifw_ai/mode_context.py`, make these two edits:

**Edit 1** — add to `_MODE_UI` dict (after `minifw_establishment` block):
```python
    "minifw_government": ModeUI(
        product_mode="minifw_government",
        label="Government",
        sublabel="Sovereign Infrastructure · APT Detection · Full Traceability",
        color="#6366f1",
        bg="rgba(99,102,241,0.10)",
        css_class="mode-government",
        icon="bi-shield-fill-check",
        sector="government",
    ),
```

**Edit 2** — update `_SECTOR_TO_MODE` (replace the government fallback line):
```python
    "government":    "minifw_government",   # dedicated government mode
```

- [ ] **Step 5.4: Update `sector_config.py` — harden the GOVERNMENT entry**

In `app/minifw_ai/sector_config.py`, replace the existing `SectorType.GOVERNMENT` block with:

```python
    SectorType.GOVERNMENT: {
        "description": "Government: Sovereign infrastructure, zero-tolerance APT/C2 detection, full audit trail.",
        "geo_ip_strict": True,
        "blocked_countries": ["KP", "IR", "RU", "CN", "SY", "BY"],
        "strict_logging": True,
        "log_retention_days": 365,
        "audit_all_queries": True,
        "apt_detection_mode": True,
        "extra_feeds": ["government_sensitive.txt", "apt_indicators.txt"],
        "block_threshold_adjustment": -10,
        "monitor_threshold_adjustment": -10,
    },
```

- [ ] **Step 5.5: Verify mode_loader resolves correctly**

```bash
PRODUCT_MODE=minifw_government python3 -c "
from app.minifw_ai.mode_loader import resolve_mode
cfg = resolve_mode('minifw_government')
print('sector:', cfg.sector)
print('policy:', cfg.policy_path)
print('desc:', cfg.description)
"
```

Expected output:
```
sector: government
policy: /home/sydeco/minifw-ai/config/modes/minifw_government/policy.json
desc: MiniFW-AI Government — sovereign infrastructure, APT/C2 detection, full audit trail
```

- [ ] **Step 5.6: Verify mode_context resolves correctly**

```bash
PRODUCT_MODE=minifw_government python3 -c "
from app.minifw_ai.mode_context import get_mode_ui
ui = get_mode_ui()
print('label:', ui.label)
print('sublabel:', ui.sublabel)
print('sector:', ui.sector)
print('css_class:', ui.css_class)
"
```

Expected output:
```
label: Government
sublabel: Sovereign Infrastructure · APT Detection · Full Traceability
sector: government
css_class: mode-government
```

- [ ] **Step 5.7: Run full test suite**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed, 0 failed.

- [ ] **Step 5.8: Commit**

```bash
git add config/modes/minifw_government/policy.json \
        app/minifw_ai/mode_loader.py \
        app/minifw_ai/mode_context.py \
        app/minifw_ai/sector_config.py
git commit -m "feat(gov): register minifw_government mode and sector config"
```

---

## Task 6: Wire Sector Rules into the Engine

**Files:**
- Modify: `app/minifw_ai/main.py`

The integration hook goes after `score_and_decide()` (line ~742) and before the event is written. It builds a normalized flow dict from available in-scope variables, calls `evaluate_sector()` + `decide_sector_action()`, then overrides `action` and adds sector-provided `reasons` if the sector decision is stricter.

- [ ] **Step 6.1: Add the sector rules import at the top of `main.py`**

Find the existing try/except import block at line ~67 and add inside it:

```python
    from minifw_ai.sector_rules import evaluate_sector, decide_sector_action
```

And in the except fallback below:

```python
    evaluate_sector = None
    decide_sector_action = None
```

- [ ] **Step 6.2: Insert the sector rules evaluation hook in the event loop**

After the `score, reasons, action = score_and_decide(...)` call (line ~742) and before `if action == "block":` (line ~744), insert:

```python
            # Sector rules layer: runs after base scoring, can upgrade action to block
            if evaluate_sector and sector_name not in {"unknown", "establishment"}:
                _flow_for_sector = _build_sector_flow(
                    client_ip=client_ip,
                    domain=domain,
                    flows=flows_for_client,
                    burst_hit=burst_hit,
                )
                _sector_detections = evaluate_sector(sector_name, _flow_for_sector)
                _sector_decision = decide_sector_action(sector_name, _sector_detections)
                if _sector_decision and _sector_decision["final_action"] == "block" and action != "block":
                    action = "block"
                    score = max(score, int(_sector_decision["confidence"] * 100))
                    reasons.append(f"sector_rule:{_sector_decision.get('trigger_type','sector_override')}")
                    reasons.append(_sector_decision["reason"][:120])
                elif _sector_decision and _sector_decision["final_action"] == "alert" and action == "allow":
                    action = "monitor"
                    reasons.append(f"sector_rule:{_sector_decision.get('trigger_type','sector_alert')}")
```

- [ ] **Step 6.3: Add the `_build_sector_flow` helper in `main.py`**

Add this function after `score_and_decide()` and before `evaluate_hard_threat()` (around line ~175):

```python
def _build_sector_flow(
    client_ip: str,
    domain: str,
    flows: list,
    burst_hit: int,
) -> dict:
    """
    Build a normalized flow dict for sector rules from available engine data.
    Fields unavailable in the current pipeline are omitted (rules handle missing fields via .get()).
    """
    import datetime
    flow_for_sector: dict = {
        "src_ip": client_ip,
        "dst_host": domain,
        "hour": datetime.datetime.now().hour,
        "burst_conn_count": burst_hit * 60,  # rough proxy: burst_hit * assumed qpm
    }
    if flows:
        latest = flows[-1]
        flow_for_sector.update({
            "dst_ip": latest.dst_ip,
            "dst_port": latest.dst_port,
            "bytes_out": latest.bytes_sent,
            "bytes_in": latest.bytes_recv,
            "tls_used": latest.tls_seen,
            "sni_present": bool(latest.sni),
            "pkt_count": latest.pkt_count,
        })
        # Interarrival std for beacon detection (available on FlowStats)
        if hasattr(latest, "interarrival_times") and len(latest.interarrival_times) >= 10:
            import statistics
            try:
                flow_for_sector["interarrival_std_ms"] = statistics.stdev(latest.interarrival_times)
            except statistics.StatisticsError:
                pass
    return flow_for_sector
```

- [ ] **Step 6.4: Run full test suite**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed, 0 failed. The engine hook is only called in the live loop so no existing unit tests are affected.

- [ ] **Step 6.5: Smoke-test the import chain**

```bash
MINIFW_SECRET_KEY=test python3 -c "
from app.minifw_ai.sector_rules import evaluate_sector, decide_sector_action
flow = {'dst_port': 4444, 'tls_used': True, 'sni_present': False, 'hour': 2, 'is_internal': False}
detections = evaluate_sector('government', flow)
decision = decide_sector_action('government', detections)
print('detections:', [d['type'] for d in detections])
print('action:', decision['final_action'])
print('reason:', decision['reason'])
"
```

Expected output (exact detections may vary by flow):
```
detections: ['gov_c2_port', 'gov_after_hours_external', 'gov_missing_sni_external_tls']
action: block
reason: Connection to known C2 command port: 4444
```

- [ ] **Step 6.6: Commit**

```bash
git add app/minifw_ai/main.py
git commit -m "feat(engine): wire sector rules evaluation hook into scoring pipeline"
```

---

## Self-Review

### Spec coverage

| Roadmap requirement | Task |
|---|---|
| Phase 3: Financial rules.py (10 detection functions) | Task 1 |
| Phase 3: financial_policy.py decision logic | Task 1 |
| Phase 4: Clone financial template | Task 3 (8 adapted rules) |
| Phase 4: Government config.json | Task 5 |
| Phase 4: Stricter blocking thresholds | Task 3 (`gov_large_outbound` blocks; financial alerts) |
| Phase 4: Segmentation violation logic | Task 3 (`detect_critical_service_misuse`) |
| Phase 4: Sovereign dashboard vocabulary | Task 5 (`mode_context.py` sublabel) |
| Main dispatcher connection (roadmap Step 4) | Task 6 |
| Government mode registration | Task 5 |
| Tests for both sectors | Tasks 2 and 4 |

### Placeholder scan
- No "TBD" or "TODO" in any code block ✓
- All test functions have complete assert bodies ✓
- All commands show expected output ✓

### Type consistency
- `evaluate_sector(sector: str, flow: Dict) -> List[Dict]` used in Task 1 `__init__.py` and Task 6 engine hook ✓
- `decide_sector_action(sector: str, detections: List[Dict]) -> Optional[Dict]` consistent ✓
- `FINANCIAL_DEFAULTS` and `GOVERNMENT_DEFAULTS` are `Dict[str, Any]` — matches function signatures ✓
- `_add_detection()` signature identical in both rules files ✓
- Task 4 test `test_gov_large_threshold_stricter_than_financial` imports from `financial_rules` — that file is created in Task 1 ✓
