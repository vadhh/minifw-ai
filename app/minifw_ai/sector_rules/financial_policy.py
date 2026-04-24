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
