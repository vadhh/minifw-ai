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

    for d in detections:
        if d["type"] in _IMMEDIATE_BLOCK_TYPES:
            return {
                "final_action": "block",
                "confidence": d["score"],
                "reason": d["reason"],
                "trigger_type": d["type"],
            }

    # Single high/critical severity → block (stricter than financial's "2 required")
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
