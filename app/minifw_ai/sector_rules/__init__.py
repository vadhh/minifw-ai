from __future__ import annotations
from typing import Any, Dict, List, Optional


def evaluate_sector(
    sector: str,
    flow: Dict[str, Any],
    custom_cfg: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
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
    if not detections:
        return None
    if sector == "finance":
        from .financial_policy import decide_financial_action
        return decide_financial_action(detections)
    if sector == "government":
        from .government_policy import decide_government_action
        return decide_government_action(detections)
    return None
