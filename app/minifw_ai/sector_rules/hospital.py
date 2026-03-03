"""
Sector Rules - Hospital Module

Handles IoMT (Internet of Medical Things) device awareness for the hospital
sector. Threshold adjustments (-20 monitor, -5 block) are already applied by
main.py via sector_config.py — this module handles only the post-decision
high-priority alerting for medical device subnets.

HIPAA compliance notes (from sector_config.py):
  - redact_payloads: True  — do not log payload content
  - strict_pii_logging: False — minimize PII in log lines
"""
from __future__ import annotations
import logging
from typing import Tuple, List

from minifw_ai.netutil import ip_in_any_subnet

logger = logging.getLogger(__name__)


def load_config(pol) -> List[str]:
    """
    Load IoMT subnet list from policy config.

    Called once at engine startup. Returns list of CIDR strings representing
    medical device subnets (e.g. patient monitors, infusion pumps, imaging).

    Args:
        pol: Policy instance (minifw_ai.policy.Policy)

    Returns:
        List of CIDR strings, empty list if not configured.
    """
    subnets = pol.cfg.get("iomt_subnets", [])
    if subnets:
        logger.info("[HOSPITAL] IoMT subnets loaded: %s", subnets)
    else:
        logger.warning("[HOSPITAL] No iomt_subnets configured in policy.json — IoMT alerting disabled")
    return subnets


def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    Hospital sector evaluation — no additional blocking rules beyond base.py.

    Threshold adjustments (-20 monitor / -5 block) are applied upstream in
    main.py via sector_config.py. This function satisfies the sector module
    interface but defers all blocking decisions to the score pipeline.

    Returns:
        ("allow", "") always — hospital rules are post-decision only.
    """
    return "allow", ""


def post_decision(
    client_ip: str,
    domain: str,
    score: int,
    thr,
    iomt_subnets: List[str],
    reasons: list,
) -> None:
    """
    Fire CRITICAL alert when a medical device shows anomalous traffic.

    Called after score_and_decide() for every event. Checks whether the
    querying client is in a known IoMT subnet and the threat score is
    noteworthy enough to warrant escalation.

    Args:
        client_ip:     querying client IP address
        domain:        DNS queried domain
        score:         final threat score (0-100) from score_and_decide()
        thr:           SegmentThreshold (has .block_threshold, .monitor_threshold)
        iomt_subnets:  list of CIDR strings from load_config()
        reasons:       mutable reasons list — appended to if alert fires
    """
    if not iomt_subnets:
        return

    if not ip_in_any_subnet(client_ip, iomt_subnets):
        return

    if score >= thr.monitor_threshold:
        logger.critical(
            "[IOMT_ALERT] Medical device anomaly: %s → %s (score=%d)",
            client_ip, domain, score,
        )
        if "iomt_device_alert" not in reasons:
            reasons.append("iomt_device_alert")
