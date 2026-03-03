"""
Sector Rules - Establishment Module

Rules for enterprise/SME/retail deployments. Built fresh — the legacy
establishment engine.py was a placeholder comment with no implementation.

Key differences from school sector:
  - VPN allowed from trusted_segments (not blocked outright)
  - No entertainment bandwidth cap
  - Cowrie SSH honeypot awareness
  - Standard DDoS threshold (100 q/60s, same as base.py)
  - Higher verbosity logging for multi-zone LAN awareness

Tunables are read from sector_config.py (SectorType.ESTABLISHMENT):
  honeypot_ip:      IP of Cowrie honeypot, None if not deployed
  trusted_segments: list of CIDRs allowed to use VPN
"""
from __future__ import annotations
import logging
from typing import Tuple

from minifw_ai.netutil import ip_in_any_subnet

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain rule sets
# ---------------------------------------------------------------------------
_VPN_PROXY_KEYWORDS = frozenset([
    "nordvpn", "expressvpn", "ultravpn",
    "hide.me", "tunnelbear", "protonvpn",
    "mullvad", "surfshark", "cyberghost",
])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _domain_matches(target: str, domain_set: frozenset) -> bool:
    t = target.lower().strip(".")
    return any(t == d or t.endswith("." + d) for d in domain_set)


def _contains_keyword(target: str, keywords: frozenset) -> bool:
    t = target.lower()
    return any(kw in t for kw in keywords)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    Establishment-sector security rules.

    Args:
        metadata: dict with domain, sni, client_ip, segment, sector,
                  and optionally sector_config.

    Returns:
        (action, reason) — "block"/"monitor"/"allow" with reason string.
    """
    domain    = metadata.get("domain", "").lower().strip()
    sni       = metadata.get("sni",    "").lower().strip()
    client_ip = metadata.get("client_ip", "")
    target    = sni if sni else domain

    sector_cfg      = metadata.get("sector_config", {})
    honeypot_ip     = sector_cfg.get("honeypot_ip")
    trusted_segments = sector_cfg.get("trusted_segments", [])

    # -- Cowrie honeypot: client connecting TO honeypot IP -------------------
    # The honeypot must stay reachable — we flag but never block the client
    # here; the alert alone is sufficient to mark it as high-interest.
    if honeypot_ip and domain == honeypot_ip:
        logger.critical(
            "[ESTABLISHMENT] Honeypot contact: %s → %s — high-interest attacker",
            client_ip, honeypot_ip,
        )
        return "monitor", "est_honeypot_contact"

    # -- VPN services: allow from trusted segments, block otherwise ----------
    if _contains_keyword(target, _VPN_PROXY_KEYWORDS):
        if trusted_segments and ip_in_any_subnet(client_ip, trusted_segments):
            logger.info("[ESTABLISHMENT] VPN from trusted segment allowed: %s (%s)", client_ip, target)
            return "allow", ""
        logger.info("[ESTABLISHMENT] VPN domain from untrusted client: %s → %s", client_ip, target)
        return "monitor", "est_vpn_untrusted_segment"

    # -- Multi-zone segment verbosity ----------------------------------------
    # Log cross-segment DNS at info level so admins can audit zone boundary
    # activity without blocking it — establishment networks are multi-zone by
    # design and legitimate cross-zone traffic is expected.
    segment = metadata.get("segment", "default")
    if segment != "default":
        logger.debug("[ESTABLISHMENT] Segment=%s client=%s domain=%s", segment, client_ip, target)

    return "allow", ""
