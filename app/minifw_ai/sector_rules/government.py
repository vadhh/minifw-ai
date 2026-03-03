"""
Sector Rules - Government Module

Rules for government/public-sector deployments.

Focus areas (all operable at DNS/SNI level):
  - Geo-IP TLD blocking: domains in blocked country-code TLDs (.kp, .ir, .ru, .cn)
    are blocked when geo_ip_strict is enabled. TLD matching is a best-effort
    heuristic — actual Geo-IP DB lookup belongs in the HTTP inspection layer.
  - APT/C2 indicator: deep subdomain chains (> 4 labels) indicate DNS tunnelling
    used by APT groups for command-and-control beaconing.
  - Audit verbosity: when audit_all_queries is set, every request is logged at
    INFO level for the 365-day retention requirement.

Tunables from sector_config.py (SectorType.GOVERNMENT):
  blocked_countries:    list of ISO-3166-1 alpha-2 codes (["KP","IR","RU","CN"])
  geo_ip_strict:        block (not just monitor) on TLD match
  apt_detection_mode:   enable deep-subdomain APT heuristic
  audit_all_queries:    emit INFO log for every query
"""
from __future__ import annotations
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Country-code TLD → ISO-3166-1 alpha-2 map (subset covering blocked defaults)
# Extend as more countries are added to blocked_countries in sector_config.
# ---------------------------------------------------------------------------
_CCTLD_MAP: dict[str, str] = {
    "kp": "KP",  # North Korea
    "ir": "IR",  # Iran
    "ru": "RU",  # Russia
    "cn": "CN",  # China
    "by": "BY",  # Belarus
    "sy": "SY",  # Syria
    "cu": "CU",  # Cuba
    "ve": "VE",  # Venezuela
}

# Domains that are exceptions to TLD blocking (well-known legitimate services
# that use .ru / .cn TLDs but are not nation-state threats).
_TLD_BLOCK_EXCEPTIONS = frozenset([
    "mail.ru",         # Common personal email; block is policy decision
    "yandex.ru",       # Search/services
])

# Deep-subdomain threshold — more than this many labels = suspicious C2 tunnel
_APT_SUBDOMAIN_DEPTH = 4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_tld(domain: str) -> str:
    """Return the rightmost label of a domain (the TLD)."""
    parts = domain.rstrip(".").split(".")
    return parts[-1] if parts else ""


def _subdomain_depth(domain: str) -> int:
    """Number of labels in a domain (e.g. a.b.c.d.example.com = 6)."""
    return len(domain.rstrip(".").split("."))


def _domain_in_exceptions(target: str, exceptions: frozenset) -> bool:
    t = target.lower().strip(".")
    return any(t == e or t.endswith("." + e) for e in exceptions)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    Government-sector security rules.

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

    sector_cfg        = metadata.get("sector_config", {})
    blocked_countries = sector_cfg.get("blocked_countries", ["KP", "IR", "RU", "CN"])
    geo_ip_strict     = sector_cfg.get("geo_ip_strict", True)
    apt_detection     = sector_cfg.get("apt_detection_mode", True)
    audit_all         = sector_cfg.get("audit_all_queries", True)

    # -- Audit all queries (365-day retention requirement) -------------------
    if audit_all:
        logger.info("[GOVERNMENT] AUDIT client=%s domain=%s sni=%s", client_ip, domain, sni)

    # -- Geo-IP TLD blocking -------------------------------------------------
    # Map blocked_countries → expected ccTLDs and compare against domain TLD.
    # This is a DNS-layer heuristic; real GeoIP lookup requires an IP→country DB.
    tld = _get_tld(target)
    country_for_tld = _CCTLD_MAP.get(tld)
    if country_for_tld and country_for_tld in blocked_countries:
        if _domain_in_exceptions(target, _TLD_BLOCK_EXCEPTIONS):
            logger.info("[GOVERNMENT] Blocked-country TLD exception allowed: %s", target)
        elif geo_ip_strict:
            logger.warning("[GOVERNMENT] Geo-IP TLD block (%s): %s", country_for_tld, target)
            return "block", "gov_geo_ip_tld_block"
        else:
            logger.info("[GOVERNMENT] Geo-IP TLD monitor (%s): %s", country_for_tld, target)
            return "monitor", "gov_geo_ip_tld_monitor"

    # -- APT deep-subdomain C2 heuristic -------------------------------------
    # Legitimate domains rarely exceed 4–5 labels. APT DNS tunnelling tools
    # (e.g. dnscat2, iodine) encode payloads in long subdomain chains such as
    # <encoded_data>.stage2.<c2>.example.com — often 6–10+ labels deep.
    if apt_detection and _subdomain_depth(target) > _APT_SUBDOMAIN_DEPTH:
        logger.info(
            "[GOVERNMENT] APT deep-subdomain heuristic: %s (%d labels)",
            target, _subdomain_depth(target),
        )
        return "monitor", "gov_apt_deep_subdomain"

    return "allow", ""
