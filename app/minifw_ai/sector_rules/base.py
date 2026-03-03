"""
Sector Rules - Base Module

Security rules that apply to ALL sectors before sector-specific evaluation.
Operates at DNS/SNI level — no HTTP inspection required.

Ported from legacy education engine.py (evaluate_general + supply_chain_guard).
Rules requiring HTTP-layer data (file extensions in URL, bandwidth bytes,
user-agent, content-length) are noted as stubs — they activate when the
engine gains an HTTP inspection collector.
"""
from __future__ import annotations
import math
import time
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-destination DDoS counters (complementary to burst.py which tracks
# total DNS rate per client; this tracks per client→domain pair)
# ---------------------------------------------------------------------------
_ddos_counters: dict[str, int] = {}
_ddos_timestamps: dict[str, float] = {}
_DDOS_RESET_INTERVAL = 60        # seconds
_DDOS_QUERY_THRESHOLD = 100      # queries per interval before block

def _reset_ddos_if_needed(key: str) -> None:
    now = time.monotonic()
    if now - _ddos_timestamps.get(key, 0) > _DDOS_RESET_INTERVAL:
        _ddos_counters[key] = 0
        _ddos_timestamps[key] = now

def _ddos_increment(key: str) -> int:
    _reset_ddos_if_needed(key)
    _ddos_counters[key] = _ddos_counters.get(key, 0) + 1
    return _ddos_counters[key]


# ---------------------------------------------------------------------------
# Domain/SNI rule sets
# ---------------------------------------------------------------------------
_CLOUD_SYNC_DOMAINS = frozenset([
    "dropbox.com", "drive.google.com", "onedrive.live.com",
    "box.com", "sync.com", "mega.nz",
])

_CHAT_APP_DOMAINS = frozenset([
    "web.whatsapp.com", "web.telegram.org", "discord.com",
    "messenger.com", "teams.microsoft.com",
])

_SENSITIVE_API_DOMAINS = frozenset([
    "api.stripe.com", "api.paypal.com", "api.quickbooks.com",
    "api.braintreegateway.com",
])

# VPN detection is intentionally NOT in base — VPN policy is sector-specific:
#   education:     always block (education.py)
#   establishment: allow from trusted segments, monitor otherwise (establishment.py)
#   hospital:      not restricted (clinical VPN is expected)
# If a future sector needs VPN monitoring add it in that sector's module.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _domain_matches(target: str, domain_set: frozenset) -> bool:
    """True if target is an exact match or subdomain of any entry in the set."""
    t = target.lower().strip(".")
    return any(t == d or t.endswith("." + d) for d in domain_set)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. Used for DGA/C2 domain detection."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _is_ip_address(s: str) -> bool:
    """Rough check — true if s looks like an IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    General security rules for all sectors.

    Evaluated after FeedMatcher/BurstTracker/MLP/YARA, before score_and_decide().
    Returns (action, reason) — action is "block", "monitor", or "allow".
    """
    domain    = metadata.get("domain", "").lower().strip()
    sni       = metadata.get("sni",    "").lower().strip()
    client_ip = metadata.get("client_ip", "")

    # Prefer SNI (post-TLS handshake hostname) over queried domain
    target = sni if sni else domain

    # -- Per-destination DDoS ------------------------------------------------
    # Catches one client hammering a single destination; burst.py handles
    # total DNS volume per client across all destinations.
    key = f"{client_ip}->{target}"
    count = _ddos_increment(key)
    if count > _DDOS_QUERY_THRESHOLD:
        logger.warning("[BASE] DDoS per-dest: %s → %s (%d queries/60s)", client_ip, target, count)
        return "block", "base_ddos_per_dest"

    # -- High-entropy domain (DGA / C2 beacon detection) --------------------
    # Threshold 4.0 is calibrated for domain labels (not full URLs).
    # Normal domains score 2.5–3.5; DGA-generated domains score 3.8–4.5+.
    # Entropy is computed on the leftmost label (most discriminative for DGA).
    # Threshold 3.5 is calibrated for domain labels — URLs would use ~7.5.
    # Require minimum length 12 to avoid flagging short legitimate domains.
    label = domain.split(".")[0]
    ent = _shannon_entropy(label)
    if len(label) >= 12 and ent > 3.5:
        logger.info("[BASE] High-entropy domain label: %s (entropy=%.2f)", domain, ent)
        return "monitor", "base_high_entropy_domain"

    # -- Unauthorized cloud sync ---------------------------------------------
    if _domain_matches(target, _CLOUD_SYNC_DOMAINS):
        logger.info("[BASE] Cloud sync domain: %s", target)
        return "monitor", "base_cloud_sync"

    # -- Chat applications ---------------------------------------------------
    if _domain_matches(target, _CHAT_APP_DOMAINS):
        logger.info("[BASE] Chat app domain: %s", target)
        return "monitor", "base_chat_app"

    # -- Sensitive payment/finance API without TLS ---------------------------
    if _domain_matches(target, _SENSITIVE_API_DOMAINS):
        is_tls = metadata.get("is_tls", True)   # assume TLS when unknown
        if not is_tls:
            logger.warning("[BASE] Sensitive API over non-TLS: %s", target)
            return "block", "base_sensitive_api_no_tls"

    # -- HTTP-layer stubs (activate when HTTP inspection collector is added) -
    # [ ] Dangerous file extensions in URL (.exe .msi .bat .dll .apk .jar)
    # [ ] Untrusted archive downloads (.zip .rar .iso from non-CDN sources)
    # [ ] Login form over plaintext HTTP
    # [ ] Bandwidth quota enforcement (requires flow byte tracking)
    # [ ] IoT device user-agent detection (requires HTTP User-Agent header)
    # [ ] API token reuse across multiple IPs (requires HTTP header tracking)

    return "allow", ""


def supply_chain_guard(metadata: dict) -> Tuple[str, str]:
    """
    Supply chain and VPN heuristic detection for all sectors.

    Returns (action, reason).
    """
    domain    = metadata.get("domain", "").lower().strip()
    sni       = metadata.get("sni",    "").lower().strip()
    target    = sni if sni else domain

    # -- VPN heuristic: direct-to-IP TLS with no SNI ------------------------
    # When Zeek is active, a missing SNI + IP-only domain resolution is a
    # strong indicator of a VPN or proxy protocol bypassing name resolution.
    if not sni and domain and _is_ip_address(domain):
        logger.info("[BASE] VPN heuristic: direct-to-IP with no SNI (%s)", domain)
        return "monitor", "base_vpn_heuristic_no_sni"

    # -- HTTP-layer stubs ----------------------------------------------------
    # [ ] Large POST (>5 MB) to untrusted IP (requires HTTP content-length)
    # [ ] Sensitive API over non-TLS (partial check in evaluate() above)
    # [ ] API token reuse across IPs (requires HTTP header tracking)

    return "allow", ""
