"""
Sector Rules - Finance Module

Rules for finance/banking/PCI-DSS deployments.

Focus areas (all operable at DNS/SNI level):
  - Tor hidden services: domains ending in .onion → block (fraud/money laundering)
  - Anonymizer/proxy services: keyword-matched → block (bypasses audit trail)
  - Cryptocurrency phishing: fake exchange/wallet domains → block
  - Non-TLS for payment processors: expanded sensitive domain set without TLS → block
    (complements base.py's _SENSITIVE_API_DOMAINS with a broader finance list)

Tunables from sector_config.py (SectorType.FINANCE):
  block_tor:           block .onion and Tor keyword domains
  block_anonymizers:   block known anonymizer/proxy services
  strict_tls:          block finance-domain queries over non-TLS
"""
from __future__ import annotations
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain / keyword rule sets
# ---------------------------------------------------------------------------

# Tor relay and anonymizer keywords — block outright in finance environments.
# Any bypass of the audit trail is a PCI-DSS violation risk.
_TOR_ANONYMIZER_KEYWORDS = frozenset([
    "torproject", ".onion",
    "i2p.net", "freenet",
    "zeronet",
])

_ANONYMIZER_KEYWORDS = frozenset([
    "anonymizer", "hidemyass", "hide-my-ip",
    "freeproxy", "proxyfree", "kproxy",
    "whoer.net", "vpnbook",
])

# Cryptocurrency exchange phishing patterns — fake domains impersonating
# major exchanges. Keyword-based to catch typosquats (e.g. bìnance.com).
_CRYPTO_PHISHING_KEYWORDS = frozenset([
    "binance-login", "binance-secure", "binance-verify",
    "coinbase-login", "coinbase-secure", "coinbase-verify",
    "kraken-login", "kraken-secure",
    "metamask-login", "metamask-secure", "metamask-connect",
    "ledger-live-login", "trezor-suite-login",
    "blockchain-wallet-login", "blockchain-secure",
    "crypto-airdrop", "nft-airdrop", "wallet-airdrop",
    "defi-claim", "token-claim", "free-crypto",
])

# Finance-sector sensitive domains: expanded set beyond base.py's payment APIs.
# These are blocked over non-TLS (complements base.py rule, not duplicates it).
_FINANCE_SENSITIVE_DOMAINS = frozenset([
    # Card networks
    "api.visa.com", "api.mastercard.com", "api.americanexpress.com",
    # Banking APIs
    "api.plaid.com", "api.yodlee.com", "api.finicity.com",
    # Crypto exchanges (legitimate — non-TLS access is suspicious)
    "api.binance.com", "api.coinbase.com", "api.kraken.com",
    "api.crypto.com", "api.gemini.com",
])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _contains_keyword(target: str, keywords: frozenset) -> bool:
    t = target.lower()
    return any(kw in t for kw in keywords)


def _domain_matches(target: str, domain_set: frozenset) -> bool:
    t = target.lower().strip(".")
    return any(t == d or t.endswith("." + d) for d in domain_set)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    Finance-sector security rules.

    Args:
        metadata: dict with domain, sni, client_ip, segment, sector,
                  and optionally sector_config, is_tls.

    Returns:
        (action, reason) — "block"/"monitor"/"allow" with reason string.
    """
    domain    = metadata.get("domain", "").lower().strip()
    sni       = metadata.get("sni",    "").lower().strip()
    client_ip = metadata.get("client_ip", "")
    target    = sni if sni else domain

    sector_cfg       = metadata.get("sector_config", {})
    block_tor        = sector_cfg.get("block_tor", True)
    block_anonymizers = sector_cfg.get("block_anonymizers", True)
    strict_tls       = sector_cfg.get("strict_tls", True)
    is_tls           = metadata.get("is_tls", True)  # assume TLS when unknown

    # -- Tor hidden services / Tor project domains ---------------------------
    if block_tor:
        if domain.endswith(".onion") or sni.endswith(".onion"):
            logger.warning("[FINANCE] Tor hidden service: %s", target)
            return "block", "fin_tor_hidden_service"
        if _contains_keyword(target, _TOR_ANONYMIZER_KEYWORDS):
            logger.warning("[FINANCE] Tor-related domain: %s", target)
            return "block", "fin_tor_domain"

    # -- Anonymizer/proxy services -------------------------------------------
    if block_anonymizers and _contains_keyword(target, _ANONYMIZER_KEYWORDS):
        logger.warning("[FINANCE] Anonymizer service: %s", target)
        return "block", "fin_anonymizer"

    # -- Cryptocurrency phishing ---------------------------------------------
    if _contains_keyword(target, _CRYPTO_PHISHING_KEYWORDS):
        logger.warning("[FINANCE] Crypto phishing pattern: %s client=%s", target, client_ip)
        return "block", "fin_crypto_phishing"

    # -- Finance-sensitive APIs over non-TLS ---------------------------------
    # base.py already covers Stripe/PayPal; this covers the broader finance set.
    if strict_tls and not is_tls and _domain_matches(target, _FINANCE_SENSITIVE_DOMAINS):
        logger.warning("[FINANCE] Sensitive finance API over non-TLS: %s", target)
        return "block", "fin_sensitive_api_no_tls"

    return "allow", ""
