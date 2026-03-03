"""
Sector Rules - Legal Module

Rules for law firm / legal sector deployments.

Focus areas (all operable at DNS/SNI level):
  - DNS exfiltration heuristic: abnormally long domain labels (> 50 chars) or
    very deep subdomain chains (> 6 labels) indicate DNS tunnelling used to
    exfiltrate privileged case files or client data without triggering DLP.
  - Unsanctioned file sharing: consumer file-sharing services that could be
    used to leak confidential case documents → monitor (stricter than base).
  - Paste/leak site detection: domains associated with public paste/data leak
    services → block (confidentiality mode).

HTTP-layer stubs (activate when HTTP inspection collector is added):
  [ ] Large upload (> large_upload_threshold_mb) to untrusted destination → block
  [ ] Document file extensions (.pdf, .docx, .xlsx) to external hosts → monitor
  [ ] Client matter number patterns in URL query strings → redact + alert

Tunables from sector_config.py (SectorType.LEGAL):
  data_exfiltration_watch:   enable DNS exfiltration heuristics
  large_upload_threshold_mb: HTTP-layer threshold (stub until HTTP collector)
  confidentiality_mode:      enable paste-site blocking
"""
from __future__ import annotations
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domain rule sets
# ---------------------------------------------------------------------------

# Consumer file-sharing services — monitored (not blocked) since some may have
# legitimate uses (opposing counsel sharing discovery files, etc.)
_FILE_SHARING_DOMAINS = frozenset([
    "wetransfer.com", "send.firefox.com",
    "filemail.com", "sendspace.com",
    "zippyshare.com", "gofile.io",
    "anonfiles.com", "file.io",
])

# Paste / data leak sites — blocked in confidentiality mode.
# These are frequent exfiltration destinations for insider threats.
_PASTE_LEAK_DOMAINS = frozenset([
    "pastebin.com", "paste.ee", "paste.org",
    "hastebin.com", "ghostbin.com", "controlc.com",
    "rentry.co", "dpaste.com",
    "privatebin.net", "zeropaste.com",
])

# DNS exfiltration thresholds
_DNS_EXFIL_LABEL_LEN  = 50   # max chars in a single label before flagging
_DNS_EXFIL_DEPTH      = 6    # max subdomain levels before flagging


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _domain_matches(target: str, domain_set: frozenset) -> bool:
    t = target.lower().strip(".")
    return any(t == d or t.endswith("." + d) for d in domain_set)


def _max_label_length(domain: str) -> int:
    """Return the length of the longest label in the domain."""
    labels = domain.rstrip(".").split(".")
    return max((len(l) for l in labels), default=0)


def _subdomain_depth(domain: str) -> int:
    return len(domain.rstrip(".").split("."))


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def evaluate(metadata: dict) -> Tuple[str, str]:
    """
    Legal-sector security rules.

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

    sector_cfg    = metadata.get("sector_config", {})
    exfil_watch   = sector_cfg.get("data_exfiltration_watch", True)
    confidential  = sector_cfg.get("confidentiality_mode", True)

    # -- DNS exfiltration heuristics -----------------------------------------
    # DNS tunnelling tools encode binary data into subdomain labels, producing
    # labels far longer than any legitimate hostname would use.
    if exfil_watch:
        max_len = _max_label_length(domain)
        depth   = _subdomain_depth(domain)

        if max_len > _DNS_EXFIL_LABEL_LEN:
            logger.warning(
                "[LEGAL] DNS exfil heuristic — long label: %s (max_label=%d) client=%s",
                domain, max_len, client_ip,
            )
            return "monitor", "legal_dns_exfil_long_label"

        if depth > _DNS_EXFIL_DEPTH:
            logger.warning(
                "[LEGAL] DNS exfil heuristic — deep chain: %s (%d labels) client=%s",
                domain, depth, client_ip,
            )
            return "monitor", "legal_dns_exfil_deep_chain"

    # -- Paste / data leak sites ---------------------------------------------
    if confidential and _domain_matches(target, _PASTE_LEAK_DOMAINS):
        logger.warning("[LEGAL] Paste/leak site blocked: %s client=%s", target, client_ip)
        return "block", "legal_paste_site"

    # -- Unsanctioned file sharing -------------------------------------------
    # Monitor rather than block — legal workflows may legitimately use these.
    if _domain_matches(target, _FILE_SHARING_DOMAINS):
        logger.info("[LEGAL] File-sharing domain: %s client=%s", target, client_ip)
        return "monitor", "legal_file_sharing"

    # -- HTTP-layer stubs ----------------------------------------------------
    # [ ] Large upload > large_upload_threshold_mb to external host → block
    # [ ] Document extensions in URL path (.pdf/.docx/.xlsx) → monitor + alert
    # [ ] Client matter numbers in URL query strings → redact + alert

    return "allow", ""
