"""
Sector Rules - Education Module  (sector_lock: "education")

Rules specific to school/education deployments.
Ported from legacy education engine.py evaluate_education().

Class-hour windows and other tunables are read from sector_config.py
(SectorType.SCHOOL) so they can be adjusted without touching this file.
"""
from __future__ import annotations
import logging
import time
from datetime import datetime
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-destination DDoS counters — stricter during class hours (50 vs 100)
# Shared state within the process; reset every 60 s per key.
# ---------------------------------------------------------------------------
_ddos_counters: dict[str, int] = {}
_ddos_timestamps: dict[str, float] = {}
_DDOS_RESET_INTERVAL = 60

def _ddos_increment(key: str) -> int:
    now = time.monotonic()
    if now - _ddos_timestamps.get(key, 0) > _DDOS_RESET_INTERVAL:
        _ddos_counters[key] = 0
        _ddos_timestamps[key] = now
    _ddos_counters[key] = _ddos_counters.get(key, 0) + 1
    return _ddos_counters[key]


# ---------------------------------------------------------------------------
# Domain rule sets
# ---------------------------------------------------------------------------
_AI_TOOL_DOMAINS = frozenset([
    "chatgpt.com", "chat.openai.com", "openai.com",
    "bard.google.com", "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "copilot.microsoft.com",
    "you.com",
    "poe.com",
])

_VPN_PROXY_KEYWORDS = frozenset([
    "vpn", "proxy", "tunnel",
    "nordvpn", "expressvpn", "ultravpn",
    "hide.me", "tunnelbear", "protonvpn",
    "mullvad", "surfshark", "cyberghost",
])

_PIRACY_KEYWORDS = frozenset([
    ".torrent", "magnet:?", "crack", "keygen", "serial",
    "warez", "nulled", "piratebay", "thepiratebay",
    "1337x", "rarbg", "nyaa",
])

_ENTERTAINMENT_DOMAINS = frozenset([
    "youtube.com", "youtu.be",
    "tiktok.com",
    "twitch.tv",
    "roblox.com",
    "store.steampowered.com", "steamcommunity.com",
    "epicgames.com",
])

_CLOUD_SYNC_DOMAINS = frozenset([
    "dropbox.com", "drive.google.com",
    "onedrive.live.com", "box.com",
])

_ENTERTAINMENT_BANDWIDTH_CAP_MB = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _current_hhmm() -> int:
    """Current time as integer HHMM (e.g. 09:30 → 930)."""
    now = datetime.now()
    return now.hour * 100 + now.minute


def _in_class_hours(class_hours: list) -> bool:
    """
    True if current time falls within any configured class-hour window.

    Args:
        class_hours: list of [start_hhmm, end_hhmm] pairs from sector_config
    """
    now = _current_hhmm()
    return any(start <= now <= end for start, end in class_hours)


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
    School-sector security rules.

    Args:
        metadata: dict with domain, sni, client_ip, segment, sector,
                  and optionally bandwidth_usage_mb, sector_config.

    Returns:
        (action, reason) — "block"/"monitor"/"allow" with reason string.
    """
    domain    = metadata.get("domain", "").lower().strip()
    sni       = metadata.get("sni",    "").lower().strip()
    client_ip = metadata.get("client_ip", "")
    target    = sni if sni else domain

    # Read class hours from sector_config passed in metadata (or fall back to default)
    sector_cfg  = metadata.get("sector_config", {})
    class_hours = sector_cfg.get("class_hours", [[800, 1200], [1300, 1600]])
    in_class    = _in_class_hours(class_hours)

    # -- VPN / proxy / tunnel service ----------------------------------------
    if _contains_keyword(target, _VPN_PROXY_KEYWORDS):
        logger.info("[EDUCATION] VPN/proxy domain: %s", target)
        return "block", "edu_vpn_proxy"

    # -- AI tools during class hours -----------------------------------------
    if in_class and _domain_matches(target, _AI_TOOL_DOMAINS):
        logger.info("[EDUCATION] AI tool during class hours: %s", target)
        return "block", "edu_ai_tool_class_hours"

    # -- Piracy patterns in domain/URL ---------------------------------------
    if _contains_keyword(target, _PIRACY_KEYWORDS) or _contains_keyword(domain, _PIRACY_KEYWORDS):
        logger.info("[EDUCATION] Piracy pattern: %s", target)
        return "block", "edu_piracy"

    # -- Entertainment bandwidth abuse ---------------------------------------
    bw_mb = metadata.get("bandwidth_usage_mb", 0)
    if bw_mb > _ENTERTAINMENT_BANDWIDTH_CAP_MB and _domain_matches(target, _ENTERTAINMENT_DOMAINS):
        logger.info("[EDUCATION] Entertainment bandwidth cap exceeded: %s (%.0f MB)", target, bw_mb)
        return "block", "edu_entertainment_bw_cap"

    # -- Unauthorized cloud sync ---------------------------------------------
    if _domain_matches(target, _CLOUD_SYNC_DOMAINS):
        logger.info("[EDUCATION] Cloud sync domain: %s", target)
        return "monitor", "edu_cloud_sync"

    # -- Stricter DDoS during class hours (50 q/60s vs base.py's 100) -------
    if in_class:
        key   = f"{client_ip}->{target}"
        count = _ddos_increment(key)
        if count > 50:
            logger.warning("[EDUCATION] DDoS during class hours: %s → %s (%d q/60s)", client_ip, target, count)
            return "block", "edu_ddos_class_hours"

    return "allow", ""
