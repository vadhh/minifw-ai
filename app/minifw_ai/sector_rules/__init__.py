"""
Sector Rules Package

Provides per-sector security rule modules loaded after the core pipeline
(FeedMatcher → BurstTracker → MLP → YARA) but before score_and_decide().

Each sector module must implement:
    evaluate(metadata: dict) -> tuple[str, str]
        Returns (action, reason) where action is "block", "monitor", or "allow".

Modules may optionally implement:
    post_decision(client_ip, domain, score, thr, sector_config, reasons) -> None
        Called after score_and_decide() for side-effects (e.g. IoMT alerting).

metadata dict keys guaranteed to be present:
    domain      str  - DNS queried domain
    sni         str  - TLS SNI from Zeek, empty string if unavailable
    client_ip   str  - querying client IP
    segment     str  - network segment (student/staff/admin/default)
    sector      str  - active sector name
"""
from __future__ import annotations
from typing import Optional, Any


def get_sector_module(sector_name: str) -> Optional[Any]:
    """Return the sector-specific rules module, or None if not yet implemented."""
    try:
        if sector_name == "hospital":
            from . import hospital
            return hospital
        if sector_name == "education":
            from . import education
            return education
        if sector_name == "establishment":
            from . import establishment
            return establishment
        if sector_name == "government":
            from . import government
            return government
        if sector_name == "finance":
            from . import finance
            return finance
        if sector_name == "legal":
            from . import legal
            return legal
    except ImportError:
        pass
    return None
