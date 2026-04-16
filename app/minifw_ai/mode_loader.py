"""
Product Mode Loader

Single source of truth for PRODUCT_MODE → sector + config path resolution.

Valid modes:
    ritapi_advanced      — RitAPI Advanced edge WAF (no MiniFW sector)
    ritapi_v_sentinel    — RITAPI V-Sentinel Django + MiniFW platform (no standalone sector)
    minifw_hospital      — MiniFW-AI: healthcare / HIPAA (sector: hospital)
    minifw_school        — MiniFW-AI: education / SafeSearch (sector: education)
    minifw_financial     — MiniFW-AI: finance / PCI-DSS (sector: finance)
    minifw_establishment — MiniFW-AI: SME / balanced defaults (sector: establishment)

Priority in sector_lock.py:
    0. PRODUCT_MODE (this module)     ← canonical
    1. MINIFW_SECTOR                  ← backward-compatible
    2. sector_lock.json               ← production hardware lock
"""

from __future__ import annotations
import os
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mode registry
# ---------------------------------------------------------------------------

# Maps PRODUCT_MODE → MiniFW sector value (None = not a MiniFW mode)
_MODE_TO_SECTOR: dict[str, Optional[str]] = {
    "ritapi_advanced":      None,
    "ritapi_v_sentinel":    None,
    "minifw_hospital":      "hospital",
    "minifw_school":        "education",
    "minifw_financial":     "finance",
    "minifw_establishment": "establishment",
    "minifw_gambling":      "establishment",   # establishment sector + GAMBLING_ONLY=1
}

# All modes that drive MiniFW sector selection
MINIFW_MODES: frozenset[str] = frozenset(
    k for k, v in _MODE_TO_SECTOR.items() if v is not None
)

ALL_MODES: frozenset[str] = frozenset(_MODE_TO_SECTOR.keys())

# Base path for mode-specific config files (resolved relative to this file's
# location: app/minifw_ai/ → ../../config/modes/)
_MODES_CONFIG_BASE = (
    Path(__file__).parent.parent.parent / "config" / "modes"
)

# Production install base
_PROD_MODES_CONFIG_BASE = Path("/opt/minifw_ai/config/modes")


@dataclass(frozen=True)
class ModeConfig:
    """Resolved configuration for a PRODUCT_MODE value."""
    product_mode: str
    sector: Optional[str]          # None for non-MiniFW modes
    policy_path: Path              # Canonical policy.json for this mode
    yara_rules_dir: Path           # YARA rules directory
    description: str


def resolve_mode(product_mode: Optional[str] = None) -> Optional[ModeConfig]:
    """
    Resolve PRODUCT_MODE to a ModeConfig.

    Args:
        product_mode: Override value; reads PRODUCT_MODE env var if None.

    Returns:
        ModeConfig if PRODUCT_MODE is set and valid, None if PRODUCT_MODE is
        not set (so callers can fall back to MINIFW_SECTOR).

    Raises:
        ValueError: PRODUCT_MODE is set but not a recognised mode value.
    """
    raw = product_mode or os.environ.get("PRODUCT_MODE", "").strip().lower()
    if not raw:
        return None

    if raw not in _MODE_TO_SECTOR:
        raise ValueError(
            f"[MODE_LOADER] Invalid PRODUCT_MODE '{raw}'. "
            f"Valid values: {sorted(ALL_MODES)}"
        )

    sector = _MODE_TO_SECTOR[raw]

    # Resolve mode-specific config paths (production path takes priority)
    prod_policy = _PROD_MODES_CONFIG_BASE / raw / "policy.json"
    dev_policy  = _MODES_CONFIG_BASE / raw / "policy.json"
    policy_path = prod_policy if prod_policy.exists() else dev_policy

    prod_yara = Path("/opt/minifw_ai/yara_rules")
    dev_yara  = Path(__file__).parent.parent.parent / "yara_rules"
    yara_dir  = prod_yara if prod_yara.exists() else dev_yara

    # MINIFW_POLICY / MINIFW_YARA_RULES env vars override computed paths
    if env_policy := os.environ.get("MINIFW_POLICY"):
        policy_path = Path(env_policy)
    if env_yara := os.environ.get("MINIFW_YARA_RULES"):
        yara_dir = Path(env_yara)

    descriptions = {
        "ritapi_advanced":      "RitAPI Advanced — Layer-7 edge WAF",
        "ritapi_v_sentinel":    "RITAPI V-Sentinel — Django ops dashboard + MiniFW",
        "minifw_hospital":      "MiniFW-AI Hospital — HIPAA, IoMT priority, payload redaction",
        "minifw_school":        "MiniFW-AI School — SafeSearch, VPN/proxy blocking, content filtering",
        "minifw_financial":     "MiniFW-AI Financial — PCI-DSS, Tor blocking, strict TLS",
        "minifw_establishment": "MiniFW-AI Establishment — balanced defaults for SME/retail",
        "minifw_gambling":      "MiniFW-AI Gambling — regulatory domain enforcement (GAMBLING_ONLY=1)",
    }

    cfg = ModeConfig(
        product_mode=raw,
        sector=sector,
        policy_path=policy_path,
        yara_rules_dir=yara_dir,
        description=descriptions[raw],
    )
    logger.info(
        f"[MODE_LOADER] PRODUCT_MODE={raw} → sector={sector}, "
        f"policy={policy_path}"
    )
    return cfg


def resolve_sector_from_mode(product_mode: str) -> str:
    """
    Extract the MiniFW sector string from a PRODUCT_MODE value.

    Called by sector_lock.py (Priority 0) before checking MINIFW_SECTOR.

    Raises:
        ValueError: mode is not a MiniFW mode or is invalid.
    """
    pm = product_mode.strip().lower()
    if pm not in _MODE_TO_SECTOR:
        raise ValueError(
            f"[MODE_LOADER] Invalid PRODUCT_MODE '{pm}'. "
            f"Valid values: {sorted(ALL_MODES)}"
        )
    sector = _MODE_TO_SECTOR[pm]
    if sector is None:
        raise ValueError(
            f"[MODE_LOADER] PRODUCT_MODE '{pm}' is not a MiniFW mode "
            f"and cannot be used to configure a MiniFW sector. "
            f"MiniFW modes: {sorted(MINIFW_MODES)}"
        )
    return sector


def get_mode_config() -> Optional[ModeConfig]:
    """Convenience wrapper: resolve current PRODUCT_MODE from environment."""
    return resolve_mode()
