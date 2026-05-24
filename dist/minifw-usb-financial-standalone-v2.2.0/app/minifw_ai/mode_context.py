"""
Mode UI Context

Provides display metadata for each PRODUCT_MODE so the dashboard can render
a consistent mode label, color, and icon across all templates — server-side,
without a round-trip JS fetch.

Called once at app startup and injected as a Jinja2 global.
"""

from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ModeUI:
    product_mode: str    # e.g. "minifw_hospital"
    label: str           # e.g. "Hospital"
    sublabel: str        # e.g. "HIPAA · IoMT · Healthcare"
    color: str           # CSS hex accent color
    bg: str              # light background for badges
    css_class: str       # body class for per-mode theming
    icon: str            # Bootstrap Icons class
    sector: str          # raw sector string (empty for non-MiniFW modes)


_MODE_UI: dict[str, ModeUI] = {
    "minifw_hospital": ModeUI(
        product_mode="minifw_hospital",
        label="Hospital",
        sublabel="HIPAA · IoMT · Healthcare",
        color="#ef4444",
        bg="rgba(239,68,68,0.10)",
        css_class="mode-hospital",
        icon="bi-hospital",
        sector="hospital",
    ),
    "minifw_school": ModeUI(
        product_mode="minifw_school",
        label="School",
        sublabel="SafeSearch · Content Filtering",
        color="#06b6d4",
        bg="rgba(6,182,212,0.10)",
        css_class="mode-school",
        icon="bi-book",
        sector="education",
    ),
    "minifw_financial": ModeUI(
        product_mode="minifw_financial",
        label="Financial",
        sublabel="PCI-DSS · Tor Blocking · Strict TLS",
        color="#10b981",
        bg="rgba(16,185,129,0.10)",
        css_class="mode-financial",
        icon="bi-bank",
        sector="finance",
    ),
    "minifw_establishment": ModeUI(
        product_mode="minifw_establishment",
        label="SME",
        sublabel="Establishment · Balanced Protection",
        color="#3b82f6",
        bg="rgba(59,130,246,0.10)",
        css_class="mode-sme",
        icon="bi-building",
        sector="establishment",
    ),
    "minifw_gambling": ModeUI(
        product_mode="minifw_gambling",
        label="Gambling",
        sublabel="Regulatory Enforcement · Domain Blocking",
        color="#8b5cf6",
        bg="rgba(139,92,246,0.10)",
        css_class="mode-gambling",
        icon="bi-shield-exclamation",
        sector="establishment",
    ),
    "minifw_legal": ModeUI(
        product_mode="minifw_legal",
        label="Legal",
        sublabel="Attorney-Client Privilege · Data Exfiltration · Ransomware",
        color="#b45309",
        bg="rgba(180,83,9,0.10)",
        css_class="mode-legal",
        icon="bi-briefcase",
        sector="legal",
    ),
    "minifw_government": ModeUI(
        product_mode="minifw_government",
        label="Government",
        sublabel="Sovereign Infrastructure · APT Detection · Full Traceability",
        color="#6366f1",
        bg="rgba(99,102,241,0.10)",
        css_class="mode-government",
        icon="bi-shield-fill-check",
        sector="government",
    ),
    "ritapi_advanced": ModeUI(
        product_mode="ritapi_advanced",
        label="API Protection",
        sublabel="Edge WAF · L7 · Bot Detection",
        color="#4f46e5",
        bg="rgba(79,70,229,0.10)",
        css_class="mode-api",
        icon="bi-layers",
        sector="",
    ),
    "ritapi_v_sentinel": ModeUI(
        product_mode="ritapi_v_sentinel",
        label="V-Sentinel",
        sublabel="Unified Platform · Django · MiniFW",
        color="#64748b",
        bg="rgba(100,116,139,0.10)",
        css_class="mode-vsentinel",
        icon="bi-shield-fill",
        sector="",
    ),
}

# Fallback for unknown / unconfigured deployments
_UNKNOWN = ModeUI(
    product_mode="",
    label="Unknown",
    sublabel="Mode not configured",
    color="#94a3b8",
    bg="rgba(148,163,184,0.10)",
    css_class="mode-unknown",
    icon="bi-question-circle",
    sector="",
)

# Sector-value → mode UI (used when PRODUCT_MODE is absent but MINIFW_SECTOR is set)
_SECTOR_TO_MODE: dict[str, str] = {
    "hospital":      "minifw_hospital",
    "education":     "minifw_school",
    "finance":       "minifw_financial",
    "establishment": "minifw_establishment",
    "government":    "minifw_government",
    "legal":         "minifw_legal",
}


def get_mode_ui() -> ModeUI:
    """
    Return the ModeUI for the current deployment.

    Resolution order:
      1. PRODUCT_MODE env var (canonical)
      2. MINIFW_SECTOR env var (legacy / backward compat)
      3. Unknown fallback
    """
    pm = os.environ.get("PRODUCT_MODE", "").strip().lower()
    if pm and pm in _MODE_UI:
        return _MODE_UI[pm]

    sector = os.environ.get("MINIFW_SECTOR", "").strip().lower()
    if sector:
        mapped = _SECTOR_TO_MODE.get(sector)
        if mapped and mapped in _MODE_UI:
            return _MODE_UI[mapped]

    return _UNKNOWN
