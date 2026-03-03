#!/usr/bin/env python3
"""
Sector Rules Pipeline Tests

Covers all rule modules loaded after YARA and before score_and_decide():
  base.py       — rules applying to every sector
  education.py  — school/university-specific rules
  establishment.py — enterprise/SME rules with Cowrie honeypot awareness
  hospital.py   — IoMT alerting (evaluate always allows)
  government.py — geo-IP TLD blocking and APT deep-subdomain heuristic
  finance.py    — Tor/anonymizer/crypto-phishing/PCI-DSS rules
  legal.py      — DNS exfiltration and confidentiality rules
  __init__.py   — get_sector_module() dispatcher

Usage:
    cd <project_root>
    PYTHONPATH=app pytest testing/test_sector_rules.py -v
"""
import sys
import types
from pathlib import Path

# Add app/ to path so bare `from minifw_ai.X import …` works.
# Also add project root so `from app.minifw_ai.X import …` works if needed.
_proj = Path(__file__).parent.parent
sys.path.insert(0, str(_proj / "app"))
sys.path.insert(0, str(_proj))

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _meta(
    domain="example.com",
    sni="",
    client_ip="10.0.0.1",
    segment="default",
    sector="hospital",
    sector_config=None,
    is_tls=True,
    bandwidth_usage_mb=0,
):
    """Return a minimal metadata dict suitable for any sector module."""
    return {
        "domain": domain,
        "sni": sni,
        "client_ip": client_ip,
        "segment": segment,
        "sector": sector,
        "sector_config": sector_config or {},
        "is_tls": is_tls,
        "bandwidth_usage_mb": bandwidth_usage_mb,
    }


# ---------------------------------------------------------------------------
# base.py
# ---------------------------------------------------------------------------
class TestBase:
    """Tests for sector_rules/base.py — universal rules for all sectors."""

    def setup_method(self):
        # Reset DDoS counters between tests to prevent state bleed.
        from minifw_ai.sector_rules import base
        base._ddos_counters.clear()
        base._ddos_timestamps.clear()

    def test_ddos_per_dest_triggers_block(self):
        """101 queries from the same IP to the same target → block."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="target.example.com", client_ip="10.1.0.1")
        action = reason = None
        for _ in range(101):
            action, reason = base.evaluate(meta)
        assert action == "block"
        assert reason == "base_ddos_per_dest"

    def test_ddos_per_dest_below_threshold_allows(self):
        """100 queries (at threshold, not above) should still allow."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="safe.example.com", client_ip="10.1.0.2")
        action = reason = None
        for _ in range(100):
            action, reason = base.evaluate(meta)
        assert action == "allow"

    def test_high_entropy_long_label_monitors(self):
        """A 16-char high-entropy first label (entropy > 3.5) → monitor."""
        from minifw_ai.sector_rules import base
        # "xk3r9mq2wz8eplvt" — long, high-entropy, looks like DGA output
        meta = _meta(domain="xk3r9mq2wz8eplvt.com", client_ip="10.1.0.3")
        action, reason = base.evaluate(meta)
        assert action == "monitor"
        assert reason == "base_high_entropy_domain"

    def test_short_label_not_flagged(self):
        """A label shorter than 12 chars is never flagged, even if high-entropy."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="xk3r9mq2.com", client_ip="10.1.0.4")  # 8 chars
        action, reason = base.evaluate(meta)
        assert action == "allow"

    def test_low_entropy_long_label_not_flagged(self):
        """A long but low-entropy first label (e.g. repeated chars) → allow."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="aaaaaaaaaaaaaaaa.com", client_ip="10.1.0.5")  # len=16, entropy~0
        action, reason = base.evaluate(meta)
        assert action == "allow"

    def test_cloud_sync_domain_monitors(self):
        """Known cloud sync domain → monitor."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="dropbox.com", client_ip="10.1.0.6")
        action, reason = base.evaluate(meta)
        assert action == "monitor"
        assert reason == "base_cloud_sync"

    def test_cloud_sync_subdomain_monitors(self):
        """Subdomain of cloud sync domain → monitor."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="files.dropbox.com", client_ip="10.1.0.7")
        action, reason = base.evaluate(meta)
        assert action == "monitor"
        assert reason == "base_cloud_sync"

    def test_chat_app_domain_monitors(self):
        """Known chat application domain → monitor."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="discord.com", client_ip="10.1.0.8")
        action, reason = base.evaluate(meta)
        assert action == "monitor"
        assert reason == "base_chat_app"

    def test_sensitive_api_no_tls_blocks(self):
        """Stripe API over non-TLS → block."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="api.stripe.com", client_ip="10.1.0.9", is_tls=False)
        action, reason = base.evaluate(meta)
        assert action == "block"
        assert reason == "base_sensitive_api_no_tls"

    def test_sensitive_api_with_tls_allows(self):
        """Stripe API over TLS (assumed default) → allow."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="api.stripe.com", client_ip="10.1.0.10", is_tls=True)
        action, reason = base.evaluate(meta)
        assert action == "allow"

    def test_normal_domain_allows(self):
        """Benign domain with no special characteristics → allow."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="bbc.co.uk", client_ip="10.1.0.11")
        action, reason = base.evaluate(meta)
        assert action == "allow"

    def test_supply_chain_vpn_heuristic_direct_ip_no_sni(self):
        """Direct IPv4 domain with no SNI → monitor (VPN heuristic)."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="1.2.3.4", sni="", client_ip="10.1.0.12")
        action, reason = base.supply_chain_guard(meta)
        assert action == "monitor"
        assert reason == "base_vpn_heuristic_no_sni"

    def test_supply_chain_domain_with_sni_allows(self):
        """Domain with a legitimate SNI → allow (not a VPN heuristic hit)."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="1.2.3.4", sni="example.com", client_ip="10.1.0.13")
        action, reason = base.supply_chain_guard(meta)
        assert action == "allow"

    def test_supply_chain_normal_domain_allows(self):
        """Normal FQDN with no SNI quirk → allow."""
        from minifw_ai.sector_rules import base
        meta = _meta(domain="example.com", sni="", client_ip="10.1.0.14")
        action, reason = base.supply_chain_guard(meta)
        assert action == "allow"

    def test_sni_takes_priority_over_domain(self):
        """When SNI is present it is used as target instead of domain."""
        from minifw_ai.sector_rules import base
        # domain would trigger cloud_sync, but SNI is a benign host
        meta = _meta(domain="dropbox.com", sni="internal.corp.example", client_ip="10.1.0.15")
        action, reason = base.evaluate(meta)
        # SNI "internal.corp.example" doesn't match any rule → allow
        assert action == "allow"


# ---------------------------------------------------------------------------
# education.py
# ---------------------------------------------------------------------------
class TestEducation:
    """Tests for sector_rules/education.py — school/university rules."""

    # class_hours=[0, 2359] → always in class; [] → never in class
    _IN_CLASS  = {"class_hours": [[0, 2359]]}
    _OUT_CLASS = {"class_hours": []}

    def setup_method(self):
        from minifw_ai.sector_rules import education
        education._ddos_counters.clear()
        education._ddos_timestamps.clear()

    def test_vpn_domain_blocks(self):
        """VPN keyword in domain → block regardless of class hours."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="nordvpn.com", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_vpn_proxy"

    def test_vpn_keyword_in_subdomain_blocks(self):
        """VPN keyword embedded in domain string → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="get.expressvpn.com", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_vpn_proxy"

    def test_ai_tool_during_class_hours_blocks(self):
        """AI tool domain during class hours → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="chat.openai.com", sector_config=self._IN_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_ai_tool_class_hours"

    def test_ai_tool_outside_class_hours_allows(self):
        """AI tool domain outside class hours → allow."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="claude.ai", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "allow"

    def test_piracy_keyword_blocks(self):
        """Piracy pattern in domain → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="1337x.to", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_piracy"

    def test_piracy_keyword_crack_blocks(self):
        """'crack' keyword in domain → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="crack-software-download.net", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_piracy"

    def test_entertainment_bw_cap_exceeded_blocks(self):
        """Entertainment domain with bandwidth > 500 MB → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(
            domain="youtube.com",
            bandwidth_usage_mb=501,
            sector_config=self._OUT_CLASS,
        )
        action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_entertainment_bw_cap"

    def test_entertainment_bw_under_cap_allows(self):
        """Entertainment domain with bandwidth ≤ 500 MB → allow."""
        from minifw_ai.sector_rules import education
        meta = _meta(
            domain="youtube.com",
            bandwidth_usage_mb=499,
            sector_config=self._OUT_CLASS,
        )
        action, reason = education.evaluate(meta)
        assert action == "allow"

    def test_cloud_sync_monitors(self):
        """Cloud sync domain → monitor (not block)."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="drive.google.com", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "monitor"
        assert reason == "edu_cloud_sync"

    def test_normal_domain_allows(self):
        """Benign domain → allow."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="khan-academy.org", sector_config=self._OUT_CLASS)
        action, reason = education.evaluate(meta)
        assert action == "allow"

    def test_ddos_during_class_hours_blocks_at_51(self):
        """51 queries from same IP to same domain during class hours → block."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="victim.edu", client_ip="10.2.0.1", sector_config=self._IN_CLASS)
        action = reason = None
        for _ in range(51):
            action, reason = education.evaluate(meta)
        assert action == "block"
        assert reason == "edu_ddos_class_hours"

    def test_ddos_outside_class_hours_not_triggered(self):
        """Same 51 queries outside class hours — education DDoS rule inactive."""
        from minifw_ai.sector_rules import education
        meta = _meta(domain="victim2.edu", client_ip="10.2.0.2", sector_config=self._OUT_CLASS)
        action = reason = None
        for _ in range(51):
            action, reason = education.evaluate(meta)
        assert action == "allow"


# ---------------------------------------------------------------------------
# establishment.py
# ---------------------------------------------------------------------------
class TestEstablishment:
    """Tests for sector_rules/establishment.py — enterprise/SME rules."""

    def test_honeypot_contact_monitors(self):
        """Client querying the honeypot IP → monitor + critical log."""
        from minifw_ai.sector_rules import establishment
        honeypot = "192.168.99.50"
        meta = _meta(
            domain=honeypot,
            client_ip="10.3.0.5",
            sector_config={"honeypot_ip": honeypot, "trusted_segments": []},
        )
        action, reason = establishment.evaluate(meta)
        assert action == "monitor"
        assert reason == "est_honeypot_contact"

    def test_vpn_from_trusted_segment_allows(self):
        """VPN domain from a client in a trusted CIDR → allow."""
        from minifw_ai.sector_rules import establishment
        meta = _meta(
            domain="nordvpn.com",
            client_ip="192.168.10.50",
            sector_config={
                "honeypot_ip": None,
                "trusted_segments": ["192.168.10.0/24"],
            },
        )
        action, reason = establishment.evaluate(meta)
        assert action == "allow"

    def test_vpn_from_untrusted_segment_monitors(self):
        """VPN domain from an untrusted client → monitor."""
        from minifw_ai.sector_rules import establishment
        meta = _meta(
            domain="mullvad.net",
            client_ip="10.99.0.1",
            sector_config={
                "honeypot_ip": None,
                "trusted_segments": ["192.168.10.0/24"],
            },
        )
        action, reason = establishment.evaluate(meta)
        assert action == "monitor"
        assert reason == "est_vpn_untrusted_segment"

    def test_vpn_no_trusted_segments_configured_monitors(self):
        """VPN domain when no trusted_segments configured → monitor."""
        from minifw_ai.sector_rules import establishment
        meta = _meta(
            domain="surfshark.com",
            client_ip="10.0.0.1",
            sector_config={"honeypot_ip": None, "trusted_segments": []},
        )
        action, reason = establishment.evaluate(meta)
        assert action == "monitor"
        assert reason == "est_vpn_untrusted_segment"

    def test_normal_domain_allows(self):
        """Benign domain → allow."""
        from minifw_ai.sector_rules import establishment
        meta = _meta(
            domain="intranet.corp.example",
            client_ip="10.3.0.1",
            sector_config={"honeypot_ip": None, "trusted_segments": []},
        )
        action, reason = establishment.evaluate(meta)
        assert action == "allow"

    def test_no_honeypot_configured_skips_check(self):
        """When honeypot_ip is None the honeypot check is skipped."""
        from minifw_ai.sector_rules import establishment
        meta = _meta(
            domain="192.168.99.50",  # same IP as above, but no honeypot configured
            client_ip="10.3.0.6",
            sector_config={"honeypot_ip": None, "trusted_segments": []},
        )
        action, reason = establishment.evaluate(meta)
        assert action == "allow"


# ---------------------------------------------------------------------------
# hospital.py
# ---------------------------------------------------------------------------
class TestHospital:
    """Tests for sector_rules/hospital.py — IoMT alerting."""

    def test_evaluate_always_allows(self):
        """hospital.evaluate() must always return allow for any domain."""
        from minifw_ai.sector_rules import hospital
        for domain in ["google.com", "192.168.1.1", "malware.ru", "ransomware.download"]:
            action, reason = hospital.evaluate(_meta(domain=domain))
            assert action == "allow", f"Expected allow for {domain}, got {action}"
            assert reason == ""

    def test_post_decision_fires_for_iomt_subnet(self):
        """IoMT alert fires when client_ip is in an IoMT subnet and score >= threshold."""
        from minifw_ai.sector_rules import hospital

        class _Thr:
            monitor_threshold = 40

        iomt_subnets = ["10.200.0.0/24"]
        reasons: list = []
        hospital.post_decision(
            client_ip="10.200.0.10",
            domain="suspicious.example.com",
            score=50,
            thr=_Thr(),
            iomt_subnets=iomt_subnets,
            reasons=reasons,
        )
        assert "iomt_device_alert" in reasons

    def test_post_decision_no_alert_below_threshold(self):
        """No IoMT alert when score is below monitor_threshold."""
        from minifw_ai.sector_rules import hospital

        class _Thr:
            monitor_threshold = 40

        reasons: list = []
        hospital.post_decision(
            client_ip="10.200.0.10",
            domain="example.com",
            score=30,
            thr=_Thr(),
            iomt_subnets=["10.200.0.0/24"],
            reasons=reasons,
        )
        assert "iomt_device_alert" not in reasons

    def test_post_decision_no_alert_outside_iomt_subnet(self):
        """No IoMT alert when client_ip is NOT in any IoMT subnet."""
        from minifw_ai.sector_rules import hospital

        class _Thr:
            monitor_threshold = 40

        reasons: list = []
        hospital.post_decision(
            client_ip="10.0.0.99",  # not in 10.200.0.0/24
            domain="example.com",
            score=80,
            thr=_Thr(),
            iomt_subnets=["10.200.0.0/24"],
            reasons=reasons,
        )
        assert "iomt_device_alert" not in reasons

    def test_post_decision_no_alert_empty_subnets(self):
        """No IoMT alert when iomt_subnets list is empty."""
        from minifw_ai.sector_rules import hospital

        class _Thr:
            monitor_threshold = 40

        reasons: list = []
        hospital.post_decision(
            client_ip="10.200.0.10",
            domain="example.com",
            score=80,
            thr=_Thr(),
            iomt_subnets=[],
            reasons=reasons,
        )
        assert "iomt_device_alert" not in reasons

    def test_post_decision_no_duplicate_reason(self):
        """post_decision does not duplicate 'iomt_device_alert' in reasons list."""
        from minifw_ai.sector_rules import hospital

        class _Thr:
            monitor_threshold = 40

        reasons: list = ["iomt_device_alert"]  # already present
        hospital.post_decision(
            client_ip="10.200.0.10",
            domain="example.com",
            score=80,
            thr=_Thr(),
            iomt_subnets=["10.200.0.0/24"],
            reasons=reasons,
        )
        assert reasons.count("iomt_device_alert") == 1


# ---------------------------------------------------------------------------
# government.py
# ---------------------------------------------------------------------------
class TestGovernment:
    """Tests for sector_rules/government.py — geo-IP TLD + APT heuristics."""

    _STRICT = {"geo_ip_strict": True,  "blocked_countries": ["KP","IR","RU","CN"], "apt_detection_mode": True,  "audit_all_queries": False}
    _LAX    = {"geo_ip_strict": False, "blocked_countries": ["KP","IR","RU","CN"], "apt_detection_mode": True,  "audit_all_queries": False}
    _NO_APT = {"geo_ip_strict": True,  "blocked_countries": ["KP","IR","RU","CN"], "apt_detection_mode": False, "audit_all_queries": False}

    def test_blocked_tld_strict_blocks(self):
        """A .ru domain with geo_ip_strict=True → block."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="kremlin.ru", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        assert action == "block"
        assert reason == "gov_geo_ip_tld_block"

    def test_blocked_tld_not_strict_monitors(self):
        """A .ru domain with geo_ip_strict=False → monitor (not block)."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="somesite.ru", sector_config=self._LAX)
        action, reason = government.evaluate(meta)
        assert action == "monitor"
        assert reason == "gov_geo_ip_tld_monitor"

    def test_blocked_tld_cn_blocks(self):
        """A .cn domain → block (strict mode)."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="example.cn", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        assert action == "block"

    def test_exception_domain_allowed(self):
        """yandex.ru is in the exception list → allow even in strict mode."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="yandex.ru", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        assert action == "allow"

    def test_apt_deep_subdomain_monitors(self):
        """Domain with > 4 labels → monitor (APT C2 heuristic)."""
        from minifw_ai.sector_rules import government
        # 6 labels: data.stage2.c2.example.com → depth 5+1=6
        meta = _meta(domain="data.stage2.c2.malware.example.com", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        # The TLD is .com → not blocked; APT heuristic fires
        assert action == "monitor"
        assert reason == "gov_apt_deep_subdomain"

    def test_apt_heuristic_disabled_allows_deep_domain(self):
        """With apt_detection_mode=False, deep subdomain chain → allow."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="data.stage2.c2.malware.example.com", sector_config=self._NO_APT)
        action, reason = government.evaluate(meta)
        assert action == "allow"

    def test_normal_domain_allows(self):
        """Benign .com domain with normal depth → allow."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="agency.gov", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        assert action == "allow"

    def test_four_label_domain_not_flagged(self):
        """Exactly 4 labels (≤ threshold) → allow."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="sub.agency.example.gov", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        # .gov not in blocked_countries ccTLD map; 4 labels not > 4
        assert action == "allow"

    def test_five_label_domain_flagged(self):
        """5 labels (> _APT_SUBDOMAIN_DEPTH of 4) → monitor."""
        from minifw_ai.sector_rules import government
        meta = _meta(domain="a.sub.agency.example.gov", sector_config=self._STRICT)
        action, reason = government.evaluate(meta)
        assert action == "monitor"
        assert reason == "gov_apt_deep_subdomain"


# ---------------------------------------------------------------------------
# finance.py
# ---------------------------------------------------------------------------
class TestFinance:
    """Tests for sector_rules/finance.py — Tor/anonymizer/phishing/PCI rules."""

    _CFG = {"block_tor": True, "block_anonymizers": True, "strict_tls": True}

    def test_onion_domain_blocks(self):
        """.onion domain → block (Tor hidden service)."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="abc123xyz.onion", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_tor_hidden_service"

    def test_tor_project_keyword_blocks(self):
        """Domain containing 'torproject' → block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="download.torproject.org", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_tor_domain"

    def test_anonymizer_keyword_blocks(self):
        """Domain containing anonymizer keyword → block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="hidemyass.com", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_anonymizer"

    def test_crypto_phishing_pattern_blocks(self):
        """Domain containing crypto phishing keyword → block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="binance-login.net", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_crypto_phishing"

    def test_metamask_phishing_blocks(self):
        """MetaMask phishing domain → block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="metamask-connect.io", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_crypto_phishing"

    def test_finance_api_no_tls_blocks(self):
        """Finance-sensitive API over non-TLS → block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="api.visa.com", is_tls=False, sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_sensitive_api_no_tls"

    def test_finance_api_with_tls_allows(self):
        """Finance-sensitive API over TLS → allow."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="api.visa.com", is_tls=True, sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "allow"

    def test_normal_domain_allows(self):
        """Benign domain → allow."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="swift.com", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "allow"

    def test_tor_disabled_allows_tor_domain(self):
        """With block_tor=False, .onion domain passes through."""
        from minifw_ai.sector_rules import finance
        cfg = {"block_tor": False, "block_anonymizers": True, "strict_tls": True}
        meta = _meta(domain="hidden.onion", sector_config=cfg)
        action, reason = finance.evaluate(meta)
        # .onion not blocked when block_tor=False; no other rules fire
        assert action == "allow"

    def test_free_crypto_airdrop_phishing_blocks(self):
        """'free-crypto' pattern → crypto phishing block."""
        from minifw_ai.sector_rules import finance
        meta = _meta(domain="free-crypto-claim.com", sector_config=self._CFG)
        action, reason = finance.evaluate(meta)
        assert action == "block"
        assert reason == "fin_crypto_phishing"


# ---------------------------------------------------------------------------
# legal.py
# ---------------------------------------------------------------------------
class TestLegal:
    """Tests for sector_rules/legal.py — DNS exfiltration and confidentiality."""

    _CFG = {"data_exfiltration_watch": True, "confidentiality_mode": True}

    def test_long_label_monitors(self):
        """A DNS label > 50 chars → monitor (exfiltration heuristic)."""
        from minifw_ai.sector_rules import legal
        long_label = "a" * 51
        meta = _meta(domain=f"{long_label}.example.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "monitor"
        assert reason == "legal_dns_exfil_long_label"

    def test_normal_label_length_allows(self):
        """Label of exactly 50 chars → allow (not above threshold)."""
        from minifw_ai.sector_rules import legal
        label = "a" * 50
        meta = _meta(domain=f"{label}.example.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "allow"

    def test_deep_chain_monitors(self):
        """Domain with > 6 labels → monitor (DNS tunnelling heuristic)."""
        from minifw_ai.sector_rules import legal
        # 7 labels
        meta = _meta(domain="a.b.c.d.e.f.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "monitor"
        assert reason == "legal_dns_exfil_deep_chain"

    def test_six_labels_not_flagged(self):
        """Domain with exactly 6 labels → allow (at threshold, not above)."""
        from minifw_ai.sector_rules import legal
        meta = _meta(domain="a.b.c.d.example.com", sector_config=self._CFG)  # 6 labels
        action, reason = legal.evaluate(meta)
        assert action == "allow"

    def test_paste_site_blocks(self):
        """Known paste site → block (confidentiality mode)."""
        from minifw_ai.sector_rules import legal
        meta = _meta(domain="pastebin.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "block"
        assert reason == "legal_paste_site"

    def test_paste_site_subdomain_blocks(self):
        """Subdomain of a paste site → block."""
        from minifw_ai.sector_rules import legal
        meta = _meta(domain="api.pastebin.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "block"
        assert reason == "legal_paste_site"

    def test_file_sharing_monitors(self):
        """Consumer file-sharing service → monitor (not block)."""
        from minifw_ai.sector_rules import legal
        meta = _meta(domain="wetransfer.com", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "monitor"
        assert reason == "legal_file_sharing"

    def test_normal_domain_allows(self):
        """Benign domain → allow."""
        from minifw_ai.sector_rules import legal
        meta = _meta(domain="lawsociety.org.uk", sector_config=self._CFG)
        action, reason = legal.evaluate(meta)
        assert action == "allow"

    def test_exfil_watch_disabled_allows_long_label(self):
        """With data_exfiltration_watch=False, long label → allow."""
        from minifw_ai.sector_rules import legal
        cfg = {"data_exfiltration_watch": False, "confidentiality_mode": True}
        label = "b" * 51
        meta = _meta(domain=f"{label}.example.com", sector_config=cfg)
        action, reason = legal.evaluate(meta)
        assert action == "allow"

    def test_confidentiality_disabled_allows_paste_site(self):
        """With confidentiality_mode=False, paste site → allow."""
        from minifw_ai.sector_rules import legal
        cfg = {"data_exfiltration_watch": True, "confidentiality_mode": False}
        meta = _meta(domain="pastebin.com", sector_config=cfg)
        action, reason = legal.evaluate(meta)
        assert action == "allow"


# ---------------------------------------------------------------------------
# __init__.py dispatcher
# ---------------------------------------------------------------------------
class TestDispatcher:
    """Tests for sector_rules/__init__.py get_sector_module()."""

    def test_hospital_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, hospital
        assert get_sector_module("hospital") is hospital

    def test_education_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, education
        assert get_sector_module("education") is education

    def test_establishment_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, establishment
        assert get_sector_module("establishment") is establishment

    def test_government_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, government
        assert get_sector_module("government") is government

    def test_finance_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, finance
        assert get_sector_module("finance") is finance

    def test_legal_module_returned(self):
        from minifw_ai.sector_rules import get_sector_module, legal
        assert get_sector_module("legal") is legal

    def test_unknown_sector_returns_none(self):
        from minifw_ai.sector_rules import get_sector_module
        assert get_sector_module("unknown") is None

    def test_empty_string_returns_none(self):
        from minifw_ai.sector_rules import get_sector_module
        assert get_sector_module("") is None

    def test_all_six_sectors_resolve(self):
        from minifw_ai.sector_rules import get_sector_module
        for sector in ("hospital", "education", "establishment", "government", "finance", "legal"):
            mod = get_sector_module(sector)
            assert mod is not None, f"get_sector_module('{sector}') returned None"
            assert callable(getattr(mod, "evaluate", None)), f"{sector}.evaluate is not callable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
