"""
Tests for Finance sector block_tor / block_anonymizers enforcement.

Validates:
- Tor exit IPs are loaded into FeedMatcher.deny_ips when block_tor=True
- ip_denied() returns True for loaded Tor IPs
- ip_denied() returns False for non-Tor IPs
- Nothing loaded when block_tor=False
- score_and_decide includes ip_denied scoring
"""

import os
import tempfile
from pathlib import Path

import pytest

# conftest.py sets GAMBLING_ONLY=1 automatically


class TestFeedMatcherLoadTorExits:
    """Test FeedMatcher.load_tor_exits() method."""

    def test_load_tor_exits_adds_ips_to_deny_set(self, tmp_path):
        """Tor exit IPs are loaded when load_tor_exits is called."""
        from minifw_ai.feeds import FeedMatcher

        # Create a minimal feeds dir (empty deny files)
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").touch()
        (feeds_dir / "deny_asn.txt").touch()

        # Create tor exit nodes file
        tor_file = feeds_dir / "tor_exit_nodes.txt"
        tor_file.write_text("1.2.3.4\n5.6.7.8\n9.10.11.12\n")

        fm = FeedMatcher(str(feeds_dir))
        assert len(fm.deny_ips) == 0

        count = fm.load_tor_exits(str(tor_file))
        assert count == 3
        assert "1.2.3.4" in fm.deny_ips
        assert "5.6.7.8" in fm.deny_ips
        assert "9.10.11.12" in fm.deny_ips

    def test_ip_denied_true_for_tor_exit(self, tmp_path):
        """ip_denied returns True for loaded Tor exit IPs."""
        from minifw_ai.feeds import FeedMatcher

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").touch()
        (feeds_dir / "deny_asn.txt").touch()

        tor_file = feeds_dir / "tor_exit_nodes.txt"
        tor_file.write_text("198.51.100.1\n203.0.113.5\n")

        fm = FeedMatcher(str(feeds_dir))
        fm.load_tor_exits(str(tor_file))

        assert fm.ip_denied("198.51.100.1") is True
        assert fm.ip_denied("203.0.113.5") is True

    def test_ip_denied_false_for_non_tor_ip(self, tmp_path):
        """ip_denied returns False for IPs not in the Tor exit list."""
        from minifw_ai.feeds import FeedMatcher

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").touch()
        (feeds_dir / "deny_asn.txt").touch()

        tor_file = feeds_dir / "tor_exit_nodes.txt"
        tor_file.write_text("198.51.100.1\n")

        fm = FeedMatcher(str(feeds_dir))
        fm.load_tor_exits(str(tor_file))

        assert fm.ip_denied("10.0.0.1") is False
        assert fm.ip_denied("192.168.1.1") is False

    def test_nothing_loaded_when_file_missing(self, tmp_path):
        """load_tor_exits returns 0 when file does not exist."""
        from minifw_ai.feeds import FeedMatcher

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").touch()
        (feeds_dir / "deny_asn.txt").touch()

        fm = FeedMatcher(str(feeds_dir))
        count = fm.load_tor_exits(str(feeds_dir / "nonexistent.txt"))
        assert count == 0
        assert len(fm.deny_ips) == 0

    def test_comments_and_blank_lines_skipped(self, tmp_path):
        """Comments (#) and blank lines are ignored in tor exit file."""
        from minifw_ai.feeds import FeedMatcher

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").touch()
        (feeds_dir / "deny_asn.txt").touch()

        tor_file = feeds_dir / "tor_exit_nodes.txt"
        tor_file.write_text("# Tor exit nodes list\n\n1.1.1.1\n# another comment\n2.2.2.2\n\n")

        fm = FeedMatcher(str(feeds_dir))
        count = fm.load_tor_exits(str(tor_file))
        assert count == 2
        assert fm.ip_denied("1.1.1.1") is True
        assert fm.ip_denied("2.2.2.2") is True

    def test_no_duplicates_with_existing_deny_ips(self, tmp_path):
        """Tor IPs already in deny_ips are not double-counted."""
        from minifw_ai.feeds import FeedMatcher

        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_domains.txt").touch()
        (feeds_dir / "allow_domains.txt").touch()
        (feeds_dir / "deny_ips.txt").write_text("1.2.3.4\n")
        (feeds_dir / "deny_asn.txt").touch()

        tor_file = feeds_dir / "tor_exit_nodes.txt"
        tor_file.write_text("1.2.3.4\n5.6.7.8\n")

        fm = FeedMatcher(str(feeds_dir))
        assert len(fm.deny_ips) == 1  # pre-existing

        count = fm.load_tor_exits(str(tor_file))
        assert count == 1  # only the new one
        assert len(fm.deny_ips) == 2


class TestScoreAndDecideIpDenied:
    """Test that score_and_decide handles ip_denied flag."""

    def test_ip_denied_adds_score(self):
        """ip_denied=True adds +15 to score and adds reason."""
        from minifw_ai.main import score_and_decide
        from minifw_ai.policy import SegmentThreshold

        thr = SegmentThreshold(block_threshold=90, monitor_threshold=60)
        weights = {}

        score, reasons, action = score_and_decide(
            domain="example.com",
            denied=False,
            sni_denied=False,
            asn_denied=False,
            burst_hit=0,
            weights=weights,
            thresholds=thr,
            ip_denied=True,
        )

        assert score == 15
        assert "ip_denied_tor_anonymizer" in reasons

    def test_ip_denied_false_no_score(self):
        """ip_denied=False adds nothing to score."""
        from minifw_ai.main import score_and_decide
        from minifw_ai.policy import SegmentThreshold

        thr = SegmentThreshold(block_threshold=90, monitor_threshold=60)
        weights = {}

        score, reasons, action = score_and_decide(
            domain="example.com",
            denied=False,
            sni_denied=False,
            asn_denied=False,
            burst_hit=0,
            weights=weights,
            thresholds=thr,
            ip_denied=False,
        )

        assert score == 0
        assert "ip_denied_tor_anonymizer" not in reasons

    def test_ip_denied_with_custom_weight(self):
        """ip_denied uses ip_denied_weight from weights dict."""
        from minifw_ai.main import score_and_decide
        from minifw_ai.policy import SegmentThreshold

        thr = SegmentThreshold(block_threshold=90, monitor_threshold=60)
        weights = {"ip_denied_weight": 25}

        score, reasons, action = score_and_decide(
            domain="example.com",
            denied=False,
            sni_denied=False,
            asn_denied=False,
            burst_hit=0,
            weights=weights,
            thresholds=thr,
            ip_denied=True,
        )

        assert score == 25
        assert "ip_denied_tor_anonymizer" in reasons

    def test_ip_denied_combined_with_dns_denied_triggers_monitor(self):
        """ip_denied + dns_denied can push score into monitor range."""
        from minifw_ai.main import score_and_decide
        from minifw_ai.policy import SegmentThreshold

        thr = SegmentThreshold(block_threshold=90, monitor_threshold=60)
        weights = {"dns_weight": 40, "sni_weight": 35}

        score, reasons, action = score_and_decide(
            domain="bad.example.com",
            denied=True,
            sni_denied=True,
            asn_denied=False,
            burst_hit=0,
            weights=weights,
            thresholds=thr,
            ip_denied=True,
        )

        # 40 (dns) + 35 (sni) + 15 (ip_denied) = 90 -> block
        assert score == 90
        assert action == "block"
        assert "ip_denied_tor_anonymizer" in reasons
        assert "dns_denied_domain" in reasons


class TestSectorConfigBlockTor:
    """Test that sector config block_tor flag controls Tor loading."""

    def test_finance_sector_has_block_tor_true(self):
        """Finance sector config has block_tor=True."""
        from minifw_ai.sector_config import SECTOR_POLICIES

        # Get finance policy - handle both enum and fallback forms
        finance_policy = None
        for key, val in SECTOR_POLICIES.items():
            if getattr(key, "value", key) == "finance":
                finance_policy = val
                break

        assert finance_policy is not None, "Finance sector not found in SECTOR_POLICIES"
        assert finance_policy.get("block_tor") is True
        assert finance_policy.get("block_anonymizers") is True

    def test_establishment_sector_has_no_block_tor(self):
        """Establishment sector does not have block_tor."""
        from minifw_ai.sector_config import SECTOR_POLICIES

        estab_policy = None
        for key, val in SECTOR_POLICIES.items():
            if getattr(key, "value", key) == "establishment":
                estab_policy = val
                break

        assert estab_policy is not None
        assert estab_policy.get("block_tor") is None or estab_policy.get("block_tor") is False
