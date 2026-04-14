"""
Tests for hospital sector extra feed: healthcare_threats.txt.

Verifies that the feed loads correctly, that domains in it are scored as
denied, and that its absence does not affect non-hospital sectors.
"""

import os
import tempfile
import pytest
from pathlib import Path
from minifw_ai.feeds import FeedMatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def feeds_dir_with_healthcare(tmp_path):
    """A feeds directory that includes healthcare_threats.txt."""
    # Minimal base feeds
    (tmp_path / "deny_domains.txt").write_text("")
    (tmp_path / "allow_domains.txt").write_text("")
    (tmp_path / "deny_ips.txt").write_text("")
    (tmp_path / "deny_asn.txt").write_text("")

    # Healthcare feed with a few test entries
    (tmp_path / "healthcare_threats.txt").write_text(
        "# test feed\n"
        "lockbit-blog.com\n"
        "*.patient-records-secure.com\n"
        "medrecords-transfer.io\n"
    )
    return tmp_path


@pytest.fixture()
def feeds_dir_without_healthcare(tmp_path):
    """A feeds directory that does NOT have healthcare_threats.txt."""
    (tmp_path / "deny_domains.txt").write_text("")
    (tmp_path / "allow_domains.txt").write_text("")
    (tmp_path / "deny_ips.txt").write_text("")
    (tmp_path / "deny_asn.txt").write_text("")
    return tmp_path


@pytest.fixture()
def real_feeds_dir():
    """Points to the actual config/feeds directory in the repo."""
    here = Path(__file__).parent.parent
    return here / "config" / "feeds"


# ---------------------------------------------------------------------------
# H-2.1 — healthcare_threats.txt file exists in repo
# ---------------------------------------------------------------------------

def test_healthcare_threats_file_exists(real_feeds_dir):
    assert (real_feeds_dir / "healthcare_threats.txt").exists(), (
        "config/feeds/healthcare_threats.txt is missing"
    )


def test_healthcare_threats_file_is_not_empty(real_feeds_dir):
    content = (real_feeds_dir / "healthcare_threats.txt").read_text()
    non_comment = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    assert len(non_comment) >= 5, "healthcare_threats.txt has fewer than 5 active entries"


# ---------------------------------------------------------------------------
# H-2.2 — FeedMatcher.load_sector_feeds loads the file
# ---------------------------------------------------------------------------

def test_load_sector_feeds_loads_healthcare_threats(feeds_dir_with_healthcare):
    fm = FeedMatcher(str(feeds_dir_with_healthcare))
    loaded = fm.load_sector_feeds(["healthcare_threats.txt"])
    assert loaded == 3


def test_domain_in_healthcare_feed_is_denied_after_load(feeds_dir_with_healthcare):
    fm = FeedMatcher(str(feeds_dir_with_healthcare))
    fm.load_sector_feeds(["healthcare_threats.txt"])
    assert fm.domain_denied("lockbit-blog.com")


def test_wildcard_domain_in_healthcare_feed_matches(feeds_dir_with_healthcare):
    fm = FeedMatcher(str(feeds_dir_with_healthcare))
    fm.load_sector_feeds(["healthcare_threats.txt"])
    assert fm.domain_denied("stolen.patient-records-secure.com")


def test_benign_domain_not_denied_after_load(feeds_dir_with_healthcare):
    fm = FeedMatcher(str(feeds_dir_with_healthcare))
    fm.load_sector_feeds(["healthcare_threats.txt"])
    assert not fm.domain_denied("google.com")


# ---------------------------------------------------------------------------
# H-2.3 — Missing feed on non-hospital sector is not an error
# ---------------------------------------------------------------------------

def test_missing_feed_does_not_raise(feeds_dir_without_healthcare):
    fm = FeedMatcher(str(feeds_dir_without_healthcare))
    # Should log a warning but not raise
    loaded = fm.load_sector_feeds(["healthcare_threats.txt"])
    assert loaded == 0
