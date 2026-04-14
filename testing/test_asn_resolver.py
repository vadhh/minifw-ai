"""
ASN Resolver Tests

Tests ASNResolver: prefix file loading, IP-to-ASN lookup, longest-prefix match,
and integration with FeedMatcher.asn_denied().
"""
import pytest

from minifw_ai.netutil import ASNResolver
from minifw_ai.feeds import FeedMatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def prefix_file(tmp_path):
    """Create a sample asn_prefixes.txt file."""
    content = """\
# Google DNS
8.8.8.0/24 AS15169
8.8.4.0/24 AS15169

# Cloudflare
1.1.1.0/24 AS13335

# Broader Google prefix (shorter match)
8.8.0.0/16 AS15169

# Private ranges
10.0.0.0/8 AS64512
192.168.0.0/16 AS64513

# Specific /32 override
10.0.0.99/32 AS99999
"""
    path = tmp_path / "asn_prefixes.txt"
    path.write_text(content)
    return str(path)


@pytest.fixture
def resolver(prefix_file):
    r = ASNResolver()
    r.load(prefix_file)
    return r


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class TestLoading:
    def test_load_returns_count(self, prefix_file):
        r = ASNResolver()
        count = r.load(prefix_file)
        assert count == 7

    def test_load_missing_file_returns_zero(self, tmp_path):
        r = ASNResolver()
        count = r.load(str(tmp_path / "nonexistent.txt"))
        assert count == 0
        assert not r.loaded

    def test_loaded_property(self, resolver):
        assert resolver.loaded is True

    def test_empty_resolver_not_loaded(self):
        r = ASNResolver()
        assert r.loaded is False

    def test_skips_comments_and_blanks(self, tmp_path):
        path = tmp_path / "sparse.txt"
        path.write_text("# comment\n\n  \n1.2.3.0/24 AS100\n")
        r = ASNResolver()
        assert r.load(str(path)) == 1

    def test_skips_malformed_lines(self, tmp_path):
        path = tmp_path / "bad.txt"
        path.write_text("no_cidr_here\n999.999.999.0/24 AS100\n1.1.1.0/24 AS200\n")
        r = ASNResolver()
        assert r.load(str(path)) == 1  # only valid line


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

class TestLookup:
    def test_exact_match(self, resolver):
        assert resolver.lookup("8.8.8.8") == "AS15169"

    def test_cloudflare(self, resolver):
        assert resolver.lookup("1.1.1.1") == "AS13335"

    def test_private_range(self, resolver):
        assert resolver.lookup("10.1.2.3") == "AS64512"

    def test_no_match_returns_none(self, resolver):
        assert resolver.lookup("203.0.113.1") is None

    def test_invalid_ip_returns_none(self, resolver):
        assert resolver.lookup("not-an-ip") is None

    def test_empty_string_returns_none(self, resolver):
        assert resolver.lookup("") is None

    def test_longest_prefix_match(self, resolver):
        """10.0.0.99 matches both /8 (AS64512) and /32 (AS99999); /32 wins."""
        assert resolver.lookup("10.0.0.99") == "AS99999"

    def test_shorter_prefix_for_non_specific_ip(self, resolver):
        """10.0.0.1 matches /8 (AS64512) but not /32."""
        assert resolver.lookup("10.0.0.1") == "AS64512"


# ---------------------------------------------------------------------------
# Integration with FeedMatcher
# ---------------------------------------------------------------------------

class TestASNDenyIntegration:
    def test_asn_denied_when_in_deny_list(self, resolver, tmp_path):
        """Full pipeline: IP → ASN → deny check."""
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_asn.txt").write_text("AS15169\nAS99999\n")
        (feeds_dir / "deny_domains.txt").write_text("")
        (feeds_dir / "allow_domains.txt").write_text("")
        (feeds_dir / "deny_ips.txt").write_text("")

        feeds = FeedMatcher(str(feeds_dir))

        # Google IP → AS15169 → denied
        asn = resolver.lookup("8.8.8.8")
        assert asn == "AS15169"
        assert feeds.asn_denied(asn) is True

    def test_asn_not_denied_when_not_in_list(self, resolver, tmp_path):
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_asn.txt").write_text("AS99999\n")
        (feeds_dir / "deny_domains.txt").write_text("")
        (feeds_dir / "allow_domains.txt").write_text("")
        (feeds_dir / "deny_ips.txt").write_text("")

        feeds = FeedMatcher(str(feeds_dir))

        # Cloudflare IP → AS13335 → NOT denied
        asn = resolver.lookup("1.1.1.1")
        assert asn == "AS13335"
        assert feeds.asn_denied(asn) is False

    def test_no_asn_resolved_not_denied(self, resolver, tmp_path):
        """If IP has no ASN mapping, asn_denied should not fire."""
        feeds_dir = tmp_path / "feeds"
        feeds_dir.mkdir()
        (feeds_dir / "deny_asn.txt").write_text("AS15169\n")
        (feeds_dir / "deny_domains.txt").write_text("")
        (feeds_dir / "allow_domains.txt").write_text("")
        (feeds_dir / "deny_ips.txt").write_text("")

        feeds = FeedMatcher(str(feeds_dir))

        asn = resolver.lookup("203.0.113.1")  # No mapping
        assert asn is None
        # Same logic as main.py: bool(None and ...) → False
        assert bool(asn and feeds.asn_denied(asn)) is False
