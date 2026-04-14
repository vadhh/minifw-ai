"""
Tests for security hardening features:
- DNS tunneling detection
- Port scan detection (FlowTracker)
- Login rate limiting & account lockout
- Input validation (SQL/command injection prevention)
"""
import os
import time
import pytest

os.environ.setdefault("MINIFW_SECTOR", "establishment")
os.environ.setdefault("MINIFW_SECRET_KEY", "test-secret-key-for-testing-only")


# ============================================================
# DNS Tunneling Detection
# ============================================================
from minifw_ai.dns_tunnel_detect import (
    _shannon_entropy,
    _extract_subdomain_labels,
    _base_domain,
    analyze_domain_tunneling,
    TunnelTracker,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("a") == 0.0

    def test_uniform_distribution(self):
        # "ab" has 1 bit per char
        entropy = _shannon_entropy("ab")
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy_random(self):
        # hex-like string should have high entropy
        s = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        entropy = _shannon_entropy(s)
        assert entropy > 3.0

    def test_low_entropy_repeated(self):
        s = "aaaaaaaaaa"
        entropy = _shannon_entropy(s)
        assert entropy == 0.0


class TestSubdomainExtraction:
    def test_simple_domain(self):
        assert _extract_subdomain_labels("example.com") == []

    def test_one_subdomain(self):
        assert _extract_subdomain_labels("www.example.com") == ["www"]

    def test_deep_subdomain(self):
        labels = _extract_subdomain_labels("a.b.c.d.example.com")
        assert labels == ["a", "b", "c", "d"]

    def test_trailing_dot(self):
        labels = _extract_subdomain_labels("www.example.com.")
        assert labels == ["www"]


class TestBaseDomain:
    def test_simple(self):
        assert _base_domain("www.example.com") == "example.com"

    def test_no_subdomain(self):
        assert _base_domain("example.com") == "example.com"

    def test_deep(self):
        assert _base_domain("a.b.c.example.com") == "example.com"


class TestAnalyzeDomainTunneling:
    def test_normal_domain_low_score(self):
        score, reasons = analyze_domain_tunneling("www.google.com")
        assert score < 20

    def test_empty_domain(self):
        score, reasons = analyze_domain_tunneling("")
        assert score == 0
        assert reasons == []

    def test_no_subdomain(self):
        score, reasons = analyze_domain_tunneling("example.com")
        assert score == 0

    def test_long_domain_detected(self):
        # Build a domain > 100 chars
        long_sub = "a" * 60
        domain = f"{long_sub}.{long_sub}.example.com"
        score, reasons = analyze_domain_tunneling(domain)
        assert score > 0
        assert any("long" in r or "length" in r for r in reasons)

    def test_high_entropy_detected(self):
        # Base64-like encoded subdomain
        encoded = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q"
        domain = f"{encoded}.tunnel.example.com"
        score, reasons = analyze_domain_tunneling(domain)
        assert score > 0

    def test_long_label_detected(self):
        long_label = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
        domain = f"{long_label}.example.com"
        score, reasons = analyze_domain_tunneling(domain)
        assert any("label" in r for r in reasons)

    def test_deep_nesting_detected(self):
        domain = "a.b.c.d.e.f.example.com"
        score, reasons = analyze_domain_tunneling(domain)
        assert any("nesting" in r for r in reasons)

    def test_obvious_tunnel_high_score(self):
        # Combine multiple indicators
        encoded = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
        domain = f"{encoded}.{encoded}.{encoded}.tunnel.example.com"
        score, reasons = analyze_domain_tunneling(domain)
        assert score >= 50

    def test_score_capped_at_100(self):
        # Even with many indicators, score shouldn't exceed 100
        encoded = "a" * 63
        domain = f"{encoded}.{encoded}.{encoded}.example.com"
        score, _ = analyze_domain_tunneling(domain)
        assert score <= 100


class TestTunnelTracker:
    def test_initial_query(self):
        tracker = TunnelTracker(window_seconds=60)
        count = tracker.record_query("sub1.example.com")
        assert count == 1

    def test_multiple_unique_subdomains(self):
        tracker = TunnelTracker(window_seconds=60)
        for i in range(10):
            count = tracker.record_query(f"sub{i}.example.com")
        assert count == 10

    def test_repeated_subdomain_not_counted_twice(self):
        tracker = TunnelTracker(window_seconds=60)
        tracker.record_query("same.example.com")
        count = tracker.record_query("same.example.com")
        assert count == 1

    def test_no_subdomain_returns_zero(self):
        tracker = TunnelTracker(window_seconds=60)
        count = tracker.record_query("example.com")
        assert count == 0

    def test_sustained_tunneling_detected(self):
        tracker = TunnelTracker(window_seconds=60)
        for i in range(25):
            tracker.record_query(f"encoded{i}.tunnel.example.com")
        is_tunneling, count = tracker.check_sustained_tunneling(
            "encoded25.tunnel.example.com", threshold=20
        )
        assert is_tunneling is True
        assert count >= 20

    def test_sustained_tunneling_not_triggered_below_threshold(self):
        tracker = TunnelTracker(window_seconds=60)
        for i in range(5):
            tracker.record_query(f"sub{i}.example.com")
        is_tunneling, count = tracker.check_sustained_tunneling(
            "sub5.example.com", threshold=20
        )
        assert is_tunneling is False

    def test_lru_eviction(self):
        tracker = TunnelTracker(window_seconds=60, max_entries=3)
        tracker.record_query("a.one.com")
        tracker.record_query("a.two.com")
        tracker.record_query("a.three.com")
        tracker.record_query("a.four.com")  # evicts one.com
        assert "one.com" not in tracker._queries


# ============================================================
# Port Scan Detection (FlowTracker)
# ============================================================
from minifw_ai.collector_flow import FlowStats, FlowTracker


class TestPortScanDetection:
    def test_no_scan_few_ports(self):
        tracker = FlowTracker()
        for port in [80, 443, 8080]:
            tracker.update_flow("10.0.0.1", "1.1.1.1", port, "tcp", pkt_size=64)
        is_scan, count = tracker.detect_port_scan("10.0.0.1")
        assert is_scan is False
        assert count == 3

    def test_scan_detected_many_ports(self):
        tracker = FlowTracker()
        for port in range(1, 20):
            tracker.update_flow("10.0.0.1", "1.1.1.1", port, "tcp", pkt_size=64)
        is_scan, count = tracker.detect_port_scan("10.0.0.1", threshold=15)
        assert is_scan is True
        assert count == 19

    def test_unique_dst_ports(self):
        tracker = FlowTracker()
        tracker.update_flow("10.0.0.1", "1.1.1.1", 80, "tcp", pkt_size=64)
        tracker.update_flow("10.0.0.1", "1.1.1.1", 443, "tcp", pkt_size=64)
        tracker.update_flow("10.0.0.1", "2.2.2.2", 80, "tcp", pkt_size=64)
        ports = tracker.get_unique_dst_ports("10.0.0.1")
        assert ports == {80, 443}

    def test_different_clients_independent(self):
        tracker = FlowTracker()
        for port in range(1, 20):
            tracker.update_flow("10.0.0.1", "1.1.1.1", port, "tcp", pkt_size=64)
        # Different client should not be flagged
        tracker.update_flow("10.0.0.2", "1.1.1.1", 80, "tcp", pkt_size=64)
        is_scan, count = tracker.detect_port_scan("10.0.0.2")
        assert is_scan is False
        assert count == 1


# ============================================================
# Login Rate Limiting & Account Lockout
# ============================================================
from app.web.routers.auth import (
    _check_ip_rate_limit,
    _record_login_attempt,
    _check_account_lockout,
    _handle_failed_login,
    _reset_failed_attempts,
    _login_attempts,
    MAX_LOGIN_ATTEMPTS_PER_IP,
    MAX_FAILED_BEFORE_LOCKOUT,
)


class TestIPRateLimiting:
    def setup_method(self):
        _login_attempts.clear()

    def test_not_rate_limited_initially(self):
        assert _check_ip_rate_limit("192.168.1.1") is False

    def test_rate_limited_after_max_attempts(self):
        ip = "192.168.1.100"
        for _ in range(MAX_LOGIN_ATTEMPTS_PER_IP):
            _record_login_attempt(ip)
        assert _check_ip_rate_limit(ip) is True

    def test_not_rate_limited_below_threshold(self):
        ip = "192.168.1.101"
        for _ in range(MAX_LOGIN_ATTEMPTS_PER_IP - 1):
            _record_login_attempt(ip)
        assert _check_ip_rate_limit(ip) is False

    def test_different_ips_independent(self):
        for _ in range(MAX_LOGIN_ATTEMPTS_PER_IP):
            _record_login_attempt("10.0.0.1")
        assert _check_ip_rate_limit("10.0.0.1") is True
        assert _check_ip_rate_limit("10.0.0.2") is False

    def test_lru_eviction(self):
        from app.web.routers.auth import _MAX_IPS_TRACKED

        # Fill up to max
        for i in range(_MAX_IPS_TRACKED):
            _record_login_attempt(f"10.{i // 256}.{i % 256}.1")
        # One more should evict the oldest
        _record_login_attempt("99.99.99.99")
        assert len(_login_attempts) <= _MAX_IPS_TRACKED


class TestAccountLockout:
    def test_unlocked_user(self):
        class MockUser:
            is_locked = False
            locked_until = None
        assert _check_account_lockout(MockUser()) is False

    def test_locked_user(self):
        from datetime import datetime, timedelta

        class MockUser:
            is_locked = True
            locked_until = datetime.utcnow() + timedelta(minutes=10)
        assert _check_account_lockout(MockUser()) is True

    def test_expired_lockout(self):
        from datetime import datetime, timedelta

        class MockUser:
            is_locked = True
            locked_until = datetime.utcnow() - timedelta(minutes=1)
        assert _check_account_lockout(MockUser()) is False


# ============================================================
# Input Validation (SQL/Command Injection Prevention)
# ============================================================
from app.web.routers.admin import (
    _validate_domain,
    _validate_ip,
    _validate_asn,
    _validate_safe_name,
    _validate_safe_path,
    _validate_no_injection,
    AddDomainRequest,
    AddIpRequest,
    AddAsnRequest,
    AddSegmentRequest,
    UpdateEnforcementRequest,
    UpdateCollectorsRequest,
    CreateUserRequest,
)
from pydantic import ValidationError


class TestDomainValidation:
    def test_valid_domain(self):
        assert _validate_domain("example.com") == "example.com"

    def test_valid_wildcard(self):
        assert _validate_domain("*.example.com") == "*.example.com"

    def test_valid_subdomain(self):
        assert _validate_domain("sub.example.com") == "sub.example.com"

    def test_strips_whitespace(self):
        assert _validate_domain("  example.com  ") == "example.com"

    def test_rejects_sql_injection(self):
        with pytest.raises(ValueError):
            _validate_domain("'; DROP TABLE users;--")

    def test_rejects_command_injection(self):
        with pytest.raises(ValueError):
            _validate_domain("$(whoami).evil.com")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            _validate_domain("a" * 254)

    def test_pydantic_model_rejects(self):
        with pytest.raises(ValidationError):
            AddDomainRequest(domain="'; DROP TABLE--")


class TestIPValidation:
    def test_valid_ip(self):
        assert _validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_cidr(self):
        assert _validate_ip("10.0.0.0/8") == "10.0.0.0/8"

    def test_rejects_invalid_octet(self):
        with pytest.raises(ValueError):
            _validate_ip("999.0.0.1")

    def test_rejects_invalid_prefix(self):
        with pytest.raises(ValueError):
            _validate_ip("10.0.0.0/33")

    def test_rejects_non_ip(self):
        with pytest.raises(ValueError):
            _validate_ip("not-an-ip")

    def test_rejects_injection(self):
        with pytest.raises(ValueError):
            _validate_ip("1.1.1.1; rm -rf /")

    def test_pydantic_model_rejects(self):
        with pytest.raises(ValidationError):
            AddIpRequest(ip="'; DROP--")


class TestASNValidation:
    def test_valid_asn(self):
        assert _validate_asn("AS12345") == "AS12345"

    def test_lowercase_normalized(self):
        assert _validate_asn("as12345") == "AS12345"

    def test_rejects_no_prefix(self):
        with pytest.raises(ValueError):
            _validate_asn("12345")

    def test_rejects_injection(self):
        with pytest.raises(ValueError):
            _validate_asn("AS123; DROP")

    def test_pydantic_model_rejects(self):
        with pytest.raises(ValidationError):
            AddAsnRequest(asn="not-an-asn")


class TestSafeNameValidation:
    def test_valid_name(self):
        assert _validate_safe_name("my_segment-1") == "my_segment-1"

    def test_rejects_spaces(self):
        with pytest.raises(ValueError):
            _validate_safe_name("my segment")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError):
            _validate_safe_name("name; rm -rf")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            _validate_safe_name("a" * 65)


class TestSafePathValidation:
    def test_valid_path(self):
        assert _validate_safe_path("/var/log/dnsmasq.log") == "/var/log/dnsmasq.log"

    def test_rejects_traversal(self):
        with pytest.raises(ValueError):
            _validate_safe_path("../../etc/passwd")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError):
            _validate_safe_path("/var/log/$(whoami)")


class TestInjectionDetection:
    def test_sql_union(self):
        with pytest.raises(ValueError):
            _validate_no_injection("1 UNION SELECT * FROM users")

    def test_sql_drop(self):
        with pytest.raises(ValueError):
            _validate_no_injection("'; DROP TABLE users;--")

    def test_command_injection(self):
        with pytest.raises(ValueError):
            _validate_no_injection("$(cat /etc/passwd)")

    def test_clean_text_passes(self):
        assert _validate_no_injection("Normal text input") == "Normal text input"


class TestPydanticModelValidation:
    def test_segment_threshold_range(self):
        with pytest.raises(ValidationError):
            AddSegmentRequest(segment_name="test", block_threshold=200, monitor_threshold=50)

    def test_enforcement_timeout_range(self):
        with pytest.raises(ValidationError):
            UpdateEnforcementRequest(
                ipset_name_v4="minifw_v4",
                ip_timeout_seconds=999999,
                nft_table="minifw",
                nft_chain="forward",
            )

    def test_enforcement_nft_name_injection(self):
        with pytest.raises(ValidationError):
            UpdateEnforcementRequest(
                ipset_name_v4="minifw; rm -rf /",
                ip_timeout_seconds=300,
                nft_table="minifw",
                nft_chain="forward",
            )

    def test_collectors_path_traversal(self):
        with pytest.raises(ValidationError):
            UpdateCollectorsRequest(
                dnsmasq_log_path="../../etc/shadow",
                zeek_ssl_log_path="/var/log/zeek/ssl.log",
                use_zeek_sni=True,
            )

    def test_create_user_role_whitelist(self):
        with pytest.raises(ValidationError):
            CreateUserRequest(
                username="testuser",
                email="test@test.com",
                password="Password123!",
                role="hacker",
                sector="gambling",
            )

    def test_create_user_sector_whitelist(self):
        with pytest.raises(ValidationError):
            CreateUserRequest(
                username="testuser",
                email="test@test.com",
                password="Password123!",
                role="admin",
                sector="invalid_sector",
            )

    def test_create_user_valid(self):
        user = CreateUserRequest(
            username="admin_user",
            email="admin@example.com",
            password="SecurePass123!",
            role="admin",
            sector="gambling",
        )
        assert user.username == "admin_user"
        assert user.role == "admin"
        assert user.sector == "gambling"
