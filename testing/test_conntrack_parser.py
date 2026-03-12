"""
Conntrack Parser & Feature Vector Tests

Tests parse_conntrack_line() with sample /proc/net/nf_conntrack data
and validates build_feature_vector_24() output values.
"""
import time
from collections import deque

import pytest

from minifw_ai.collector_flow import (
    parse_conntrack_line,
    FlowStats,
    FlowTracker,
    build_feature_vector_24,
)


# ---------------------------------------------------------------------------
# parse_conntrack_line()
# ---------------------------------------------------------------------------

# Note: conntrack lines contain BOTH original and reply direction fields.
# parse_conntrack_line() iterates all fields and takes the LAST src=/dst=/dport=
# match, which is the reply direction. The returned tuple is therefore
# (reply_src, reply_dst, reply_dport, proto).
SAMPLE_LINES = [
    (
        "ipv4     2 tcp      6 117 ESTABLISHED src=192.168.1.100 dst=8.8.8.8 sport=54321 dport=443 src=8.8.8.8 dst=192.168.1.100 sport=443 dport=54321 [ASSURED] mark=0 use=2",
        ("8.8.8.8", "192.168.1.100", 54321, "tcp"),
    ),
    (
        "ipv4     2 udp      17 30 src=10.0.0.5 dst=1.1.1.1 sport=12345 dport=53 src=1.1.1.1 dst=10.0.0.5 sport=53 dport=12345 mark=0 use=2",
        ("1.1.1.1", "10.0.0.5", 12345, "udp"),
    ),
    (
        "ipv4     2 tcp      6 299 ESTABLISHED src=172.16.0.10 dst=93.184.216.34 sport=41000 dport=80 src=93.184.216.34 dst=172.16.0.10 sport=80 dport=41000 [ASSURED] mark=0 use=2",
        ("93.184.216.34", "172.16.0.10", 41000, "tcp"),
    ),
]


@pytest.mark.parametrize("line,expected", SAMPLE_LINES)
def test_parse_conntrack_line_extracts_tuple(line, expected):
    result = parse_conntrack_line(line)
    assert result == expected


def test_parse_conntrack_line_returns_none_for_short_line():
    assert parse_conntrack_line("too short") is None


def test_parse_conntrack_line_returns_none_for_empty():
    assert parse_conntrack_line("") is None


def test_parse_conntrack_line_returns_none_for_missing_fields():
    # Has src but no dst
    line = "ipv4     2 tcp      6 117 ESTABLISHED src=192.168.1.1 sport=1234"
    assert parse_conntrack_line(line) is None


# ---------------------------------------------------------------------------
# build_feature_vector_24() — value validation
# ---------------------------------------------------------------------------

def test_feature_vector_returns_24_floats():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.pkt_count = 50
    flow.first_seen = time.time() - 10.0
    flow.last_seen = time.time()
    flow.pkt_sizes = deque([1000] * 50)
    flow.bytes_sent = 50000

    vec = build_feature_vector_24(flow)
    assert len(vec) == 24
    assert all(isinstance(v, (int, float)) for v in vec)


def test_feature_vector_duration_sec():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = time.time() - 5.0
    flow.last_seen = time.time()

    vec = build_feature_vector_24(flow)
    duration = vec[0]
    assert 4.5 < duration < 5.5  # ~5s with timing tolerance


def test_feature_vector_pkts_per_sec():
    now = time.time()
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = now - 10.0
    flow.last_seen = now
    flow.pkt_count = 100

    vec = build_feature_vector_24(flow)
    pps = vec[4]  # pkts_per_sec is index 4
    assert 9.0 < pps < 11.0  # ~10 pps


def test_feature_vector_small_pkt_ratio():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = time.time() - 5.0
    flow.last_seen = time.time()
    flow.pkt_count = 10
    # 8 small + 2 large → ratio = 0.8
    flow.pkt_sizes = deque([50] * 8 + [1500] * 2)

    vec = build_feature_vector_24(flow)
    small_ratio = vec[13]  # small_pkt_ratio is index 13
    assert small_ratio == pytest.approx(0.8)


def test_feature_vector_interarrival_mean_ms():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = time.time() - 5.0
    flow.last_seen = time.time()
    flow.pkt_count = 20
    # Uniform IAT of 100ms
    flow.interarrival_times = deque([100.0] * 20)

    vec = build_feature_vector_24(flow)
    iat_mean = vec[10]  # interarrival_mean_ms is index 10
    assert iat_mean == pytest.approx(100.0)


def test_feature_vector_dns_fields():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = time.time() - 1.0
    flow.last_seen = time.time()
    flow.domain = "sub.example.com"

    vec = build_feature_vector_24(flow)
    dns_seen = vec[20]       # dns_seen
    fqdn_len = vec[21]       # fqdn_len
    subdomain_depth = vec[22] # subdomain_depth

    assert dns_seen == 1.0
    assert fqdn_len == len("sub.example.com")
    assert subdomain_depth == 1.0  # "sub.example.com" has 2 dots, depth = 2 - 1 = 1


def test_feature_vector_tls_fields():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443, proto="tcp")
    flow.first_seen = time.time() - 1.0
    flow.last_seen = time.time()
    flow.tls_seen = True
    flow.sni = "example.com"

    vec = build_feature_vector_24(flow)
    tls_seen = vec[14]  # tls_seen
    sni_len = vec[17]   # sni_len

    assert tls_seen == 1.0
    assert sni_len == len("example.com")


def test_feature_vector_no_domain_no_tls():
    flow = FlowStats(client_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, proto="tcp")
    flow.first_seen = time.time() - 1.0
    flow.last_seen = time.time()

    vec = build_feature_vector_24(flow)
    tls_seen = vec[14]
    dns_seen = vec[20]
    sni_len = vec[17]
    fqdn_len = vec[21]

    assert tls_seen == 0.0
    assert dns_seen == 0.0
    assert sni_len == 0.0
    assert fqdn_len == 0.0
