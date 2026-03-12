"""
Zeek Collector Tests

Tests parse_zeek_ssl_tsv() with sample Zeek ssl.log lines
to verify correct (client_ip, sni) extraction.
"""
import pytest

from minifw_ai.collector_zeek import parse_zeek_ssl_tsv


# ---------------------------------------------------------------------------
# Successful parsing
# ---------------------------------------------------------------------------

# Zeek ssl.log TSV format (tab-separated):
# ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  version  ...  server_name  ...
SAMPLE_LINES = [
    (
        "1709000000.000000\tC1234\t192.168.1.10\t54321\t93.184.216.34\t443\tTLSv12\t-\t-\texample.com\t-",
        ("192.168.1.10", "example.com"),
    ),
    (
        "1709000001.000000\tC5678\t10.0.0.5\t12345\t172.217.14.206\t443\tTLSv13\t-\t-\twww.google.com\t-",
        ("10.0.0.5", "www.google.com"),
    ),
    (
        "1709000002.000000\tC9012\t172.16.0.100\t55555\t1.2.3.4\t8443\tTLSv12\t-\t-\tapi.service.internal.example.org\t-",
        ("172.16.0.100", "api.service.internal.example.org"),
    ),
]


@pytest.mark.parametrize("line,expected", SAMPLE_LINES)
def test_parse_zeek_ssl_tsv_extracts_ip_and_sni(line, expected):
    result = parse_zeek_ssl_tsv(line)
    assert result is not None
    client_ip, sni = result
    assert client_ip == expected[0]
    assert sni == expected[1]


# ---------------------------------------------------------------------------
# Lines that should return None
# ---------------------------------------------------------------------------

def test_parse_zeek_comment_line():
    assert parse_zeek_ssl_tsv("#separator \\x09") is None
    assert parse_zeek_ssl_tsv("#fields ts uid id.orig_h") is None


def test_parse_zeek_empty_line():
    assert parse_zeek_ssl_tsv("") is None


def test_parse_zeek_none_input():
    # parse_zeek_ssl_tsv checks `not line` first
    assert parse_zeek_ssl_tsv(None) is None


def test_parse_zeek_too_few_fields():
    assert parse_zeek_ssl_tsv("1709000000\tC1234") is None


def test_parse_zeek_no_sni_field():
    """If no field looks like a domain, returns None."""
    line = "1709000000\tC1234\t192.168.1.10\t54321\t93.184.216.34\t443\tTLSv12\t-\t-\t-\t-"
    result = parse_zeek_ssl_tsv(line)
    assert result is None
