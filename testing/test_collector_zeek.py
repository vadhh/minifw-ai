"""
Zeek Collector Tests

Tests parse_zeek_ssl_tsv() with sample Zeek ssl.log lines to verify
correct extraction of client_ip, SNI, ALPN (h2 flag), and cert chain
self-signed heuristic from ZeekSSLEvent.
"""
import pytest

from minifw_ai.collector_zeek import parse_zeek_ssl_tsv, ZeekSSLEvent


# Zeek ssl.log TSV column layout (standard Zeek 5.x/6.x):
# 0:ts  1:uid  2:id.orig_h  3:id.orig_p  4:id.resp_h  5:id.resp_p
# 6:version  7:cipher  8:curve  9:server_name  10:resumed  11:last_alert
# 12:next_protocol  13:established  14:cert_chain_fuids ...

def _line(client_ip="192.168.1.10", sni="example.com",
          next_proto="-", established="T", cert_chain="-"):
    """Build a minimal Zeek ssl.log TSV line."""
    return (
        f"1709000000.000000\tC1234\t{client_ip}\t54321\t93.184.216.34\t443\t"
        f"TLSv12\tAES256\t-\t{sni}\tF\t-\t{next_proto}\t{established}\t{cert_chain}"
    )


# ---------------------------------------------------------------------------
# Successful parsing — basic fields
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("client_ip,sni", [
    ("192.168.1.10", "example.com"),
    ("10.0.0.5", "www.google.com"),
    ("172.16.0.100", "api.service.internal.example.org"),
])
def test_parse_zeek_ssl_tsv_extracts_ip_and_sni(client_ip, sni):
    result = parse_zeek_ssl_tsv(_line(client_ip=client_ip, sni=sni))
    assert result is not None
    assert result.client_ip == client_ip
    assert result.sni == sni


def test_parse_returns_zeek_ssl_event():
    result = parse_zeek_ssl_tsv(_line())
    assert isinstance(result, ZeekSSLEvent)


# ---------------------------------------------------------------------------
# ALPN — h2 detection
# ---------------------------------------------------------------------------

def test_alpn_h2_detected():
    result = parse_zeek_ssl_tsv(_line(next_proto="h2"))
    assert result is not None
    assert result.alpn_h2 == 1.0


def test_alpn_http11_not_h2():
    result = parse_zeek_ssl_tsv(_line(next_proto="http/1.1"))
    assert result is not None
    assert result.alpn_h2 == 0.0


def test_alpn_missing_not_h2():
    result = parse_zeek_ssl_tsv(_line(next_proto="-"))
    assert result is not None
    assert result.alpn_h2 == 0.0


# ---------------------------------------------------------------------------
# Cert chain — self-signed heuristic
# ---------------------------------------------------------------------------

def test_single_cert_chain_is_self_signed():
    result = parse_zeek_ssl_tsv(_line(cert_chain="FuFpaa3jM0aMFgVWRb"))
    assert result is not None
    assert result.cert_self_signed == 1.0


def test_multi_cert_chain_not_self_signed():
    result = parse_zeek_ssl_tsv(_line(cert_chain="FuFpaa3jM0aMFgVWRb,FzZuNF3gUSYWdDxlI4"))
    assert result is not None
    assert result.cert_self_signed == 0.0


def test_no_cert_chain_not_self_signed():
    result = parse_zeek_ssl_tsv(_line(cert_chain="-"))
    assert result is not None
    assert result.cert_self_signed == 0.0


# ---------------------------------------------------------------------------
# Lines that should return None
# ---------------------------------------------------------------------------

def test_parse_zeek_comment_line():
    assert parse_zeek_ssl_tsv("#separator \\x09") is None
    assert parse_zeek_ssl_tsv("#fields ts uid id.orig_h") is None


def test_parse_zeek_empty_line():
    assert parse_zeek_ssl_tsv("") is None


def test_parse_zeek_none_input():
    assert parse_zeek_ssl_tsv(None) is None


def test_parse_zeek_too_few_fields():
    assert parse_zeek_ssl_tsv("1709000000\tC1234") is None


def test_parse_zeek_no_sni_no_alpn_no_cert():
    """Line with no usable data returns None."""
    line = "\t".join(["1709000000.0", "C1234", "192.168.1.10", "54321",
                      "1.2.3.4", "443", "TLSv12", "-", "-", "-", "-", "-", "-", "F", "-"])
    assert parse_zeek_ssl_tsv(line) is None
