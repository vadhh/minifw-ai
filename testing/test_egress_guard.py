from unittest.mock import Mock
import pytest
from minifw_ai import egress_guard


@pytest.mark.parametrize("name", ["", "eth0;flush ruleset", 'mfcg"', "a" * 16])
def test_rejects_invalid_or_unspecified_interface(name):
    with pytest.raises(ValueError):
        egress_guard.render(name)


def test_guard_is_narrow_and_ipv6_is_explicit():
    rules = egress_guard.render("mfcg")
    assert "redirect to :53" in rules and "dport 853" in rules
    assert "nfproto ipv6" not in rules and "dport 443" not in rules
    assert 'iifname "mfcg" meta nfproto ipv6 counter drop' in egress_guard.render("mfcg", True)


def test_replacement_is_one_transaction(monkeypatch):
    command = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(egress_guard.subprocess, "run", command)
    egress_guard.apply("mfcg", True)
    assert command.call_args.args[0] == ["nft", "-f", "-"]
    assert command.call_args.kwargs["input"].startswith("delete table inet minifw_egress\ntable")


def test_doh_resolvers_denied_on_443_only_by_address():
    rules = egress_guard.render("mfcg", doh=["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
    assert 'iifname "mfcg" ip daddr { 1.1.1.1, 8.8.8.8 } meta l4proto { tcp, udp } th dport 443 counter drop' in rules
    assert 'iifname "mfcg" ip6 daddr { 2606:4700:4700::1111 } meta l4proto { tcp, udp } th dport 443 counter drop' in rules
    assert "ip6 daddr" not in egress_guard.render("mfcg", doh=["1.1.1.1"])


@pytest.mark.parametrize("bad", ["1.1.1.1 } ; flush ruleset", "dns.google", "1.1.1.0/24"])
def test_doh_entries_must_be_single_addresses(bad):
    with pytest.raises(ValueError):
        egress_guard.render("mfcg", doh=[bad])


def test_shipped_doh_list_parses():
    from pathlib import Path
    listed = egress_guard.load_doh_list(Path(__file__).resolve().parents[1] / "config/feeds/doh_resolvers.txt")
    assert {"8.8.8.8", "1.1.1.1", "9.9.9.9"} <= {str(a) for a in listed}
    assert len(listed) == len(set(listed))
