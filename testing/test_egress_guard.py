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
