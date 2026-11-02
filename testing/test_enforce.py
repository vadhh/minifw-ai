"""
Enforcement Module Tests

Tests enforce.py using mocked subprocess.run to verify:
- ipset_create() issues correct nft commands
- ipset_add() issues correct nft add element commands
- nft_apply_forward_drop() skips rule if already exists
- is_valid_nft_object_name() rejects injection patterns
"""
import subprocess
from unittest.mock import patch, MagicMock, call

import pytest

from minifw_ai.enforce import (
    ipset_create,
    ipset_add,
    nft_apply_forward_drop,
    is_valid_nft_object_name,
)


# ---------------------------------------------------------------------------
# is_valid_nft_object_name()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("minifw_block_v4", True),
    ("minifw", True),
    ("set1", True),
    ("A" * 32, True),
    # Rejections
    ("", False),
    ("A" * 33, False),
    ("has space", False),
    ("has/slash", False),
    ("has;semicolon", False),
    ("has-dash", False),
    ("has.dot", False),
    ("drop; nft flush", False),
    ("../etc/passwd", False),
])
def test_is_valid_nft_object_name(name, expected):
    assert is_valid_nft_object_name(name) == expected


# ---------------------------------------------------------------------------
# ipset_create()
# ---------------------------------------------------------------------------

@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_create_calls_nft_add_table_and_set(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stderr="")

    ipset_create("minifw_block_v4", timeout=86400)

    # First call: add table
    assert mock_run.call_count == 2
    table_call = mock_run.call_args_list[0]
    assert table_call[0][0] == ["nft", "add", "table", "inet", "minifw"]

    # Second call: add set with timeout
    set_call = mock_run.call_args_list[1]
    cmd = set_call[0][0]
    assert "add" in cmd and "set" in cmd
    assert "minifw_block_v4" in cmd
    assert "86400s" in cmd
    assert "timeout" in cmd


@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_create_rejects_invalid_name(mock_run):
    with pytest.raises(ValueError, match="Invalid nftables set name"):
        ipset_create("bad;name", timeout=3600)
    mock_run.assert_not_called()


@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_create_ignores_file_exists_error(mock_run):
    """If the set already exists, the error is silently ignored."""
    mock_run.side_effect = [
        MagicMock(returncode=0),  # add table succeeds
        subprocess.CalledProcessError(1, "nft", stderr="File exists"),
    ]
    # Should NOT raise
    ipset_create("minifw_block_v4", timeout=3600)


# ---------------------------------------------------------------------------
# ipset_add()
# ---------------------------------------------------------------------------

@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_add_calls_nft_add_element(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stderr="")

    mock_run.side_effect = [MagicMock(returncode=1), MagicMock(returncode=0)]
    assert ipset_add("minifw_block_v4", "192.168.1.100", timeout=86400) is True

    cmd = mock_run.call_args[0][0]
    assert "add" in cmd and "element" in cmd
    assert "minifw_block_v4" in cmd
    assert "192.168.1.100" in cmd
    assert "86400s" in cmd


@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_add_rejects_invalid_set_name(mock_run):
    with pytest.raises(ValueError, match="Invalid nftables set name"):
        ipset_add("drop; flush", "10.0.0.1", timeout=3600)
    mock_run.assert_not_called()


@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_add_does_not_refresh_an_existing_block(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    assert ipset_add("minifw_block_v4", "192.168.1.100", timeout=86400) is False
    mock_run.assert_called_once()
    assert mock_run.call_args[0][0][1:3] == ["get", "element"]


@patch("minifw_ai.enforce.subprocess.run")
def test_ipset_add_raises_on_subprocess_error(mock_run):
    mock_run.side_effect = [MagicMock(returncode=1), subprocess.CalledProcessError(
        1, "nft", stderr="some error"
    )]
    with pytest.raises(subprocess.CalledProcessError):
        ipset_add("minifw_block_v4", "10.0.0.1", timeout=3600)


# ---------------------------------------------------------------------------
# nft_apply_forward_drop()
# ---------------------------------------------------------------------------

@patch("minifw_ai.enforce.subprocess.run")
@patch("minifw_ai.enforce.Path.write_text")
def test_nft_apply_forward_drop_adds_rule_when_missing(mock_accounting, mock_run):
    """When the set is NOT in the chain output, the drop rule is added."""
    mock_run.side_effect = [
        MagicMock(returncode=0),  # add table
        MagicMock(returncode=0),  # add chain
        MagicMock(returncode=0),  # ipset_create: add table
        MagicMock(returncode=0, stderr=""),  # ipset_create: add set
        MagicMock(returncode=0, stdout="chain forward {\n}\n"),  # list chain (no rule)
        MagicMock(returncode=0),  # activate conntrack hooks
        MagicMock(returncode=0),  # add rule
    ]

    nft_apply_forward_drop("minifw_block_v4")

    # Last call should be "add rule" with drop
    last_cmd = mock_run.call_args_list[-1][0][0]
    assert "add" in last_cmd and "rule" in last_cmd
    assert "drop" in last_cmd
    assert "@minifw_block_v4" in last_cmd
    assert mock_run.call_args_list[-2][0][0][-6:] == ["ct", "state", "new", "counter", "comment", "MiniFW-AI-Conntrack"]
    mock_accounting.assert_called_once_with("1\n")


@patch("minifw_ai.enforce.subprocess.run")
@patch("minifw_ai.enforce.Path.write_text")
def test_nft_apply_forward_drop_skips_if_rule_exists(mock_accounting, mock_run):
    """When the set IS already in the chain output, no rule is added."""
    mock_run.side_effect = [
        MagicMock(returncode=0),  # add table
        MagicMock(returncode=0),  # add chain
        MagicMock(returncode=0),  # ipset_create: add table
        MagicMock(returncode=0, stderr=""),  # ipset_create: add set
        MagicMock(
            returncode=0,
            stdout='chain forward {\n  ct state new counter comment "MiniFW-AI-Conntrack"\n  ip saddr @minifw_block_v4 drop\n}\n',
        ),  # list chain (rule exists)
    ]

    nft_apply_forward_drop("minifw_block_v4")

    # Should NOT have a 6th call to add the rule
    assert mock_run.call_count == 5


@patch("minifw_ai.enforce.subprocess.run")
@patch("minifw_ai.enforce.Path.write_text")
def test_legacy_drop_rule_also_gets_conntrack_hooks(mock_accounting, mock_run):
    mock_run.side_effect = [MagicMock(returncode=0) for _ in range(4)] + [
        MagicMock(returncode=0, stdout="ip saddr @minifw_block_v4 drop"),
        MagicMock(returncode=0),
    ]
    nft_apply_forward_drop("minifw_block_v4")
    assert mock_run.call_count == 6
    assert mock_run.call_args[0][0][-6:] == ["ct", "state", "new", "counter", "comment", "MiniFW-AI-Conntrack"]


@patch("minifw_ai.enforce.subprocess.run")
def test_nft_apply_forward_drop_rejects_invalid_names(mock_run):
    with pytest.raises(ValueError):
        nft_apply_forward_drop("bad;name")
    mock_run.assert_not_called()
