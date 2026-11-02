from __future__ import annotations
import subprocess
import logging
import re
import ipaddress
from pathlib import Path


def is_valid_nft_object_name(name: str) -> bool:
    """Only allows alphanumeric chars and underscores, max 32 chars."""
    return re.match(r"^[a-zA-Z0-9_]{1,32}$", name) is not None


def ipset_create(
    set_name: str,
    timeout: int,
    family: str = "inet",
    table_name: str = "minifw",
) -> None:
    """
    Creates a native nftables set in the dedicated minifw table (default).
    We enable the 'timeout' flag so IPs can expire automatically.
    """
    if not is_valid_nft_object_name(set_name):
        raise ValueError(f"Invalid nftables set name: {set_name}")

    try:
        # 1. Ensure the table exists
        subprocess.run(
            ["nft", "add", "table", family, table_name], check=False
        )  # This can fail benignly if it exists

        # 2. Create the named set
        cmd = [
            "nft",
            "add",
            "set",
            family,
            table_name,
            set_name,
            "{",
            "type",
            "ipv4_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "timeout",
            f"{timeout}s",
            ";",
            "}",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        # Avoid logging if the set already exists, which is a common, benign error
        if "File exists" not in e.stderr:
            logging.error(f"Failed to create nft set '{set_name}': {e.stderr}")
            raise


def ipset_add(
    set_name: str,
    ip: str,
    timeout: int,
    family: str = "inet",
    table_name: str = "minifw",
) -> bool:
    """
    Adds an IP to the native nftables set.
    """
    if not is_valid_nft_object_name(set_name):
        raise ValueError(f"Invalid nftables set name: {set_name}")
    ipaddress.IPv4Address(ip)
    if not all(is_valid_nft_object_name(name) for name in (family, table_name)):
        raise ValueError("Invalid nftables family/table")

    present = subprocess.run(
        ["nft", "get", "element", family, table_name, set_name, "{", ip, "}"],
        capture_output=True, text=True,
    )
    if present.returncode == 0:
        return False

    try:
        cmd = [
            "nft",
            "add",
            "element",
            family,
            table_name,
            set_name,
            "{",
            ip,
            "timeout",
            f"{timeout}s",
            "}",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to add IP {ip} to nft set '{set_name}': {e.stderr}")
        raise


def nft_apply_forward_drop(
    set_name: str,
    table: str = "inet",
    table_name: str = "minifw",
    chain: str = "forward",
) -> None:
    """
    Creates the firewall rule that drops traffic from IPs in the set.
    Uses a dedicated table (default: minifw) to avoid conflicts with
    other firewall managers (e.g. ARCHANGEL) that may flush inet filter.
    """
    if (
        not is_valid_nft_object_name(set_name)
        or not is_valid_nft_object_name(table)
        or not is_valid_nft_object_name(table_name)
        or not is_valid_nft_object_name(chain)
    ):
        raise ValueError(
            f"Invalid nftables object name provided: table='{table}', table_name='{table_name}', chain='{chain}', set='{set_name}'"
        )

    try:
        # 1. Ensure table and chain exist
        subprocess.run(["nft", "add", "table", table, table_name], check=False)
        subprocess.run(
            [
                "nft",
                "add",
                "chain",
                table,
                table_name,
                chain,
                "{",
                "type",
                "filter",
                "hook",
                chain,
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            check=False,
        )  # Can fail benignly if it exists

        # 2. Ensure the set exists before we reference it
        ipset_create(set_name, 3600, family=table, table_name=table_name)

        # 3. Check if the rule already exists
        result = subprocess.run(
            ["nft", "list", "chain", table, table_name, chain],
            capture_output=True,
            text=True,
            check=True,
        )
        out = result.stdout

        # A loaded module alone does not activate conntrack hooks in a fresh network namespace.
        if "MiniFW-AI-Conntrack" not in out:
            subprocess.run(
                ["nft", "add", "rule", table, table_name, chain, "ct", "state", "new",
                 "counter", "comment", "MiniFW-AI-Conntrack"],
                check=True, capture_output=True, text=True,
            )
        try:
            Path("/proc/sys/net/netfilter/nf_conntrack_acct").write_text("1\n")
        except OSError:
            logging.warning("[FLOW] Conntrack accounting unavailable; packet/byte rate features require measured counters")

        # 4. Add the rule if missing
        if f"@{set_name}" not in out:
            subprocess.run(
                [
                    "nft",
                    "add",
                    "rule",
                    table,
                    table_name,
                    chain,
                    "ip",
                    "saddr",
                    f"@{set_name}",
                    "counter",
                    "drop",
                    "comment",
                    "MiniFW-AI-Blocklist",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    except subprocess.CalledProcessError as e:
        if "File exists" not in e.stderr:
            logging.error(f"Failed to apply nftables drop rule: {e.stderr}")
            raise
    except ValueError as e:
        logging.error(f"Validation error in nft_apply_forward_drop: {e}")
        raise
