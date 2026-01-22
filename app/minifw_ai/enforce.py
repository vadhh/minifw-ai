from __future__ import annotations
import subprocess

# -------------------------------------------------------------------------
# PURE NFTABLES IMPLEMENTATION
# Replaces legacy 'ipset' commands with native 'nft' named sets
# -------------------------------------------------------------------------

def ipset_create(set_name: str, timeout: int) -> None:
    """
    Creates a native nftables set in the 'inet filter' table.
    We enable the 'timeout' flag so IPs can expire automatically.
    """
    # 1. Ensure the table exists
    subprocess.run(["nft", "add", "table", "inet", "filter"], check=False)

    # 2. Create the named set
    # Syntax: nft add set inet filter <name> { type ipv4_addr; flags timeout; }
    cmd = [
        "nft", "add", "set", "inet", "filter", set_name,
        "{", 
        "type", "ipv4_addr", ";", 
        "flags", "timeout", ";",
        "timeout", f"{timeout}s", ";", # Default timeout
        "}"
    ]
    subprocess.run(cmd, check=False)

def ipset_add(set_name: str, ip: str, timeout: int) -> None:
    """
    Adds an IP to the native nftables set.
    """
    # Syntax: nft add element inet filter <name> { 1.2.3.4 timeout 60s }
    cmd = [
        "nft", "add", "element", "inet", "filter", set_name,
        "{", ip, "timeout", f"{timeout}s", "}"
    ]
    subprocess.run(cmd, check=False)

def nft_apply_forward_drop(set_name: str, table: str = "inet", chain: str = "forward") -> None:
    """
    Creates the firewall rule that drops traffic from IPs in the set.
    """
    # 1. Ensure table and chain exist
    subprocess.run(["nft", "add", "table", table, "filter"], check=False)
    subprocess.run([
        "nft", "add", "chain", table, "filter", chain,
        "{", "type", "filter", "hook", chain, "priority", "0", ";", "policy", "accept", ";", "}"
    ], check=False)

    # 2. Ensure the set exists before we reference it
    # (We assume default timeout of 3600 if creating lazily)
    ipset_create(set_name, 3600)

    # 3. Check if the rule already exists
    out = subprocess.run(
        ["nft", "list", "chain", table, "filter", chain], 
        capture_output=True, text=True, check=False
    ).stdout

    # 4. Add the rule if missing
    if f"@{set_name}" not in out:
        subprocess.run([
            "nft", "add", "rule", table, "filter", chain,
            "ip", "saddr", f"@{set_name}", "drop",
            "comment", "MiniFW-AI-Blocklist" # No spaces allowed in comment!
        ], check=False)