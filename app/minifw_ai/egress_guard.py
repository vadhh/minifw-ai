"""Opt-in client-interface DNS guard; IPv6 denial is explicit, not IPv6 inspection."""
import argparse
import re
import subprocess


def render(interface, block_ipv6=False):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", interface):
        raise ValueError("An explicit client interface name is required")
    ipv6 = f'iifname "{interface}" meta nfproto ipv6 counter drop' if block_ipv6 else ""
    return f'''table inet minifw_egress {{
 chain dns {{
  type nat hook prerouting priority dstnat; policy accept;
  iifname "{interface}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :53
 }}
 chain forward {{
  type filter hook forward priority -5; policy accept;
  iifname "{interface}" tcp dport 853 counter drop
  iifname "{interface}" udp dport 853 counter drop
  {ipv6}
 }}
}}
'''


def apply(interface, block_ipv6=False):
    rules = render(interface, block_ipv6)
    subprocess.run(["ip", "link", "show", "dev", interface], capture_output=True, check=True)
    existing = subprocess.run(["nft", "list", "table", "inet", "minifw_egress"], capture_output=True)
    batch = ("delete table inet minifw_egress\n" if existing.returncode == 0 else "") + rules
    # A single nft transaction preserves the previous rules if replacement fails.
    subprocess.run(["nft", "-f", "-"], input=batch, text=True, capture_output=True, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface")
    parser.add_argument("--block-ipv6", action="store_true")
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if args.remove:
        subprocess.run(["nft", "delete", "table", "inet", "minifw_egress"], check=True)
    elif args.interface:
        apply(args.interface, args.block_ipv6)
    else:
        parser.error("Supply --interface or --remove")
