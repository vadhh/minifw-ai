"""Opt-in client-interface DNS guard; IPv6 denial is explicit, not IPv6 inspection.

DoH is blocked only by destination address (listed public resolvers on 443);
unlisted or self-hosted DoH endpoints are not identified."""
import argparse
import ipaddress
import re
import subprocess

DEFAULT_DOH_LIST = "/opt/minifw_ai/config/feeds/doh_resolvers.txt"


def load_doh_list(path):
    """Parse one address per line; '#' comments allowed. Invalid entries raise."""
    addresses = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            addresses.append(ipaddress.ip_address(line))
    return addresses


def render(interface, block_ipv6=False, doh=()):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", interface):
        raise ValueError("An explicit client interface name is required")
    ipv6 = f'iifname "{interface}" meta nfproto ipv6 counter drop' if block_ipv6 else ""
    doh = [ipaddress.ip_address(str(a)) for a in doh]
    doh_rules = []
    for family, version in (("ip", 4), ("ip6", 6)):
        listed = ", ".join(sorted({str(a) for a in doh if a.version == version}))
        if listed:
            doh_rules.append(f'iifname "{interface}" {family} daddr {{ {listed} }} meta l4proto {{ tcp, udp }} th dport 443 counter drop')
    doh_rules = "\n  ".join(doh_rules)
    return f'''table inet minifw_egress {{
 chain dns {{
  type nat hook prerouting priority dstnat; policy accept;
  iifname "{interface}" meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 counter redirect to :53
 }}
 chain forward {{
  type filter hook forward priority -5; policy accept;
  iifname "{interface}" tcp dport 853 counter drop
  iifname "{interface}" udp dport 853 counter drop
  {doh_rules}
  {ipv6}
 }}
}}
'''


def apply(interface, block_ipv6=False, doh=()):
    rules = render(interface, block_ipv6, doh)
    subprocess.run(["ip", "link", "show", "dev", interface], capture_output=True, check=True)
    existing = subprocess.run(["nft", "list", "table", "inet", "minifw_egress"], capture_output=True)
    batch = ("delete table inet minifw_egress\n" if existing.returncode == 0 else "") + rules
    # A single nft transaction preserves the previous rules if replacement fails.
    subprocess.run(["nft", "-f", "-"], input=batch, text=True, capture_output=True, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface")
    parser.add_argument("--block-ipv6", action="store_true")
    parser.add_argument("--doh-list", default=DEFAULT_DOH_LIST,
                        help="resolver addresses to deny on 443; pass an empty string to disable")
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if args.remove:
        subprocess.run(["nft", "delete", "table", "inet", "minifw_egress"], check=True)
    elif args.interface:
        apply(args.interface, args.block_ipv6, load_doh_list(args.doh_list) if args.doh_list else ())
    else:
        parser.error("Supply --interface or --remove")
