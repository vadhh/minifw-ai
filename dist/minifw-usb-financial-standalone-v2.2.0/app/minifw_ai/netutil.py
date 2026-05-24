from __future__ import annotations
import ipaddress
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def ip_in_any_subnet(ip: str, cidrs: list[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


class ASNResolver:
    """Resolve IP addresses to ASN strings using a local prefix map.

    The prefix file format is one entry per line:
        <CIDR> <ASN>
    Example:
        8.8.8.0/24 AS15169
        1.1.1.0/24 AS13335

    Lines starting with # are comments. Empty lines are skipped.
    """

    def __init__(self) -> None:
        # List of (network, asn_string) sorted by prefix length descending
        # for longest-prefix-match semantics.
        self._prefixes: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []

    def load(self, path: str | Path) -> int:
        """Load prefix-to-ASN mappings from a file.

        Returns the number of prefixes loaded.
        """
        p = Path(path)
        if not p.exists():
            logger.info("[ASN] Prefix file not found: %s — ASN lookup disabled", path)
            return 0

        count = 0
        for line_no, line in enumerate(
            p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
        ):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                logger.debug("[ASN] Skipping malformed line %d: %s", line_no, line)
                continue
            cidr, asn = parts
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                logger.debug("[ASN] Invalid CIDR on line %d: %s", line_no, cidr)
                continue
            self._prefixes.append((network, asn.strip()))
            count += 1

        # Sort by prefix length descending for longest-match-first
        self._prefixes.sort(key=lambda x: x[0].prefixlen, reverse=True)
        logger.info("[ASN] Loaded %d prefix-to-ASN mappings from %s", count, path)
        return count

    def lookup(self, ip: str) -> Optional[str]:
        """Resolve an IP address to its ASN string, or None if not found."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, asn in self._prefixes:
            if ip_obj in network:
                return asn
        return None

    @property
    def loaded(self) -> bool:
        return len(self._prefixes) > 0
