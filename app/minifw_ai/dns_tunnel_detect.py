"""
DNS Tunneling Detection

Detects DNS tunneling by analyzing:
1. Subdomain label entropy (base64/hex encoded data has high entropy)
2. Abnormally long subdomain labels (>30 chars per label)
3. High query rate to same base domain with varying subdomains
4. Total domain length (tunneling domains often exceed 100 chars)

Returns a tunnel score 0-100 and list of reasons.
"""
from __future__ import annotations

import math
from collections import OrderedDict, deque
import time


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per char)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _extract_subdomain_labels(domain: str) -> list[str]:
    """Extract subdomain labels (everything except TLD and base domain).

    e.g. "abc.def.example.com" -> ["abc", "def"]
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return []
    return parts[:-2]


def _base_domain(domain: str) -> str:
    """Extract base domain (last 2 labels)."""
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def analyze_domain_tunneling(domain: str) -> tuple[int, list[str]]:
    """Analyze a single domain for tunneling indicators.

    Returns:
        (score, reasons) where score is 0-100
    """
    if not domain:
        return 0, []

    score = 0
    reasons = []
    labels = _extract_subdomain_labels(domain)

    if not labels:
        return 0, []

    subdomain_str = ".".join(labels)

    # Check 1: Total domain length (tunneling payloads are long)
    if len(domain) > 150:
        score += 40
        reasons.append("dns_tunnel_extreme_length")
    elif len(domain) > 100:
        score += 25
        reasons.append("dns_tunnel_long_domain")

    # Check 2: Long individual labels (normal labels are <20 chars)
    max_label_len = max(len(label) for label in labels) if labels else 0
    if max_label_len > 50:
        score += 35
        reasons.append("dns_tunnel_long_label")
    elif max_label_len > 30:
        score += 20
        reasons.append("dns_tunnel_suspicious_label_length")

    # Check 3: High entropy in subdomain (encoded data)
    entropy = _shannon_entropy(subdomain_str)
    if entropy > 4.5:
        score += 35
        reasons.append(f"dns_tunnel_high_entropy_{entropy:.1f}")
    elif entropy > 3.8:
        score += 15
        reasons.append(f"dns_tunnel_elevated_entropy_{entropy:.1f}")

    # Check 4: Many subdomain labels (deep nesting)
    if len(labels) > 5:
        score += 15
        reasons.append("dns_tunnel_deep_nesting")

    # Check 5: Numeric/hex-heavy labels (base16/base32/base64 encoding)
    digit_ratio = sum(1 for c in subdomain_str if c.isdigit() or c in "abcdef") / max(len(subdomain_str), 1)
    if digit_ratio > 0.7 and len(subdomain_str) > 20:
        score += 20
        reasons.append("dns_tunnel_encoded_payload")

    return min(score, 100), reasons


class TunnelTracker:
    """Track per-base-domain query diversity to detect sustained tunneling.

    Detects: same base domain queried with many different subdomains in a
    short window (classic tunneling pattern).
    """

    def __init__(self, window_seconds: int = 300, max_entries: int = 5000):
        self.window = window_seconds
        self.max_entries = max_entries
        # base_domain -> deque of (timestamp, subdomain_hash)
        self._queries: OrderedDict[str, deque] = OrderedDict()

    def record_query(self, domain: str) -> int:
        """Record a query and return unique subdomain count for this base domain."""
        base = _base_domain(domain)
        labels = _extract_subdomain_labels(domain)
        if not labels:
            return 0

        subdomain = ".".join(labels)
        now = time.time()

        if base not in self._queries:
            if len(self._queries) >= self.max_entries:
                self._queries.popitem(last=False)
            self._queries[base] = deque(maxlen=500)
        else:
            self._queries.move_to_end(base)

        dq = self._queries[base]
        dq.append((now, subdomain))

        # Prune old entries
        while dq and (now - dq[0][0]) > self.window:
            dq.popleft()

        # Count unique subdomains in window
        unique_subs = len(set(sub for _, sub in dq))
        return unique_subs

    def check_sustained_tunneling(self, domain: str, threshold: int = 20) -> tuple[bool, int]:
        """Check if base domain shows sustained tunneling pattern.

        Returns (is_tunneling, unique_subdomain_count).
        """
        unique = self.record_query(domain)
        return unique >= threshold, unique
