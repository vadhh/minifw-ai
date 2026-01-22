from __future__ import annotations
from pathlib import Path
import fnmatch

class FeedMatcher:
    def __init__(self, feeds_dir: str):
        d = Path(feeds_dir)
        self.deny_domains = self._load_lines(d / "deny_domains.txt")
        self.allow_domains = self._load_lines(d / "allow_domains.txt")
        self.deny_ips = set(self._load_lines(d / "deny_ips.txt"))
        self.deny_asn = set(self._load_lines(d / "deny_asn.txt"))

    @staticmethod
    def _load_lines(path: Path) -> list[str]:
        if not path.exists():
            return []
        lines: list[str] = []
        for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            lines.append(ln)
        return lines

    def domain_allowed(self, domain: str) -> bool:
        return any(fnmatch.fnmatch(domain, pat) for pat in self.allow_domains)

    def domain_denied(self, domain: str) -> bool:
        return any(fnmatch.fnmatch(domain, pat) for pat in self.deny_domains)

    def ip_denied(self, ip: str) -> bool:
        return ip in self.deny_ips

    def asn_denied(self, asn: str) -> bool:
        return asn in self.deny_asn
