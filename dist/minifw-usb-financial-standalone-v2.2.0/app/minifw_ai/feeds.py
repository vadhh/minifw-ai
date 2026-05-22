from __future__ import annotations
from pathlib import Path
import fnmatch
import logging
import time

logger = logging.getLogger(__name__)

# Core feed files watched for hot-reload
_WATCHED_FILES = ("deny_domains.txt", "allow_domains.txt", "deny_ips.txt", "deny_asn.txt")


class FeedMatcher:
    def __init__(self, feeds_dir: str):
        self.feeds_dir = Path(feeds_dir)
        self._load_core_feeds()
        self._mtimes: dict[str, float] = self._snapshot_mtimes()
        self._last_reload_check: float = time.monotonic()

    def _load_core_feeds(self) -> None:
        self.deny_domains = self._load_lines(self.feeds_dir / "deny_domains.txt")
        self.allow_domains = self._load_lines(self.feeds_dir / "allow_domains.txt")
        self.deny_ips = set(self._load_lines(self.feeds_dir / "deny_ips.txt"))
        self.deny_asn = set(self._load_lines(self.feeds_dir / "deny_asn.txt"))

    def _snapshot_mtimes(self) -> dict[str, float]:
        mtimes = {}
        for name in _WATCHED_FILES:
            p = self.feeds_dir / name
            try:
                mtimes[name] = p.stat().st_mtime if p.exists() else 0.0
            except OSError:
                mtimes[name] = 0.0
        return mtimes

    def reload_if_changed(self, interval: float = 5.0) -> bool:
        """
        Check every `interval` seconds whether any core feed file has changed.
        If so, reload all core feeds and return True. Called from the engine loop.
        """
        now = time.monotonic()
        if now - self._last_reload_check < interval:
            return False
        self._last_reload_check = now

        current = self._snapshot_mtimes()
        if current == self._mtimes:
            return False

        changed = [k for k in _WATCHED_FILES if current.get(k) != self._mtimes.get(k)]
        self._load_core_feeds()
        self._mtimes = current
        logger.info(f"[FEEDS] Hot-reloaded: {', '.join(changed)}")
        return True

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

    def load_sector_feeds(self, extra_feeds: list[str]) -> int:
        """
        Load additional sector-specific feeds into deny_domains.

        Args:
            extra_feeds: List of feed filenames (e.g., ["school_blacklist.txt"])

        Returns:
            Number of new patterns loaded
        """
        loaded_count = 0
        for feed_name in extra_feeds:
            feed_path = self.feeds_dir / feed_name
            if feed_path.exists():
                patterns = self._load_lines(feed_path)
                self.deny_domains.extend(patterns)
                loaded_count += len(patterns)
                logger.info(f"[FEEDS] Loaded {len(patterns)} patterns from {feed_name}")
            else:
                logger.warning(f"[FEEDS] Sector feed not found: {feed_path}")
        return loaded_count

    def domain_allowed(self, domain: str) -> bool:
        return any(fnmatch.fnmatch(domain, pat) for pat in self.allow_domains)

    def domain_denied(self, domain: str) -> bool:
        return any(fnmatch.fnmatch(domain, pat) for pat in self.deny_domains)

    def ip_denied(self, ip: str) -> bool:
        return ip in self.deny_ips

    def load_tor_exits(self, path: str | Path) -> int:
        """
        Load Tor exit node IPs into deny_ips.

        Args:
            path: Path to tor_exit_nodes.txt (one IP per line)

        Returns:
            Number of IPs loaded
        """
        path = Path(path)
        ips = self._load_lines(path)
        new_ips = set(ips) - self.deny_ips
        self.deny_ips.update(new_ips)
        logger.info(f"[FEEDS] Loaded {len(new_ips)} Tor exit node IPs from {path}")
        return len(new_ips)

    def asn_denied(self, asn: str) -> bool:
        return asn in self.deny_asn
