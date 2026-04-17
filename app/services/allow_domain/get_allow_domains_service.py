from pathlib import Path
import threading

BASE_DIR = Path(__file__).resolve().parents[3]
ALLOW_DOMAIN_FILE = BASE_DIR / "config" / "feeds" / "allow_domains.txt"

_lock = threading.Lock()
_mtime: float = -1.0
_cache: list = []


def get_allow_domains():
    global _mtime, _cache
    if not ALLOW_DOMAIN_FILE.exists():
        return []
    try:
        current_mtime = ALLOW_DOMAIN_FILE.stat().st_mtime
    except OSError:
        return []
    with _lock:
        if current_mtime != _mtime:
            with ALLOW_DOMAIN_FILE.open("r") as f:
                _cache = [{"name": ln.strip()} for ln in f if ln.strip()]
            _mtime = current_mtime
        return list(_cache)
