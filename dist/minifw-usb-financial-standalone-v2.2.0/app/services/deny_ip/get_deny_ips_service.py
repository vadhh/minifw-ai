from pathlib import Path
import threading

BASE_DIR = Path(__file__).resolve().parents[3]
DENY_IP_FILE = BASE_DIR / "config" / "feeds" / "deny_ips.txt"

_lock = threading.Lock()
_mtime: float = -1.0
_cache: list = []


def get_deny_ips():
    global _mtime, _cache
    if not DENY_IP_FILE.exists():
        return []
    try:
        current_mtime = DENY_IP_FILE.stat().st_mtime
    except OSError:
        return []
    with _lock:
        if current_mtime != _mtime:
            with DENY_IP_FILE.open("r") as f:
                _cache = [
                    {"ip": ln.strip()}
                    for ln in f
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            _mtime = current_mtime
        return list(_cache)
