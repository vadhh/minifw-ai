from __future__ import annotations
import time
from pathlib import Path
from typing import Iterator, Tuple, Optional

def tail_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.strip()

def parse_dnsmasq(line: str) -> Optional[Tuple[str, str]]:
    if " query[" not in line or " from " not in line:
        return None
    try:
        right = line.split(" query[", 1)[1]
        domain = right.split("] ", 1)[1].split(" ", 1)[0].strip()
        client_ip = line.rsplit(" from ", 1)[1].strip()
        return client_ip, domain
    except Exception:
        return None

def stream_dns_events(log_path: str):
    p = Path(log_path)
    if not p.exists():
        raise FileNotFoundError(f"Missing dnsmasq log: {p}")
    for ln in tail_lines(p):
        evt = parse_dnsmasq(ln)
        if evt:
            yield evt
