from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    ts: str
    segment: str
    client_ip: str
    domain: str
    action: str
    score: int
    reasons: list[str]
    sector: str = "unknown"  # Factory-set sector (from sector lock)
    severity: str = "info"   # Elevated to "critical" for hospital IoMT alerts
    trace_id: str = ""
    decision_owner: str = "Policy Engine"
    student_flagged: bool = False      # education sector: client IP matched student subnet
    vpn_block_enforced: bool = False   # education sector: VPN/proxy YARA rule fired
    audit_mode: bool = False           # education/strict-logging sectors: event is audit-tagged


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventWriter:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, ev: Event) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
