#!/usr/bin/env python3
"""Bridge Velociraptor endpoint telemetry into the minifw-ai events view.

Velociraptor writes its client monitoring results as line-delimited JSON in the
server datastore. The dashboard already reads Event-shaped JSONL from MINIFW_LOG
(app/services/events/get_events_service.py), so the whole integration is a
translation of one JSONL shape into another -- no new table, router, or template.

    python tools/endpoint_bridge.py --source /var/tmp/velociraptor --once

ponytail: file-tail bridge, not a Velociraptor API client. The datastore is
already JSONL on disk; polling it costs one stat() per tick. Move to the gRPC
API only if you need server-side event streaming (multi-org, or offline hosts).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402

# Velociraptor RSS beyond this is worth surfacing; the agent idles near 90 MB
# and climbs to ~290 MB during a hash sweep (measured, 2.1 GB / 20k-file corpus).
RSS_WARN_BYTES = 400 * 1024 * 1024


def _iso(epoch: float) -> str:
    if not epoch:
        return now_iso()
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()


def stats_to_event(row: dict, sector: str) -> Event | None:
    """Generic.Client.Stats -> agent health event. None when nothing is notable."""
    rss = row.get("RSS") or 0
    if rss < RSS_WARN_BYTES:
        return None
    client = row.get("ClientId") or row.get("_Source") or "unknown"
    return Event(
        ts=_iso(row.get("Timestamp")),
        segment="endpoint",
        client_ip=client,
        domain="agent.resource",
        action="monitor",
        score=20,
        reasons=[f"Endpoint agent RSS {rss // (1024 * 1024)} MB exceeds {RSS_WARN_BYTES // (1024 * 1024)} MB"],
        sector=sector,
        severity="warning",
        decision_owner="Endpoint Agent",
    )


def flow_to_event(row: dict, sector: str) -> Event | None:
    """System.Flow.Completion -> one informational event per completed collection.

    Deliberately action="allow" with no reasons: get_events_service marks an
    event as threat_detected when score>0, action!="allow", OR reasons is
    non-empty, and those feed the dashboard's threat counters. A collection
    finishing normally is not a threat, so it must not inflate them. The
    artifact name still lands in `domain`, so the row stays identifiable.
    """
    flow = row.get("Flow") or {}
    artifacts = flow.get("artifacts_with_results") or []
    if not artifacts:
        return None
    return Event(
        ts=_iso(row.get("Timestamp")),
        segment="endpoint",
        client_ip=flow.get("client_id", "unknown"),
        domain=artifacts[0],
        action="allow",
        score=0,
        reasons=[],
        sector=sector,
        severity="info",
        decision_owner="Endpoint Agent",
    )


# Which monitoring artifact maps through which translator.
HANDLERS = {
    "Generic.Client.Stats": stats_to_event,
    "System.Flow.Completion": flow_to_event,
}


def iter_new_rows(path: Path, offset: int):
    """Yield parsed JSON rows from `offset`, returning the new offset."""
    rows = []
    with path.open("r", encoding="utf-8") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # partial line: re-read next tick
        return rows, f.tell()


def scan_once(source: Path, writer: EventWriter, offsets: dict, sector: str) -> int:
    written = 0
    for artifact, handler in HANDLERS.items():
        for path in source.glob(f"clients/*/monitoring/{artifact}/*.json"):
            key = str(path)
            rows, new_offset = iter_new_rows(path, offsets.get(key, 0))
            offsets[key] = new_offset
            for row in rows:
                event = handler(row, sector)
                if event is not None:
                    writer.write(event)
                    written += 1
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True, help="Velociraptor datastore root")
    ap.add_argument("--out", default=os.environ.get("MINIFW_LOG", "logs/events.jsonl"))
    ap.add_argument("--sector", default=os.environ.get("MINIFW_SECTOR", "unknown"))
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--once", action="store_true", help="single pass, then exit")
    args = ap.parse_args()

    source = Path(args.source)
    if not source.is_dir():
        print(f"source not found: {source}", file=sys.stderr)
        return 1

    writer = EventWriter(args.out)
    offsets: dict[str, int] = {}

    while True:
        written = scan_once(source, writer, offsets, args.sector)
        print(f"wrote {written} event(s) -> {args.out}", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
