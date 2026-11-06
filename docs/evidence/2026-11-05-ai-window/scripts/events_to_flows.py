"""Held-out adapter: the shipped conntrack collector never exports short connections to flows.jsonl
(export needs pkt_count >= 5), but the engine writes an event at every observation, and C20 counts a
connection at its first observation (FlowTracker is_new). This turns each TCP 5-tuple's FIRST flow event
into one flows.jsonl record (timestamp = that event time, i.e. when the runtime would count it), so the
frozen evaluate_window_model.py can be run unchanged. Format conversion only; no labels or thresholds.

Usage: python3 -I events_to_flows.py <heldout-run-dir> <output-dir>
"""
import gzip
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
first = {}
with gzip.open(src / "events.jsonl.gz", "rt") as f:
    for line in f:
        e = json.loads(line)
        if e.get("telemetry_source") != "flow" or e.get("proto") != "tcp" or not e.get("src_port"):
            continue
        key = (e["client_ip"], e["dst_ip"], e["dst_port"], e["src_port"], "tcp")
        t = datetime.fromisoformat(e["ts"]).timestamp()
        if key not in first or t < first[key]:
            first[key] = t
with (out / "flows.jsonl").open("w") as f:
    for (client_ip, dst_ip, dst_port, src_port, proto), t in sorted(first.items(), key=lambda kv: kv[1]):
        f.write(json.dumps(dict(client_ip=client_ip, dst_ip=dst_ip, dst_port=dst_port, src_port=src_port,
                                proto=proto, timestamp=t)) + "\n")
for actor in src.glob("actor-*.jsonl"):
    shutil.copy(actor, out / actor.name)
print(f"{src.name}: {len(first)} TCP connections from first flow events -> {out / 'flows.jsonl'}")
