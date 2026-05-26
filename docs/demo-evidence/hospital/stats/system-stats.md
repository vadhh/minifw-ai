# System Stats — St. Roch Memorial Hospital Demo
**Captured:** 2026-05-26  
**Package:** minifw-usb-hospital-standalone-v2.2.0

---

## Runtime Metrics

| Metric | Value |
|--------|-------|
| CPU (idle, between events) | 0.0% |
| CPU (peak, during block decision) | < 2% |
| RAM (RSS) | ~164 MB |
| Process count | 3 (engine, web, scheduler) |
| Port | 8000 (HTTP) |
| TLS | None (hospital standalone — upgrade path to deb with TLS) |

## Event Counters (after full dual-attack demo run)

| Counter | Value |
|---------|-------|
| Total events | ~28 |
| Allow | ~20 |
| Monitor | ~6 |
| Block | 2 |
| False positives | 0 |

## HIPAA Audit Trail

Both block events carry:
- `trace_id`: `HIPAA-PHI-*` format — unique per decision
- `decision_owner`: `HIPAA Compliance Engine`
- `sector`: `hospital`
- Full reasons array documenting every contributing signal

These fields are written to `logs/events.jsonl` as structured JSONL.
Any SIEM that ingests JSONL can parse them directly.

## Deployment Footprint

| Item | Value |
|------|-------|
| Package size (with venv) | ~380 MB |
| Database (SQLite) | < 1 MB |
| Log file (full demo run) | ~50 KB |
| Startup time (fresh machine) | 25–40 seconds |
| Reset time (fast_reset.sh) | 8–15 seconds |
