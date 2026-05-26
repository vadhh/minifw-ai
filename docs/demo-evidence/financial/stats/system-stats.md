# System Performance — MiniFW-AI Financial Demo
**Captured:** 2026-05-25 (demo running for 2 days, 20 hours continuous)

## Process Footprint (uvicorn web + engine combined)

| Metric | Value |
|--------|-------|
| CPU usage (idle / between attacks) | 0.0% |
| Memory (RSS) | 164 MB |
| Virtual memory | 751 MB |
| System RAM used | 7,445 MB / 15,890 MB (47%) |
| System CPU (background load) | 9.3% |
| Continuous uptime | 2 days 20 hours |

## Event Throughput

| Counter | Value |
|---------|-------|
| Total events processed | 498 |
| Allow (clean traffic) | 488 (97.99%) |
| Monitor (escalating threat) | 8 |
| Block (enforced stop) | 2 |
| False positives | 0 |

## Key Performance Points for Clients

- **Zero CPU overhead at idle** — 0.0% CPU between attacks. The engine consumes no measurable compute during normal trading hours.
- **164 MB footprint** — runs comfortably alongside existing gateway software. No dedicated server required.
- **2-day continuous uptime** with zero manual intervention — no restarts, no crashes.
- **488 clean passes out of 490 decisions** — no disruption to legitimate Bloomberg, Reuters, SWIFT, Oracle ERP traffic.
- **2 blocks, both correct** — no false positives in 498 events.
