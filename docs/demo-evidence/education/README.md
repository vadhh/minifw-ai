# MiniFW-AI Education Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** Westgate Academy — student VPN bypass + guest content filter evasion  
**Evidence captured:** 2026-05-26

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/architecture-education.svg` | **Architecture diagram.** 1200×820 visual — network segments, scoring pipeline, policy decision, dashboard mock. |
| `report/evidence-report.md` | **Main document.** Sales/LinkedIn/PDF-ready. Three blocks with raw JSON and key numbers. |
| `logs/score-timeline.md` | Human-readable event timeline with ASCII score bars. Good for IT managers and safeguarding leads. |
| `logs/normal-traffic-sample.jsonl` | 7 raw JSON allow events from clean educational baseline. |
| `logs/attack-sequence.jsonl` | Full event sequence — monitors through all three blocks. |
| `logs/block-events.jsonl` | 3 raw block decisions with EDU-SAFE trace IDs. |
| `stats/system-stats.md` | Container count, CPU, RAM, event counters, loop behavior. |
| `screenshots/CAPTURE_GUIDE.md` | 10-screenshot index with per-audience usage recommendations. |
| `screenshots/*.png` | *(Capture during demo run — see CAPTURE_GUIDE.md)* |

---

## Quick Use

**For a LinkedIn post:** Pull the VPN bypass block JSON from `logs/block-events.jsonl`. Add screenshot 04.

**For a safeguarding lead:** Show `logs/score-timeline.md` — the threshold story (student 70 vs guest 60) is clear in the ASCII bars. Then show the block events JSON with trace IDs.

**For a MAT director:** Use `report/evidence-report.md` — the "Key Numbers" table and the "What This Proves" section frame it at the right level.

**For an IT manager:** Show `07-detail-BLOCK2-guest-content-filter.png` — segment-aware policy, same AI engine, different thresholds, no manual per-device config.

---

## The Threshold Story

- Student network blocks at **70** — stricter than staff, reflects the safeguarding requirement
- Guest WiFi blocks at **60** — tightest threshold, least information about who's on it
- Staff blocks at **80** — standard corporate threshold

Same AI engine. Three simultaneous policies. No additional hardware.
