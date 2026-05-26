# MiniFW-AI Establishment Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** Crown Hotel Group — office monitors + guest WiFi instant blocks
**Evidence captured:** 2026-05-26

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/architecture-establishment.svg` | **Architecture diagram.** 1200×820 visual — network segments, scoring pipeline, policy decision, dashboard mock. |
| `report/evidence-report.md` | **Main document.** Dual-threshold architecture explained with raw block JSON. |
| `logs/score-timeline.md` | Timeline showing score 40 = MONITOR on office, score 40 = BLOCK on guest. |
| `logs/block-events.jsonl` | 2 guest WiFi block decisions with SME-EST trace IDs. |

---

## The One-Number Story

**Score 40 on office → MONITOR.  
Score 40 on guest → BLOCK.**

Same score. Same engine. Different segment policy. This is the establishment story.

## Use Cases

**For an SME owner:** `report/evidence-report.md` — lead with the guest WiFi block story, then explain what happens to the office events (monitored, not blocked, staff kept working).

**For an IT manager:** `logs/score-timeline.md` — shows all four office monitors and explains why none of them triggered a block. Then shows the guest WiFi blocks at score 40.

**For an insurance broker:** The SME-EST trace IDs in `logs/block-events.jsonl` are the contemporaneous evidence that the business acted immediately on a threat. Timestamped, logged, auditable.
