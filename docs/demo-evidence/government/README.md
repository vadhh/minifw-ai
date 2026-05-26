# MiniFW-AI Government Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** National sovereign infrastructure — APT28 C2 + Tor relay blocked
**Evidence captured:** 2026-05-26

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/architecture-government.svg` | **Architecture diagram.** 1200×820 visual — network segments, scoring pipeline, policy decision, dashboard mock. |
| `report/evidence-report.md` | **Main document.** Before/during/after with raw block JSON. Includes near-miss analysis. |
| `logs/score-timeline.md` | Timeline with ASCII score bars. Near miss vs monitor vs block clearly shown. |
| `logs/normal-traffic-sample.jsonl` | 5 sovereign allow events from clean baseline. |
| `logs/block-events.jsonl` | 3 raw block decisions with GOV-SOV trace IDs. |
| `stats/system-stats.md` | Government-specific policy differences vs other sectors. |
| `screenshots/CAPTURE_GUIDE.md` | 9-screenshot index with per-audience usage. |

---

## Quick Use

**For a CISO:** Show the `logs/score-timeline.md` — the near-miss story (score 40, threshold 45) is the most useful conversation starter. Then show the APT28 block.

**For a Permanent Secretary / DG:** Pull the "Key Numbers" from `report/evidence-report.md`. Lead with "C2 confirmation never received by attacker" — that's the headline.

**For a procurement review:** `04-events-BLOCK1-apt28-c2-score75.png` + `09-events-sustained-3blocks-clean.png`. Two images, tells the whole story.

**For an incident review board:** The block JSON in `logs/block-events.jsonl` — timestamped, scored, auditable. Use the GOV-SOV trace IDs as the correlation key.

---

## The Classified Threshold Story

**70** — classified segment block threshold  
**75** — internal block threshold  
**5-point delta** — the risk budget difference between classified and internal operations

On a classified network, a score of 70 is sufficient evidence to block. On the internal
network, you need 75. This is policy, not a default. Adjustable in policy.json.
