# MiniFW-AI Financial Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** ArborCrest Capital dual-attacker simulation  
**Evidence captured:** 2026-05-22 (log data) + 2026-05-25 (system stats)

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/evidence-report.md` | **Main document.** Sales/LinkedIn/PDF-ready. Before → During → After with raw logs and key numbers. |
| `logs/score-timeline.md` | Human-readable attack timeline with ASCII score bars. Good for technical buyers. |
| `logs/normal-traffic-sample.jsonl` | 10 raw JSON events from clean baseline. Proves zero false positives. |
| `logs/attack-sequence.jsonl` | Full 10-event attack chain from both attackers. |
| `logs/block-events.jsonl` | 2 raw block decisions. Ready to paste into a client email or deck. |
| `stats/system-stats.md` | CPU / RAM / uptime numbers. Proves low overhead. |
| `screenshots/CAPTURE_GUIDE.md` | Step-by-step guide: 7 screenshots to take, when to take them, what to caption. |
| `screenshots/*.png` | *(Capture during next demo run — see CAPTURE_GUIDE.md)* |

---

## Quick Use

**For a LinkedIn post:** Use `report/evidence-report.md` — pull the "Key Numbers" table and one of the block events (raw JSON). Add screenshot 4 or 5.

**For a client email:** Attach `report/evidence-report.md` as a PDF. Paste the block events table inline.

**For a technical buyer:** Show `logs/score-timeline.md` — the ASCII score bars are readable without a dashboard.

**For a compliance officer:** Show the block events JSON — `decision_owner: "PCI-DSS Policy Engine"` and the `SWIFT-MT103-*` trace IDs speak directly to audit requirements.

---

## Completing the Pack

Screenshots are the only remaining gap. Run the demo and follow `screenshots/CAPTURE_GUIDE.md`. 7 screenshots, takes about 3 minutes.
