# MiniFW-AI Hospital Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** St. Roch Memorial Hospital dual-attack simulation  
**Evidence captured:** 2026-05-26

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/evidence-report.md` | **Main document.** Sales/LinkedIn/PDF-ready. Before → During → After with raw block JSON and key numbers. |
| `logs/score-timeline.md` | Human-readable attack timeline with ASCII score bars. Good for technical buyers and HIPAA auditors. |
| `logs/normal-traffic-sample.jsonl` | 10 raw JSON events from clean clinical baseline. Proves zero false positives. |
| `logs/attack-sequence.jsonl` | Full 8-event attack chain from both attackers. |
| `logs/block-events.jsonl` | 2 raw block decisions with HIPAA-PHI trace IDs. Ready to paste into a client email or deck. |
| `stats/system-stats.md` | CPU / RAM / event counters. Proves low overhead. |
| `screenshots/CAPTURE_GUIDE.md` | 13-screenshot index with per-audience usage recommendations. |
| `screenshots/*.png` | *(Capture during next demo run — see CAPTURE_GUIDE.md)* |

---

## Quick Use

**For a LinkedIn post:** Use `report/evidence-report.md` — pull the "Key Numbers" table and the IoMT block JSON. Add screenshot 08.

**For a client email:** Attach `report/evidence-report.md` as a PDF. Paste the block events inline.

**For a technical buyer:** Show `logs/score-timeline.md` — the ASCII score bars show the mednet threshold at 45 vs internal at 80 clearly.

**For a HIPAA compliance officer:** Show the block events JSON — `decision_owner: "HIPAA Compliance Engine"` and the `HIPAA-PHI-*` trace IDs speak directly to audit requirements.

**For a hospital CIO:** Lead with the IoMT threshold story — mednet blocks at 45, general blocks at 85. The 40-point gap is the ransomware's operating window. MiniFW-AI closes it.

---

## The IoMT Number to Know

**Score 47** — where the IoMT ransomware was blocked.  
**Score 45** — mednet block threshold.  
**Score 85** — general block threshold.  

The ransomware was blocked 38 points before a general-purpose firewall would have acted.
That 38-point gap is the EMR protection window. Without IoMT segmentation, it's open.
