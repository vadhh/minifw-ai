# Screenshot Index — Financial Demo Evidence
**Captured:** 2026-05-25  
**Demo run:** ArborCrest Capital — full dual-attacker sequence  
**Total:** 13 screenshots

---

## Complete Sequence

| File | What it shows | Best use |
|------|--------------|---------|
| `01-dashboard-clean-baseline.png` | Main dashboard — Financial mode, 0 blocked, 0 alerts, all green | Sales deck opener — "normal Friday morning" |
| `02-events-clean-baseline.png` | Security Events — 7 clean events, bloomberg/reuters/swift/nasdaq all score 18–22 | Prove zero false positives |
| `03-events-first-anomaly-tor-score55.png` | First MONITOR: `tor-exit-4f2a.net` score 55 — anomaly detected among clean traffic | Shows AI reacts to the first signal |
| `04-detail-tor-exit-score55-monitor.png` | Event Details modal — score bar at 55 Monitor Zone, client IP `10.50.0.1`, sector: Trading | Technical detail — not a black box |
| `05-events-trickbot-c2-score72.png` | TrickBot C2 beacon detected — score 72, 2 monitors visible alongside clean traffic | Shows AI building its case step by step |
| `06-detail-exfil-score82-approaching-block.png` | Event Details modal — score 82, ERP pivot, "Block Zone" on the score bar | Score bar in red zone — tension before the block |
| `07-events-escalation-4-monitors.png` | 4 active MONITOR events, scores 55→72→82→89 — escalation in progress | Full escalation sequence in one frame |
| `08-events-BLOCK1-score95-trading-floor.png` | **BLOCK #1** — `exfil.payment-collect.io` score 95, AI SCORED badge, red Blocked row | **Primary proof screenshot — use for LinkedIn and sales** |
| `09-detail-BLOCK1-score95-ai-scored.png` | Event Details modal — score 95, Status: Blocked, Detection Method: AI SCORED, Block Zone | Proves AI-driven decision, not a static rule |
| `10-events-attacker2-swift-building.png` | BLOCK #1 visible + second attacker building — harvest.cred-stealer score 58, swift-intercept 74, wire-redirect 84→91 | Shows concurrent dual-attacker detection |
| `11-events-BLOCK2-score97-swift-fraud.png` | **BLOCK #2** — `drop.wire-redirect.io` score 97, AI SCORED — both blocks visible in feed | **Second key screenshot — SWIFT fraud stopped** |
| `12-detail-BLOCK2-score97-ai-scored.png` | Event Details modal — score 97, Status: Blocked, IP `192.168.1.50`, domain: drop.wire-redirect.io | Detail proof for SWIFT block |
| `13-events-sustained-safe-2blocks-clean.png` | Sustained safe state — 2 blocked, 19 allowed, clean traffic resumed: bloomberg/reuters/swift all score 18–22 | Closing shot — "trading continues, breach stopped" |

---

## Recommended Selections by Use Case

**LinkedIn post (1–2 images):**  
→ `08-events-BLOCK1-score95-trading-floor.png` + `13-events-sustained-safe-2blocks-clean.png`

**Sales deck (4–5 images):**  
→ `01`, `03`, `08`, `11`, `13`

**Technical buyer (full set):**  
→ All 13 in order — tells the complete story from baseline to both blocks to recovery

**WhatsApp / quick proof:**  
→ `11-events-BLOCK2-score97-swift-fraud.png` — shows 2 blocked, score 97, AI SCORED, one frame

**Compliance officer:**  
→ `09-detail-BLOCK1-score95-ai-scored.png` + `12-detail-BLOCK2-score97-ai-scored.png` — AI SCORED badge + PCI-DSS trace IDs
