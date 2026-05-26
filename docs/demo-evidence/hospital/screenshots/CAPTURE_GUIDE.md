# Screenshot Index — Hospital Demo Evidence
**Scenario:** St. Roch Memorial Hospital — dual-vector attack  
**Total:** 13 screenshots (same narrative structure as financial)

---

## Complete Sequence

| File | What it shows | Best use |
|------|--------------|---------|
| `01-dashboard-clean-baseline.png` | Main dashboard — Hospital mode, 0 blocked, 0 alerts, all green | Sales deck opener — "normal clinical morning" |
| `02-events-clean-baseline.png` | Security Events — 7 clean events, EMR/PACS/HL7/pharmacy all score 18–22 | Prove zero false positives from clinical traffic |
| `03-events-first-anomaly-iomt-score33.png` | First MONITOR: `c2.iomt-backdoor.net` score 33, mednet segment | Shows AI reacts to first IoMT anomaly |
| `04-detail-iomt-score33-monitor.png` | Event Details modal — score 33 Monitor Zone, client IP 172.16.2.50, segment: mednet | Technical detail — shows mednet segment label |
| `05-events-medfware-c2-score39.png` | Firmware exploit C2 — score 39, 2 monitors visible, clean traffic alongside | AI building its case, clinical traffic unaffected |
| `06-detail-ransomware-score43-approaching-block.png` | Event Details modal — score 43, ransomware staging, "Block Zone" on score bar | Score bar approaching 45 threshold — tension |
| `07-events-escalation-3-monitors.png` | 3 active MONITOR events: 33→39→43 — escalation in progress | Full IoMT escalation sequence in one frame |
| `08-events-BLOCK1-score47-iomt.png` | **BLOCK #1** — `exfil.ransom-hospital.net` score 47, AI SCORED badge, red Blocked row | **Primary proof screenshot — IoMT story** |
| `09-detail-BLOCK1-score47-ai-scored.png` | Event Details modal — score 47, Status: Blocked, Detection Method: AI SCORED, mednet segment | Proves AI-driven IoMT decision, HIPAA trace ID visible |
| `10-events-attacker2-phi-building.png` | BLOCK #1 visible + second attacker building — phi-stealer 52, phi-dump 64, patient-exfil 75 | Dual-attacker concurrent detection |
| `11-events-BLOCK2-score82-phi.png` | **BLOCK #2** — `drop.patient-exfil.net` score 82, AI SCORED — both blocks visible | **Second key screenshot — PHI exfil stopped** |
| `12-detail-BLOCK2-score82-ai-scored.png` | Event Details modal — score 82, Status: Blocked, IP 192.168.1.75, HIPAA trace ID | Detail proof for HIPAA compliance conversation |
| `13-events-sustained-safe-2blocks-clean.png` | Sustained safe state — 2 blocked, 18+ allowed, EMR/PACS/HL7 scoring 18–22 | Closing shot — "clinical operations continue, breach stopped" |

---

## Recommended Selections by Use Case

**LinkedIn post (1–2 images):**  
→ `08-events-BLOCK1-score47-iomt.png` + `13-events-sustained-safe-2blocks-clean.png`

**Sales deck (4–5 images):**  
→ `01`, `03`, `08`, `11`, `13`

**Technical buyer (full set):**  
→ All 13 in order — tells complete story from baseline to both blocks to recovery

**WhatsApp / quick proof:**  
→ `11-events-BLOCK2-score82-phi.png` — shows 2 blocked, both trace IDs, one frame

**HIPAA compliance officer:**  
→ `09-detail-BLOCK1-score47-ai-scored.png` + `12-detail-BLOCK2-score82-ai-scored.png` — AI SCORED badge + HIPAA-PHI trace IDs

**Hospital CIO (IoMT story):**  
→ `07-events-escalation-3-monitors.png` + `08-events-BLOCK1-score47-iomt.png` — show the escalation then the block at score 47
