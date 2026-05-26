# Screenshot Index — Government Demo Evidence
**Scenario:** National Sovereign Infrastructure  
**Total:** 9 screenshots

---

## Complete Sequence

| File | What it shows | Best use |
|------|--------------|---------|
| `01-dashboard-clean-baseline.png` | Dashboard — Government sector, 0 blocked, classified/internal/guest segments visible | Sales deck opener |
| `02-events-clean-baseline.png` | data.gov, nist.gov, parliament.gov all score 18–22 | Prove zero false positives from sovereign traffic |
| `03-events-phishing-near-miss.png` | gov-login-verify.com — ALLOW at score 40, below monitor 45 | Near-miss talking point — shows where to extend the feed |
| `04-events-BLOCK1-apt28-c2-score75.png` | **BLOCK #1** — apt28-c2.sovereign-exfil.ru score 75, classified segment, AI SCORED | **Primary proof — APT C2 stopped** |
| `05-detail-BLOCK1-classified-apt.png` | Event Details modal — score 75, segment: classified, YARA GovAptC2, GOV-SOV trace ID | Classified threshold 70 story, YARA breakdown |
| `06-events-BLOCK2-tor-relay-score75.png` | **BLOCK #2** — tor-state-relay.onion-gw.net score 75, guest segment | Sovereignty policy — Tor blocked on government premises |
| `07-events-monitor-leak-site.png` | MONITOR — govdocs-leak.onion.to score 40, classified segment | Shows monitor-not-block decision for ambiguous signals |
| `08-events-burst-cascade-score100.png` | Burst attack — 250 queries → BLOCK cascade score 100, classified | Burst detector fires — government 40 QPM threshold |
| `09-events-sustained-3blocks-clean.png` | Sustained state — 3 blocks, data.gov/parliament.gov continuing normally | Closing shot — sovereign operations unaffected |

---

## Recommended Selections by Use Case

**LinkedIn post:**  
→ `04-events-BLOCK1-apt28-c2-score75.png` — APT28 C2 blocked, one frame

**Sales deck:**  
→ `01`, `04`, `06`, `09`

**CISO / security architect:**  
→ `05-detail-BLOCK1-classified-apt.png` — score breakdown, YARA rule named, classified segment, trace ID

**Procurement / Permanent Secretary:**  
→ `04` + `09` — "APT blocked, sovereign operations unaffected"

**Post-incident review / audit:**  
→ `05` + `07` — shows the monitor/block decision logic and the audit trail
