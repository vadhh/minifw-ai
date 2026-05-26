# MiniFW-AI Education — Presenter Cue Card
**Scenario:** Westgate Academy | **URL:** https://localhost:8447 | **Login:** admin / Education1!

---

## Timing

| Time    | What happens                                  | Say                                                           |
|---------|-----------------------------------------------|---------------------------------------------------------------|
| T+0     | Clean baseline — Khan Academy, BBC, Wikipedia | "Normal school morning. Legitimate education traffic. All green." |
| T+15s   | MONITOR ~40 — instagram.com (student)         | "Social media. Watching, not blocking."                       |
| T+20s   | MONITOR ~40 — nordvpn.com (student)           | "VPN attempt. Below threshold. AI still building its case."   |
| T+25s   | **BLOCK 75 — nordvpn-bypass.proxy.io**        | "Blocked. YARA caught the bypass pattern. VPN tunnel never opened." |
| T+35s   | **BLOCK 75 — filter-bypass.student.io**       | "Second block. Guest WiFi. Lower threshold — we know less about visitors." |
| T+40s+  | VPN burst (200 queries) → cascade             | "Burst attack — 200 queries. Burst tracker fires. All blocked." |
| T+50s+  | Sustained normal, 2+ blocks in counter        | "Blocked. Clean traffic continues. Learning destinations unaffected." |

---

## Key Numbers for Q&A

| Metric | Value |
|--------|-------|
| Student segment block threshold | 70 |
| Guest segment block threshold | 60 |
| Staff segment block threshold | 80 |
| Score at first block | 75 (student: Feed+40, YARA+35) |
| VPN tunnel established | No |
| False positives (Khan Academy, BBC, Wikipedia) | 0 |
| Human interventions | 0 |
| Audit log entries per event | Full JSONL with IP, domain, score, reasons |
| Works offline | Yes |

---

## Safeguarding Key Point (for safeguarding leads and governors)

> "Every block has a timestamp, a student IP, a domain, and a documented reason. That's your audit trail. Not 'the filter probably caught it' — a timestamped AI decision with a traceable reasoning chain."

## Threshold Key Point (for IT managers)

> "The student network blocks at 70. The guest WiFi blocks at 60. Same system, different thresholds. Each subnet has its own policy — no software change needed to adjust."
