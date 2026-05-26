# MiniFW-AI Hospital — Presenter Cue Card
**Scenario:** St. Roch Memorial Hospital | **URL:** http://localhost:8000 | **Login:** admin / Hospital1!

---

## Timing

| Time    | What happens                        | Say                                                          |
|---------|-------------------------------------|--------------------------------------------------------------|
| T+0     | Clean baseline — green rows         | "Normal Tuesday morning. EMR, PACS, pharmacy. All clean."    |
| T+90s   | MONITOR 33 — IoMT device (172.16.2.50) | "Patient monitor calling out externally. Watching."       |
| T+96s   | MONITOR 39 — firmware exploit C2   | "Known exploit C2. AI building its case."                    |
| T+102s  | MONITOR 43 — ransomware staging    | "Ransomware payload. Two points from the block line."        |
| T+108s  | **BLOCK 47 — mednet threshold**    | "Blocked. Score 47. IoMT threshold is 45, not 85."           |
| T+150s  | MONITOR 52 — credential theft      | "Phishing victim. Internal workstation."                     |
| T+156s  | MONITOR 64 — FHIR PHI export       | "Bulk patient export. 82,000 records at risk."               |
| T+162s  | MONITOR 75 — PHI staging           | "Data staged externally. About to send."                     |
| T+168s  | **BLOCK 82 — PHI stopped**         | "Blocked. Zero bytes left the building."                     |
| T+168s+ | Sustained safe — 2 blocked         | "Clinical ops never interrupted. HIPAA trace IDs logged."    |

---

## Key Numbers for Q&A

| Metric | Value |
|--------|-------|
| IoMT block threshold | 45 (vs 85 general) |
| General block threshold (internal) | 80 |
| Seconds to first block | ~108s |
| Patient records protected | 82,000 |
| Bytes exfiltrated | 0 |
| False positives (clean clinical traffic) | 0 |
| Human interventions | 0 |
| CPU at idle | < 1% |
| RAM footprint | ~164 MB |
| Works offline (no cloud) | Yes |

---

## IoMT Key Point (say this explicitly)

> "If this device were treated like a laptop, we would have kept watching until score 85. The ransomware would have had 38 more score points of damage time. The segmented threshold is the IoMT protection story."

## HIPAA Compliance Point (for compliance officers)

> "Every block event has a HIPAA-PHI trace ID and `decision_owner: HIPAA Compliance Engine`. That goes directly into your audit log. It's defensible evidence of detection, prevention, and logging — what HIPAA requires."
