# MiniFW-AI Legal — Presenter Cue Card
**Scenario:** Clifton & Associates LLP | **URL:** https://localhost:8448 | **Login:** admin / Legal1!

---

## Timing

| Time    | What happens                                         | Say                                                                             |
|---------|------------------------------------------------------|---------------------------------------------------------------------------------|
| T+0     | Clean baseline — Westlaw, LexisNexis, courts.gov     | "Normal billing day. Legal research. Six segments. Zero alerts."                |
| T+15s   | MONITOR 40 — wetransfer-legal.io, paralegal          | "Unauthorized cloud upload. AI watching. Human reviews. Calls the paralegal."   |
| T+25s   | **BLOCK 75 — Tor relay, client room**                | "Visitor device, client suite. Tor prohibited. Blocked before tunnel opened."   |
| T+35s   | **BLOCK 75 — clio-encrypt C2, associate**            | "Ransomware C2. Clio case management targeted. Blocked. Case files intact."     |
| T+45s   | **BLOCK 75 — privilege violation, paralegal**        | "Opposing counsel harvester. Attorney-client privilege breach stopped."         |
| T+55s   | **BLOCK 100 — ransomware burst (200 queries)**       | "Aggressive retry. Burst tracker fires. All queries blocked."                   |
| T+65s+  | Sustained — 4 blocks, research traffic continuing   | "Four threats stopped. Partners still billing. Case files untouched."           |

---

## Key Numbers for Q&A

| Metric | Value |
|--------|-------|
| Partner threshold | 85 (most trusted) |
| Associate threshold | 72 |
| Paralegal threshold | 70 |
| Client room threshold | 62 |
| Guest WiFi threshold | 60 |
| LEGAL-ACP trace ID per event | Yes — bar association audit trail |
| Case files encrypted | 0 |
| Privileged data exfiltrated | 0 bytes |
| Human interventions | 0 (autonomous blocking) |
| Legitimate research false positives | 0 |

---

## Privilege Key Point (for General Counsel)

> "Every block event carries a LEGAL-ACP trace ID and a documented reasons array. If the bar association asks what the firm did to protect privileged communications — this log is the contemporaneous record. Not a policy doc. An event-level audit trail."

## Threshold Key Point (for Managing Partner)

> "Partners have threshold 85. Feed plus YARA alone (75) won't block a partner. Paralegals threshold at 70. Client meeting rooms at 62. Same engine, six simultaneous policies."
