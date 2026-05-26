# MiniFW-AI Establishment — Presenter Cue Card
**Scenario:** Crown Hotel Group | **URL:** https://localhost:8444 | **Login:** admin / SME_Demo1!

---

## Timing

| Time    | What happens                                         | Say                                                                              |
|---------|------------------------------------------------------|----------------------------------------------------------------------------------|
| T+0     | Office365 allow — 192.168.1.10 (office)              | "Normal Tuesday. One employee on 365. Zero alerts."                              |
| T+10s   | MONITOR 40 — phishing domain, office                 | "Phishing email. Office threshold 80. Score 40. Watching, not blocking."         |
| T+20s   | MONITOR 75 — ransomware C2, office                   | "Ransomware C2. Score 75 — five points from block. MONITOR. AI building case."   |
| T+30s   | MONITOR 75 — crypto miner, office                    | "Crypto miner. Hotel's electricity. Score 75 on YARA. MONITOR."                  |
| T+40s   | **BLOCK 40 — guest WiFi (172.16.1.x)**               | "Guest threshold is 40. One feed match. Instant block. You know nothing about that device." |
| T+50s   | **BLOCK 100 — guest burst (250 queries)**            | "Infected phone on hotel WiFi. 250 queries in 5 seconds. Isolated."              |
| T+60s+  | Office allows + guest blocks side by side            | "Staff working normally. Guest device isolated. POS network untouched."          |

---

## Key Numbers for Q&A

| Metric | Value |
|--------|-------|
| Office block threshold | 80 |
| Guest WiFi block threshold | **40** (any feed-match = BLOCK) |
| DMZ block threshold | 70 |
| Ransomware C2 score (office) | 75 — MONITOR (5 below block) |
| Guest WiFi blocks at score | 40 (one signal is enough) |
| POS system segment | DMZ — threshold 70 |
| False positives (Office365) | 0 |
| Human interventions | 0 |
| Block release time | ~10 seconds via dashboard |

---

## Guest WiFi Key Point

> "Office threshold 80. Guest threshold 40. Same score on the office network = MONITOR. Same score on guest WiFi = BLOCK. You know your staff. You don't know your guests. The policy reflects that."
