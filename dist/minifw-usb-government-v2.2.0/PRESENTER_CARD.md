# MiniFW-AI Government — Presenter Cue Card
**Scenario:** National Sovereign Infrastructure | **URL:** https://localhost:8449 | **Login:** admin / Government1!

---

## Timing

| Time    | What happens                                        | Say                                                                       |
|---------|-----------------------------------------------------|---------------------------------------------------------------------------|
| T+0     | Clean baseline — data.gov, nist.gov, parliament.gov | "Normal working day. Sovereign traffic. Zero alerts."                     |
| T+15s   | ALLOW* score 40 — gov-login-verify.com (internal)   | "Phishing portal. Score 40, below monitor 45. Near miss — add to feed."   |
| T+25s   | **BLOCK 75 — APT28 C2, classified segment**         | "APT28 C2 beacon. Classified segment, threshold 70. Blocked. Auditable."  |
| T+35s   | **BLOCK 75 — Tor relay, guest network**             | "Tor from government guest WiFi. Sovereignty policy. Blocked."            |
| T+45s   | MONITOR 40 — govdocs-leak.onion.to, classified      | "Leak site query from classified net. Signal, not block. Investigate."    |
| T+55s   | **BLOCK 100 — APT burst (250 queries)**             | "250 DNS queries in 5 seconds. Burst threshold fires. All blocked."       |
| T+65s+  | Sustained — 3+ blocks, clean allows continuing     | "Three threat vectors stopped. Sovereign operations continue."            |

---

## Key Numbers for Q&A

| Metric | Value |
|--------|-------|
| Classified segment block threshold | 70 (tightest in suite) |
| Internal block threshold | 75 |
| Guest block threshold | 65 |
| Government burst threshold | 40 QPM (strictest) |
| APT C2 blocked at score | 75 |
| Blocks before attacker confirmed implant active | Yes (C2 beacon blocked) |
| Log retention (production) | 365 days (policy.json) |
| SIEM ingest format | Structured JSONL |
| Works air-gapped | Yes |

---

## Classified Segment Key Point

> "Classified blocks at 70, not 80. That 10-point difference is deliberate — on a classified network, ambiguity is not tolerable. The AI doesn't need 80 points of evidence to block. It needs 70."

## Near Miss Talking Point

> "The phishing portal scored 40 and was allowed — below the internal monitor threshold of 45. This is the system showing you where to tighten. Add `gov-login-verify.com` to the deny feed and that score triggers a monitor immediately."
