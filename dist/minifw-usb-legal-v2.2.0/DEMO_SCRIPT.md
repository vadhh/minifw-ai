# MiniFW-AI Legal Demo — Presenter Script
**Scenario:** Clifton & Associates LLP — ransomware C2, Tor relay, privilege breach stopped
**Duration:** ~5 minutes live demo
**Audience:** Managing Partner, IT Director, General Counsel, Risk & Compliance Officer

---

## Before the Demo

    docker compose -f docker/docker-compose.usb-legal.yml ps

All three containers running. https://localhost:8448 loads login. admin / Legal1!

---

## Phase 1 — Clean Baseline

**What the audience sees:** Westlaw, LexisNexis, courts.gov — all score 18–22, all green.

**Say:**
> "Clifton & Associates — normal billing day. Partners doing legal research: Westlaw, LexisNexis, federal court dockets. All legitimate. Scoring 18 to 22. Six network segments: partners at threshold 85, associates at 72, paralegals at 70, client meeting rooms at 62, guest WiFi at 60. One engine enforcing all six simultaneously."

---

## Phase 2 — Unauthorized Cloud Upload (MONITOR)

**What happens:** `wetransfer-legal.io` from 10.20.2.10 (paralegal network) — MONITOR, score 40.

**Say:**
> "Score 40. Monitor. A paralegal is attempting to upload case files to an unauthorized cloud transfer service. Not blocked yet — the AI doesn't have enough evidence for an autonomous block. But the event is in the feed. A human reviewer sees it. They call the paralegal. They ask what's being uploaded."

> "This is the difference between a firewall and a behavioral AI. A firewall either blocks WeTransfer outright — which you can't do in a law firm that uses it for legitimate client deliveries — or allows it entirely. MiniFW-AI scores the specific domain and the specific device and decides: monitor, not block."

---

## Phase 3 — Tor Exit Relay (client room BLOCK)

**What happens:** `tor-exit-relay.onion-gw.net` from 192.168.200.5 (client meeting room) — BLOCK, score 75.

**Say:**
> "Client meeting room. Score 75. BLOCK. A visitor device in the client suite is querying a Tor exit relay. Client threshold is 62. Feed match 40 plus YARA 35 equals 75 — thirteen points above the block line."

> "The client doesn't know which device in that room is doing it. It might be a legitimate privacy tool. It might be opposing counsel's investigator. It doesn't matter — the firm's policy is that Tor access from the client network is prohibited. MiniFW-AI enforces the policy."

---

## Phase 4 — Ransomware C2 (associate network BLOCK)

**What happens:** `clio-encrypt.c2-server.ru` from 10.20.1.20 (associate network) — BLOCK, score 75.

**Say:**
> "Score 75. BLOCK. Ransomware C2 beacon from an associate's workstation. The YARA rule `LegalRansomwareC2` matched on `clio-encrypt` — a known ransomware family that specifically targets legal document management systems. Clio is the case management platform this firm uses."

> "The associate's machine is compromised. The ransomware dropper was staged. The C2 beacon was its first communication. It was blocked before the attacker received any confirmation. The case files are intact."

---

## Phase 5 — Privilege Violation (paralegal network BLOCK)

**What happens:** `opposing-counsel.harvest.io` from 10.20.2.50 (paralegal) — BLOCK, score 75.

**Say:**
> "Score 75. BLOCK. Attorney-client privilege violation. A paralegal device queried a domain called `opposing-counsel.harvest.io` — a domain designed to exfiltrate case data to opposing counsel's infrastructure. The YARA rule `LegalPrivilegeViolation` matched."

> "This is the scenario that ends careers and triggers bar association proceedings. The domain name is the evidence. The AI blocked it in the DNS lookup phase — before a single document was staged. The LEGAL-ACP trace ID in the event detail is your contemporaneous record."

---

## Phase 6 — Ransomware Burst (cascade block)

**What happens:** 200 queries for `clio-encrypt.c2-server.ru` — BLOCK score 100.

**Say:**
> "The ransomware tool is retrying aggressively — 200 DNS queries in burst. Burst tracker fires at 50 QPM. Score 100. All queries blocked. IP isolated. The case files are still intact."

---

## Q&A Responses

**"What's the attorney-client privilege angle?"**
> "Every block event carries a LEGAL-ACP trace ID and a reasons array that documents which privilege policy was triggered. If a client or bar association asks for evidence that the firm took reasonable steps to protect privileged communications, this log is the answer. Not policy documents — an event-level audit trail."

**"How does it handle legitimate cloud services vs. unauthorized uploads?"**
> "WeTransfer.com scores 20 on the partner network — legitimate use. `wetransfer-legal.io` (a spoofed variant) scores 40 and triggers a monitor. The domain, the segment, and the naming pattern all contribute. The score is calibrated to the firm's actual risk model, not a blocklist."

**"What happens if a partner accidentally triggers a block?"**
> "Partners have the highest threshold — 85. Feed match alone (40) doesn't block a partner. Feed plus YARA (75) doesn't block a partner. It would take all scoring signals simultaneously to push a partner to 85. In practice, legitimate partner traffic doesn't hit the feeds at all."

---

## Timing Reference

| Time | Event |
|------|-------|
| T+0 | Clean baseline — Westlaw, LexisNexis, courts.gov |
| T+15s | MONITOR 40 — wetransfer-legal.io, paralegal |
| T+25s | **BLOCK 75** — Tor relay, client room |
| T+35s | **BLOCK 75** — clio-encrypt.c2-server.ru, associate |
| T+45s | **BLOCK 75** — opposing-counsel.harvest.io, paralegal |
| T+55s | **BLOCK 100** — ransomware burst cascade |
| T+65s+ | Sustained — 4 blocks, Westlaw/LexisNexis continuing |
