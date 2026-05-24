# Financial Executive Live Demo — Design Spec

**Date:** 2026-05-22  
**Scope:** `dist/minifw-usb-financial-standalone-v2.2.0/`  
**Goal:** Transform the technical financial demo into a commercial executive live demo with a compelling narrative, realistic financial context, a presenter script, and sub-60s fast recovery.

---

## 1. Scenario Identity

**Company:** ArborCrest Capital  
**Profile:** $4B wealth management firm — trading floor + Oracle ERP/finance operations  
**Subnets:**
- Trading floor: `10.50.0.0/24`
- Finance/ERP: `192.168.1.0/24` (internal)

**No new dashboard UI.** The existing AI Threat Synthesis card handles live display. All narrative richness goes into event data and the presenter script.

---

## 2. Domain Name Overhaul

### Normal Traffic (replaces current `NORMAL_TRAFFIC` in scheduler)

| IP | Domain | Segment | Narrative role |
|----|--------|---------|----------------|
| 10.50.0.10 | bloomberg.com | trading | Market data terminal |
| 10.50.0.11 | feeds.reuters.com | trading | News/wire feed |
| 10.50.0.12 | swift.arborcrest.int | trading | SWIFT settlement gateway |
| 10.50.0.13 | api.refinitiv.com | trading | Refinitiv pricing feed |
| 10.50.0.11 | market.nasdaq.com | trading | NASDAQ data feed |
| 192.168.1.10 | oracle-erp.arborcrest.int | internal | Oracle Financials ERP |
| 192.168.1.11 | sap.arborcrest.int | internal | SAP settlement batch |
| 192.168.1.12 | internal-auth.arborcrest.int | internal | Identity/auth |

### Attack Traffic (replaces current `ATTACK_SEQUENCE`)

5-step sequence, `client_ip: 10.50.0.1`, all `segment: "trading"`:

All 5 steps use `client_ip: 10.50.0.1` (trading floor workstation). Steps 3–5 include `oracle_erp_subnet_pivot` in `reasons[]` — this reflects the same compromised workstation reaching across subnets into ERP territory, not a different IP. The demo narrative calls this out explicitly.

| Step | Domain | Score | Action | reasons[] | Narrative |
|------|--------|-------|--------|-----------|-----------|
| 1 | tor-exit-4f2a.net | 55 | monitor | `["anonymizer_traffic", "trading_floor_anomaly"]` | Tor exit node — not trading software |
| 2 | c2.trickbot-gate.com | 72 | monitor | `["dns_feed_match", "banking_trojan_c2_beacon", "financial_fraud_feed"]` | Banking trojan phoning home |
| 3 | exfil.payment-collect.io | 82 | monitor | `["card_exfil_pattern", "oracle_erp_subnet_pivot", "pci_dss_boundary_crossed"]` | Pivot to ERP subnet — PCI boundary hit |
| 4 | exfil.payment-collect.io | 89 | monitor | `["card_exfil_pattern", "client_portfolio_exfil", "pci_dss_violation"]` | Active exfiltration attempt escalating |
| 5 | exfil.payment-collect.io | 95 | **block** | `["dns_feed_match", "card_exfil_pattern", "pci_dss_violation", "erp_subnet_block"]` | **BLOCK — confirmed exfil intent** |

### trace_id format

Normal events: `TXN-AC-{8 hex chars}`  
Attack events: `SWIFT-MT103-{8 hex chars}`

### Phase timing

| Phase | Duration | Description |
|-------|----------|-------------|
| T+0 – T+90s | 90s | Normal operations (cycle through 8 normal entries, ~11s each) |
| T+90s – T+120s | 30s | Attack sequence (5 steps × 6s delay) |
| T+120s+ | ∞ | Post-block normal traffic (10s interval) |

---

## 3. Files to Create / Modify

### `scheduler/demo_scheduler.py` — modify

- Replace `NORMAL_TRAFFIC` constant with ArborCrest domain table above
- Replace `ATTACK_SEQUENCE` with 5-step sequence above
- Update `trace_id` generation: normal → `TXN-AC-{hex}`, attack → `SWIFT-MT103-{hex}`
- Update `decision_owner`: `"PCI-DSS Policy Engine"` for attack events
- Phase 1 loop: 90s duration, ~11s interval (8 entries × 11s ≈ 88s)
- Phase 2: 5 steps × 6s delay = 30s
- Phase 3: 10s interval

### `demo_data/normal_traffic.json` — modify

Update all domains to match ArborCrest table. Add `192.168.1.x` IPs for ERP entries.

### `demo_data/attack_traffic.json` — modify

Update to match 5-step attack sequence, including new step 3 (ERP pivot) and step 4 (escalation).

### `DEMO_SCRIPT.md` — create

Full presenter script. See Section 4.

### `PRESENTER_CARD.md` — create

Compact one-pager. See Section 5.

### `fast_reset.sh` — create

Sub-60s recovery script. See Section 6.

---

## 4. `DEMO_SCRIPT.md` — Structure

```
# ArborCrest Capital — Live Demo Script
# MiniFW-AI Financial Sector | Executive Presentation

## Setup
- URL: https://localhost:8443
- Login: admin / Finance1!
- Duration: ~5 minutes end-to-end
- Scheduler runs automatically on demo start

---

## PHASE 1 — Normal Operations (T+0 to T+90s)

### What appears on screen
- Dashboard stat cards: green across PCI / SWIFT / Oracle ERP / Blocked IPs = 0
- Events table: bloomberg.com, feeds.reuters.com, swift.arborcrest.int all showing ALLOW
- Threat scores: 18–22 across all sessions

### What to say
"This is ArborCrest Capital on a normal Friday morning. 300 traders, two floors.
Bloomberg terminals, Reuters feeds, SWIFT settlement gateway — all nominal.
Every DNS query is scored in real time by MiniFW-AI. Everything you see here
is at 18–22 out of 100. Our trading floor block threshold is 80."

### What it means
Every outbound DNS query is being behaviorally profiled. Clean traffic passes
transparently. No performance impact on trading operations.

### Why it matters
Executives can see that the firewall is not a blunt instrument — it observes
without interrupting legitimate business traffic.

---

## PHASE 2 — Suspicious Connection (T+90s) — Score: 55, MONITOR

### What appears on screen
- New event row: `tor-exit-4f2a.net` — score 55 — action: MONITOR — amber highlight
- AI Threat Synthesis card updates: anomaly detected on trading floor subnet

### What to say
"Here — 10:15:01. One workstation just queried a Tor exit node.
That is not Bloomberg. That is not Reuters. Score jumps to 55 —
above our 45-point monitoring threshold for the trading floor.
We are now watching that session."

### What it means
An anonymizer tool is being used from inside the trading floor network.
This could be a compromised workstation or a malicious insider.

### Why it matters
Traditional firewalls would not flag this — there is no policy rule for
"employee uses Tor." MiniFW-AI flags it because the behavioral pattern
is inconsistent with financial trading operations.

---

## PHASE 3 — Banking Trojan C2 Beacon (T+96s) — Score: 72, MONITOR

### What appears on screen
- New event row: `c2.trickbot-gate.com` — score 72 — action: MONITOR — orange highlight
- reasons: banking_trojan_c2_beacon, financial_fraud_feed

### What to say
"Now it's beaconing to a TrickBot command-and-control server.
TrickBot is a banking trojan — it is specifically designed to steal
financial credentials and intercept wire transfers.
Score is 72. We have not blocked yet. The AI is still building its case —
looking for intent, not just a single data point."

### What it means
The compromised workstation is in contact with malware infrastructure.
The attacker has a foothold and is now receiving instructions.

### Why it matters
A signature-based system would need a prior sample of this exact domain.
MiniFW-AI matched it against the financial_fraud threat feed AND flagged
the behavioral chain — anomalizer followed by C2 — as a compound signal.

---

## PHASE 4 — ERP Pivot / PCI Boundary Crossed (T+102s) — Score: 82, MONITOR

### What appears on screen
- New event row: `exfil.payment-collect.io` — score 82 — action: MONITOR — red highlight
- reasons: oracle_erp_subnet_pivot, pci_dss_boundary_crossed

### What to say
"The attacker just pivoted. They're no longer on the trading floor —
they've reached the Oracle ERP subnet. That's where ArborCrest's
client account records live. Portfolio data. Settlement history.
Score is now 82 — above our 80-point block threshold.
One more signal and the engine commits."

### What it means
The attacker has moved laterally from the trading floor to the ERP/finance
network. They are targeting PCI-scoped data — client financial records.

### Why it matters
This lateral movement from trading floor to ERP subnet is exactly the
kind of multi-stage attack that evades perimeter-only defenses.
MiniFW-AI sees the full behavioral chain across subnets.

---

## PHASE 5 — BLOCK (T+108s) — Score: 95

### What appears on screen
- Event row flashes red: `exfil.payment-collect.io` — score 95 — action: BLOCK — CRITICAL
- AI Threat Synthesis card: CRITICAL alert, PCI-DSS violation confirmed
- Blocked IPs counter increments to 1

### What to say
"BLOCK. Score 95. The AI connected the dots:
anonymizer → banking trojan C2 → ERP pivot → active exfiltration attempt.
That is a behavioral chain. No single signature rule could catch that.
The IP is in the nftables block list in milliseconds.
No analyst was paged. No ticket was raised. It happened automatically."

### What it means
MiniFW-AI classified this as a confirmed PCI-DSS violation with active
data exfiltration intent and enforced a kernel-level network block.

### Why it matters
The average time to detect a breach in financial services is 197 days.
This was stopped in under 2 minutes — before a single byte of client
data left the building.

---

## PHASE 6 — Operations Continue Safely (T+120s+)

### What appears on screen
- Bloomberg, Reuters, SWIFT, Oracle ERP all returning to ALLOW
- Blocked IPs: 1 (attacker still blocked)
- All other sessions: scores 18–22

### What to say
"Trading continues. The ERP is untouched. ArborCrest's client data
never left. The rest of the floor never noticed an incident occurred.
The attacker remains blocked for 24 hours. PCI-DSS: compliant."

### What it means
The firewall enforced a surgical block — one IP — while leaving all
legitimate trading and ERP operations completely unaffected.

### Why it matters
This is the business case: a breach that would cost $4.5M on average
in the financial sector was stopped automatically, with zero operational
disruption and full PCI-DSS compliance preserved.

---

## Anticipated Executive Questions

**Q: Could this block legitimate traffic by mistake?**
A: Yes — any AI system can have false positives. That's why we have
   the MONITOR phase: the engine watches and builds confidence before
   committing. The 80-point threshold is tuned for financial operations.
   You can adjust it per segment in policy.json.

**Q: What if the attacker uses a different domain tomorrow?**
A: The detection is behavioral, not signature-based. The anonymizer +
   C2 beacon + lateral movement pattern would still be flagged even
   with a brand-new domain — as long as the behavior is anomalous.

**Q: Does this require cloud connectivity?**
A: No. MiniFW-AI runs entirely on-premises. The threat feeds are
   updated on your schedule. No data leaves your network.

**Q: What compliance frameworks does this satisfy?**
A: PCI-DSS (network segmentation, threat detection, audit logging),
   ISO 27001 (anomaly detection, incident response), SOC 2 Type II
   (continuous monitoring). Full audit trail in logs/audit.jsonl.
```

---

## 5. `PRESENTER_CARD.md` — Structure

One table, fits on a printed page. Columns: Phase | T+ | Score | Cue (what appears) | Say (one sentence).

```
# ArborCrest Capital Demo — Presenter Card
# MiniFW-AI Financial Sector | admin / Finance1! | https://localhost:8443

| Phase                    | T+     | Score | Screen Cue                            | Say                                                                 |
|--------------------------|--------|-------|---------------------------------------|---------------------------------------------------------------------|
| Normal Operations        | 0s     | 18–22 | All green, bloomberg/reuters ALLOW    | "Normal Friday morning — 300 traders, all systems nominal."         |
| Trading Activity         | 20s    | 18–22 | NASDAQ, SAP, SWIFT queries flowing    | "Every DNS query scored live. 18–22 — well below our 45pt floor."  |
| Suspicious Connection    | 90s    | 55    | tor-exit-4f2a.net — MONITOR (amber)   | "One workstation just queried Tor. That's not Bloomberg."           |
| C2 Beacon                | 96s    | 72    | c2.trickbot-gate.com — MONITOR (red)  | "Banking trojan phoning home. Score 72 — AI is building its case." |
| ERP Pivot / PCI Boundary | 102s   | 82    | exfil.payment-collect.io — MONITOR    | "They've reached Oracle ERP — client accounts. Score 82."          |
| *** BLOCK ***            | 108s   | 95    | BLOCK — CRITICAL — red flash          | "BLOCK. 95. Behavioral chain detected. Milliseconds. Automatic."   |
| Safe Operations Resume   | 120s+  | 18–22 | Bloomberg/ERP back to ALLOW, 1 blocked| "Trading continues. Data never left. PCI-DSS: compliant."          |

## Recovery: bash fast_reset.sh  (target: 45s)
## Full script: DEMO_SCRIPT.md
```

---

## 6. `fast_reset.sh` — Design

**Target: dashboard ready within 45 seconds of running the script.**

Key optimizations vs. `recover_demo.sh`:

| Current behavior | Fast reset behavior |
|-----------------|---------------------|
| Sequential `sleep 1` between kills | Parallel kills in one pass, single `sleep 1` after |
| Removes `minifw.db` if corrupt | Preserves `minifw.db` (admin user already provisioned) |
| Clears events, relaunches full `run_demo.sh` | Same — but health poll at 0.5s intervals |
| 30s health poll timeout | 45s health poll timeout (more headroom) |
| Only kills engine + scheduler | Kills engine + web + scheduler in one command |

Script flow:
1. Kill all three processes in parallel (engine, web, scheduler) via `pkill -f` — single `sleep 1`
2. Free port 8443 if still held — single `lsof` check
3. Clear `logs/events.jsonl` only (preserve DB)
4. Launch `run_demo.sh` in background
5. Health poll: `curl` every 0.5s up to 45s
6. Print ready URL + credentials on success

---

## 7. Out of Scope

- No dashboard template changes
- No new UI components
- No changes to `policy.json` or YARA rules
- No changes to the main `app/` source (only `dist/` package)
- No Docker package changes (financial standalone only)
