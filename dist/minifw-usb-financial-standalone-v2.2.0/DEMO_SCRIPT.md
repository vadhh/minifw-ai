# ArborCrest Capital — Executive Live Demo Script
# MiniFW-AI Financial Sector

**URL:** https://localhost:8443  
**Login:** admin / Finance1!  
**Duration:** ~5 minutes end-to-end  
**Scheduler:** Runs automatically when `bash run_demo.sh` completes startup.

---

## Pre-Demo Checklist

- [ ] `bash run_demo.sh` started and dashboard is live
- [ ] Browser open to https://localhost:8443, logged in as admin
- [ ] AI Threat Synthesis card visible on dashboard
- [ ] Events table showing at least 2–3 ALLOW rows (Bloomberg, Reuters, SWIFT)
- [ ] Clock: note your start time — attack fires at T+90s (~1m30s after launch)

---

## PHASE 1 — Normal Operations (T+0 to T+90s)

### What appears on screen
- Events table: `bloomberg.com`, `feeds.reuters.com`, `swift.arborcrest.int`,
  `api.refinitiv.com`, `market.nasdaq.com`, `oracle-erp.arborcrest.int`,
  `sap.arborcrest.int`, `internal-auth.arborcrest.int` — all action: **ALLOW**, scores 18–22
- AI Threat Synthesis card: green / stable

### What to say
> "This is ArborCrest Capital on a normal Friday morning. $4 billion in assets
> under management, 300 traders across two floors. You can see Bloomberg terminals
> pulling market data, Reuters feeds, the SWIFT settlement gateway — and on the
> internal side, Oracle Financials and SAP processing overnight positions.
>
> Every single DNS query is being scored in real time by MiniFW-AI. Everything
> you see here is at 18 to 22 out of 100 — well below our 45-point monitoring
> threshold for the trading floor. Clean baseline."

### What it means
Every outbound connection is profiled behaviorally without interrupting trading.
Legitimate traffic passes transparently with zero latency impact.

### Why it matters
The firewall is not a blunt instrument. It understands what normal looks like
for a financial trading environment — and it will know when something deviates.

---

## PHASE 2 — Suspicious Connection (T+90s)

### What appears on screen
- New event row: `tor-exit-4f2a.net` — score **55** — action: **MONITOR** — amber highlight
- reasons: `anonymizer_traffic`, `trading_floor_anomaly`
- trace_id: `SWIFT-MT103-xxxxxxxx`
- AI Threat Synthesis card updates: anomaly detected, trading floor subnet

### What to say
> "Here — watch the events table. One workstation just queried a Tor exit node.
> That is not Bloomberg. That is not Reuters. Score jumps to 55 — above our
> 45-point monitoring threshold for the trading floor.
>
> We're not blocking yet. We're watching."

### What it means
An anonymizer tool is active from inside the trading floor network.
This could be a compromised workstation or a malicious insider.

### Why it matters
Traditional firewalls have no policy rule for 'employee uses Tor.'
MiniFW-AI flags it because the behavior is inconsistent with financial
trading operations — and it remembers this session for the next signal.

---

## PHASE 3 — Banking Trojan C2 Beacon (T+96s)

### What appears on screen
- New event row: `c2.trickbot-gate.com` — score **72** — action: **MONITOR** — orange/red highlight
- reasons: `dns_feed_match`, `banking_trojan_c2_beacon`, `financial_fraud_feed`

### What to say
> "Now it's beaconing to a TrickBot command-and-control server.
> TrickBot is a banking trojan — it's specifically designed to steal
> financial credentials and intercept wire transfers.
>
> Score is 72. We still haven't blocked. The AI is building its behavioral case —
> it's looking for intent, not just a single data point."

### What it means
The compromised workstation is receiving instructions from malware infrastructure.
The attacker has a foothold and is preparing the next move.

### Why it matters
A signature-based system needs a prior sample of this exact domain.
MiniFW-AI matched it against the financial_fraud threat feed AND weighted the
behavioral chain — anonymizer followed by C2 — as a compound signal.
Two data points. Score rises from 55 to 72.

---

## PHASE 4 — ERP Pivot / PCI Boundary Crossed (T+102s)

### What appears on screen
- New event row: `exfil.payment-collect.io` — score **82** — action: **MONITOR** — red highlight
- reasons: `card_exfil_pattern`, `oracle_erp_subnet_pivot`, `pci_dss_boundary_crossed`

### What to say
> "The attacker just pivoted. They're no longer on the trading floor —
> they've reached the Oracle ERP subnet. That's where ArborCrest's
> client account records live. Portfolio data. Settlement history.
> Account numbers.
>
> Score is now 82. We're above our 80-point block threshold.
> One more signal and the engine commits to a block."

### What it means
The attacker has moved laterally from the trading floor to the ERP/finance
subnet. They are targeting PCI-scoped client financial records.

### Why it matters
This lateral movement across subnets is exactly what evades perimeter-only
defenses. The firewall sees the full behavioral chain across both networks — it knows
this is the same actor who started with the Tor query.

---

## PHASE 5 — Escalation (T+108s)

### What appears on screen
- Another event row: `exfil.payment-collect.io` — score **89** — action: **MONITOR**
- reasons: `card_exfil_pattern`, `client_portfolio_exfil`, `pci_dss_violation`

### What to say
> "Score 89. Active exfiltration attempt. The AI has seen enough."

*(Pause. Let the next event arrive.)*

---

## PHASE 6 — BLOCK (T+114s)

### What appears on screen
- Event row flashes red: `exfil.payment-collect.io` — score **95** — action: **BLOCK** — CRITICAL severity
- AI Threat Synthesis card: CRITICAL alert, PCI-DSS violation confirmed
- decision_owner: `PCI-DSS Policy Engine`

### What to say
> "BLOCK. Score 95.
>
> The AI connected the dots: anonymizer on trading floor → banking trojan C2
> beacon → lateral pivot to Oracle ERP → active client data exfiltration.
> That is a behavioral chain. No single firewall rule catches that.
>
> The IP is in the nftables block list in milliseconds. No analyst was paged.
> No ticket was raised. No human made this decision."

### What it means
MiniFW-AI classified this as a confirmed PCI-DSS violation with active
data exfiltration intent and enforced a kernel-level network block autonomously.

### Why it matters
The average time to detect a breach in financial services is 197 days.
ArborCrest stopped this in under 2 minutes — before a single byte of
client data left the building. Automatically.

---

## PHASE 7 — Operations Continue Safely (T+120s+)

### What appears on screen
- Bloomberg, Reuters, SWIFT, Oracle ERP all returning to ALLOW, scores 18–22
- Attacker IP still blocked (not expired)
- AI Threat Synthesis card: stable

### What to say
> "Trading continues. The ERP is untouched. The rest of ArborCrest's floor
> never noticed an incident occurred. The attacker's IP is blocked for 24 hours.
>
> PCI-DSS: compliant. No breach. No data loss. No disruption."

### Why it matters
Surgical enforcement — one IP blocked, everything else running normally.
This is the business case: a breach that costs $4.5M on average in financial
services, stopped automatically, with zero operational impact.

---

## Anticipated Executive Questions

**Q: Could this block legitimate traffic by mistake?**
> "Yes — any AI system can produce false positives. That's why we have the
> MONITOR phase: the engine watches and builds confidence before committing.
> The 80-point block threshold is tuned for financial operations and is fully
> configurable per network segment in policy.json."

**Q: What if the attacker uses a different domain tomorrow?**
> "The detection is behavioral, not signature-based. The anonymizer + C2 beacon
> + lateral movement pattern would still be flagged even with a brand-new domain
> — as long as the behavior is anomalous relative to the financial baseline."

**Q: Does this require cloud connectivity?**
> "No. MiniFW-AI runs entirely on-premises. Threat feeds update on your schedule.
> No traffic data leaves your network."

**Q: What compliance frameworks does this cover?**
> "PCI-DSS (network segmentation, threat detection, audit logging), ISO 27001
> (anomaly detection, incident response), and SOC 2 Type II (continuous monitoring).
> Full audit trail is maintained in logs/audit.jsonl."
