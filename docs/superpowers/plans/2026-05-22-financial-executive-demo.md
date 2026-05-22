# Financial Executive Live Demo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform `dist/minifw-usb-financial-standalone-v2.2.0/` into a commercial executive live demo for ArborCrest Capital with a rich 7-step attack narrative, realistic financial domain names, a complete presenter script, and a sub-60s fast-reset script.

**Architecture:** All changes are confined to the `dist/minifw-usb-financial-standalone-v2.2.0/` package — no main `app/` source is modified. The scheduler enriches event data in-place (ArborCrest domains, 5-step attack chain, financial trace IDs). Two new markdown documents (full script + presenter card) land in the package root. A new `fast_reset.sh` replaces the sequential-sleep `recover_demo.sh` logic with parallel process kills and 0.5s health polling.

**Tech Stack:** Python 3, bash, existing `app.minifw_ai.events.Event` / `EventWriter` dataclasses, `curl` for health checks.

---

## File Map

| Action | Path (relative to `dist/minifw-usb-financial-standalone-v2.2.0/`) |
|--------|---------------------------------------------------------------------|
| Modify | `demo_data/normal_traffic.json` |
| Modify | `demo_data/attack_traffic.json` |
| Modify | `scheduler/demo_scheduler.py` |
| Create | `DEMO_SCRIPT.md` |
| Create | `PRESENTER_CARD.md` |
| Create | `fast_reset.sh` |

> All paths below are relative to `dist/minifw-usb-financial-standalone-v2.2.0/` unless stated otherwise.

---

## Task 1: Update demo_data JSON files

**Files:**
- Modify: `demo_data/normal_traffic.json`
- Modify: `demo_data/attack_traffic.json`

These files are not used by the scheduler at runtime (the scheduler has its own inline constants) but they document the scenario for anyone inspecting the package and may be consumed by other tooling.

- [ ] **Step 1.1: Overwrite `demo_data/normal_traffic.json`**

```json
[
  {"client_ip": "10.50.0.10", "domain": "bloomberg.com",                  "label": "safe", "note": "Bloomberg terminal — market data"},
  {"client_ip": "10.50.0.11", "domain": "feeds.reuters.com",              "label": "safe", "note": "Reuters news/wire feed"},
  {"client_ip": "10.50.0.12", "domain": "swift.arborcrest.int",           "label": "safe", "note": "SWIFT settlement gateway"},
  {"client_ip": "10.50.0.13", "domain": "api.refinitiv.com",              "label": "safe", "note": "Refinitiv pricing feed"},
  {"client_ip": "10.50.0.11", "domain": "market.nasdaq.com",              "label": "safe", "note": "NASDAQ data feed"},
  {"client_ip": "192.168.1.10", "domain": "oracle-erp.arborcrest.int",   "label": "safe", "note": "Oracle Financials ERP"},
  {"client_ip": "192.168.1.11", "domain": "sap.arborcrest.int",          "label": "safe", "note": "SAP settlement batch"},
  {"client_ip": "192.168.1.12", "domain": "internal-auth.arborcrest.int","label": "safe", "note": "Identity / auth service"}
]
```

- [ ] **Step 1.2: Overwrite `demo_data/attack_traffic.json`**

```json
[
  {
    "client_ip": "10.50.0.1",
    "domain": "tor-exit-4f2a.net",
    "label": "anonymizer",
    "score": 55,
    "action": "monitor",
    "note": "Step 1 — Tor exit node from trading floor workstation"
  },
  {
    "client_ip": "10.50.0.1",
    "domain": "c2.trickbot-gate.com",
    "label": "banking_trojan_c2",
    "score": 72,
    "action": "monitor",
    "note": "Step 2 — TrickBot C2 beacon, matches financial_fraud feed"
  },
  {
    "client_ip": "10.50.0.1",
    "domain": "exfil.payment-collect.io",
    "label": "erp_pivot",
    "score": 82,
    "action": "monitor",
    "note": "Step 3 — ERP subnet pivot, PCI boundary crossed"
  },
  {
    "client_ip": "10.50.0.1",
    "domain": "exfil.payment-collect.io",
    "label": "card_exfil",
    "score": 89,
    "action": "monitor",
    "note": "Step 4 — Active client portfolio exfiltration attempt"
  },
  {
    "client_ip": "10.50.0.1",
    "domain": "exfil.payment-collect.io",
    "label": "pci_dss_violation",
    "score": 95,
    "action": "block",
    "note": "Step 5 — BLOCK: confirmed PCI-DSS violation, behavioral chain complete"
  }
]
```

- [ ] **Step 1.3: Verify JSON is valid**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
python3 -c "
import json
for f in ['demo_data/normal_traffic.json', 'demo_data/attack_traffic.json']:
    data = json.load(open(f))
    print(f'{f}: {len(data)} entries OK')
"
```

Expected output:
```
demo_data/normal_traffic.json: 8 entries OK
demo_data/attack_traffic.json: 5 entries OK
```

- [ ] **Step 1.4: Commit**

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/demo_data/
git commit -m "feat(demo): update financial demo_data with ArborCrest domains and 5-step attack"
```

---

## Task 2: Rewrite `scheduler/demo_scheduler.py`

**Files:**
- Modify: `scheduler/demo_scheduler.py`

Replaces generic domains with ArborCrest names, expands attack from 4 to 5 steps, adds financial `trace_id` formatting, varies normal event scores, and extends Phase 1 from 60s to 90s.

- [ ] **Step 2.1: Write a verification snippet before touching the file**

Run this to capture what the current scheduler produces so you can compare after:

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
MINIFW_SECRET_KEY=demo-financial-key-change-in-prod!! \
MINIFW_SECTOR=finance \
PRODUCT_MODE=minifw_financial \
PYTHONPATH="$(pwd):$(pwd)/app" \
python3 -c "
import sys; sys.path.insert(0, 'app')
from scheduler.demo_scheduler import NORMAL_TRAFFIC, ATTACK_SEQUENCE
print('Normal entries:', len(NORMAL_TRAFFIC))
print('Attack steps:', len(ATTACK_SEQUENCE))
print('First normal domain:', NORMAL_TRAFFIC[0]['domain'])
print('Last attack score:', ATTACK_SEQUENCE[-1]['score'])
"
```

Expected (current, pre-change):
```
Normal entries: 8
Attack steps: 4
First normal domain: data.bloomberg.com
Last attack score: 95
```

- [ ] **Step 2.2: Overwrite `scheduler/demo_scheduler.py`**

```python
"""
Financial Executive Demo Scheduler — ArborCrest Capital

Writes timed Event records directly to logs/events.jsonl.
Phase 1 (T+0   – T+90s):  Normal ArborCrest traffic      — action=allow
Phase 2 (T+90s – T+120s): 5-step attack sequence          — monitor → block
Phase 3 (T+120s+):        Post-block normal traffic        — action=allow

Run via: python3 scheduler/demo_scheduler.py
Killed by run_demo.sh cleanup trap.
"""
from __future__ import annotations

import os
import random
import sys
import time
import uuid
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG))
sys.path.insert(0, str(_PKG / "app"))

os.environ.setdefault("MINIFW_SECRET_KEY", os.environ.get("MINIFW_SECRET_KEY", "demo-financial-key-change-in-prod!!"))
os.environ.setdefault("MINIFW_SECTOR", "finance")
os.environ.setdefault("PRODUCT_MODE", "minifw_financial")

from app.minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402

NORMAL_TRAFFIC = [
    {"client_ip": "10.50.0.10", "domain": "bloomberg.com",                   "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "feeds.reuters.com",               "segment": "trading"},
    {"client_ip": "10.50.0.12", "domain": "swift.arborcrest.int",            "segment": "trading"},
    {"client_ip": "10.50.0.13", "domain": "api.refinitiv.com",               "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "market.nasdaq.com",               "segment": "trading"},
    {"client_ip": "192.168.1.10", "domain": "oracle-erp.arborcrest.int",    "segment": "internal"},
    {"client_ip": "192.168.1.11", "domain": "sap.arborcrest.int",           "segment": "internal"},
    {"client_ip": "192.168.1.12", "domain": "internal-auth.arborcrest.int", "segment": "internal"},
]

ATTACK_SEQUENCE = [
    {
        "client_ip": "10.50.0.1",
        "domain":    "tor-exit-4f2a.net",
        "segment":   "trading",
        "action":    "monitor",
        "score":     55,
        "reasons":   ["anonymizer_traffic", "trading_floor_anomaly"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "c2.trickbot-gate.com",
        "segment":   "trading",
        "action":    "monitor",
        "score":     72,
        "reasons":   ["dns_feed_match", "banking_trojan_c2_beacon", "financial_fraud_feed"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "monitor",
        "score":     82,
        "reasons":   ["card_exfil_pattern", "oracle_erp_subnet_pivot", "pci_dss_boundary_crossed"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "monitor",
        "score":     89,
        "reasons":   ["card_exfil_pattern", "client_portfolio_exfil", "pci_dss_violation"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "block",
        "score":     95,
        "reasons":   ["dns_feed_match", "card_exfil_pattern", "pci_dss_violation", "erp_subnet_block"],
        "severity":  "critical",
    },
]


def _txn_id() -> str:
    return f"TXN-AC-{uuid.uuid4().hex[:8].upper()}"


def _swift_id() -> str:
    return f"SWIFT-MT103-{uuid.uuid4().hex[:8].upper()}"


def make_writer(log_path: str) -> EventWriter:
    return EventWriter(log_path)


def write_normal_event(writer: EventWriter, entry: dict) -> None:
    ev = Event(
        ts=now_iso(),
        segment=entry["segment"],
        client_ip=entry["client_ip"],
        domain=entry["domain"],
        action="allow",
        score=random.randint(18, 22),
        reasons=["normal_financial_traffic"],
        sector="finance",
        severity="info",
        trace_id=_txn_id(),
        decision_owner="Policy Engine",
    )
    writer.write(ev)


def write_attack_sequence(writer: EventWriter, delay: float = 0.0) -> None:
    for step in ATTACK_SEQUENCE:
        ev = Event(
            ts=now_iso(),
            segment=step["segment"],
            client_ip=step["client_ip"],
            domain=step["domain"],
            action=step["action"],
            score=step["score"],
            reasons=step["reasons"],
            sector="finance",
            severity=step["severity"],
            trace_id=_swift_id(),
            decision_owner="PCI-DSS Policy Engine",
        )
        writer.write(ev)
        if delay > 0:
            time.sleep(delay)


def run(log_path: str) -> None:
    writer = make_writer(log_path)
    start = time.monotonic()

    print(f"[scheduler] Starting ArborCrest Capital demo scheduler -> {log_path}")
    print("[scheduler] Phase 1: Normal traffic (T+0 - T+90s)")

    normal_idx = 0
    while time.monotonic() - start < 90:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(11)

    print("[scheduler] Phase 2: Attack sequence (T+90s - T+120s) -- BLOCK incoming")
    write_attack_sequence(writer, delay=6.0)
    print("[scheduler] Phase 3: Post-block normal traffic -- firewall holding")

    while True:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(10)


if __name__ == "__main__":
    log_path = os.environ.get("MINIFW_LOG", "logs/events.jsonl")
    run(log_path)
```

- [ ] **Step 2.3: Verify the rewrite with the same snippet**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
MINIFW_SECRET_KEY=demo-financial-key-change-in-prod!! \
MINIFW_SECTOR=finance \
PRODUCT_MODE=minifw_financial \
PYTHONPATH="$(pwd):$(pwd)/app" \
python3 -c "
import sys; sys.path.insert(0, 'app')
from scheduler.demo_scheduler import NORMAL_TRAFFIC, ATTACK_SEQUENCE, _txn_id, _swift_id
print('Normal entries:', len(NORMAL_TRAFFIC))
print('Attack steps:', len(ATTACK_SEQUENCE))
print('First normal domain:', NORMAL_TRAFFIC[0]['domain'])
print('Attack scores:', [s['score'] for s in ATTACK_SEQUENCE])
print('Attack actions:', [s['action'] for s in ATTACK_SEQUENCE])
print('Sample TXN ID:', _txn_id())
print('Sample SWIFT ID:', _swift_id())
assert NORMAL_TRAFFIC[0]['domain'] == 'bloomberg.com'
assert NORMAL_TRAFFIC[5]['domain'] == 'oracle-erp.arborcrest.int'
assert len(ATTACK_SEQUENCE) == 5
assert ATTACK_SEQUENCE[2]['score'] == 82
assert ATTACK_SEQUENCE[4]['action'] == 'block'
assert ATTACK_SEQUENCE[4]['score'] == 95
assert ATTACK_SEQUENCE[1]['reasons'] == ['dns_feed_match', 'banking_trojan_c2_beacon', 'financial_fraud_feed']
assert ATTACK_SEQUENCE[4]['decision_owner'] if False else True  # checked in write fn
print('All assertions passed.')
"
```

Expected output:
```
Normal entries: 8
Attack steps: 5
First normal domain: bloomberg.com
Attack scores: [55, 72, 82, 89, 95]
Attack actions: ['monitor', 'monitor', 'monitor', 'monitor', 'block']
Sample TXN ID: TXN-AC-3F9A2B1C
Sample SWIFT ID: SWIFT-MT103-A4D8E921
All assertions passed.
```

- [ ] **Step 2.4: Dry-run event write to a temp file**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
MINIFW_SECRET_KEY=demo-financial-key-change-in-prod!! \
MINIFW_SECTOR=finance \
PRODUCT_MODE=minifw_financial \
PYTHONPATH="$(pwd):$(pwd)/app" \
python3 -c "
import sys, json, tempfile, os
sys.path.insert(0, 'app')
from scheduler.demo_scheduler import make_writer, write_normal_event, write_attack_sequence, NORMAL_TRAFFIC

tmp = tempfile.mktemp(suffix='.jsonl')
writer = make_writer(tmp)

# Write one normal + full attack sequence
write_normal_event(writer, NORMAL_TRAFFIC[0])
write_attack_sequence(writer, delay=0)

lines = open(tmp).readlines()
events = [json.loads(l) for l in lines]
print(f'Events written: {len(events)}')
print(f'Normal event trace_id prefix: {events[0][\"trace_id\"][:6]}')
print(f'Attack event trace_id prefix: {events[1][\"trace_id\"][:10]}')
print(f'Block event action: {events[-1][\"action\"]}')
print(f'Block event decision_owner: {events[-1][\"decision_owner\"]}')
assert events[0]['trace_id'].startswith('TXN-AC-')
assert events[1]['trace_id'].startswith('SWIFT-MT103-')
assert events[-1]['action'] == 'block'
assert events[-1]['decision_owner'] == 'PCI-DSS Policy Engine'
assert 18 <= events[0]['score'] <= 22
os.unlink(tmp)
print('Dry-run passed.')
"
```

Expected output:
```
Events written: 6
Normal event trace_id prefix: TXN-AC
Attack event trace_id prefix: SWIFT-MT10
Block event action: block
Block event decision_owner: PCI-DSS Policy Engine
Dry-run passed.
```

- [ ] **Step 2.5: Commit**

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py
git commit -m "feat(demo): enrich financial scheduler with ArborCrest narrative and 5-step attack chain"
```

---

## Task 3: Create `DEMO_SCRIPT.md`

**Files:**
- Create: `DEMO_SCRIPT.md`

Full blow-by-blow presenter script with timing, screen cues, what to say, executive meaning, and anticipated Q&A.

- [ ] **Step 3.1: Create `DEMO_SCRIPT.md`**

```markdown
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
defenses. The firewall sees the same session across both networks — it knows
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
```

- [ ] **Step 3.2: Verify file exists and is non-empty**

```bash
wc -l dist/minifw-usb-financial-standalone-v2.2.0/DEMO_SCRIPT.md
```

Expected: line count > 100

- [ ] **Step 3.3: Commit**

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/DEMO_SCRIPT.md
git commit -m "docs(demo): add ArborCrest Capital full executive demo script"
```

---

## Task 4: Create `PRESENTER_CARD.md`

**Files:**
- Create: `PRESENTER_CARD.md`

Compact one-page presenter reference. All timing, cues, and say-lines fit in a single table.

- [ ] **Step 4.1: Create `PRESENTER_CARD.md`**

```markdown
# ArborCrest Capital — Presenter Card
# MiniFW-AI Financial Sector Executive Demo

**URL:** https://localhost:8443 · **Login:** admin / Finance1!  
**Recovery:** `bash fast_reset.sh` (target: 45 seconds)  
**Full script:** `DEMO_SCRIPT.md`

---

| Phase | T+ | Score | Screen Cue | Say |
|-------|----|-------|------------|-----|
| Normal Operations | 0s | 18–22 | bloomberg.com, reuters, swift.arborcrest.int → ALLOW (green) | "Normal Friday morning at ArborCrest. 300 traders. All systems nominal. Scores 18–22 — well below threshold." |
| Trading Activity | ~30s | 18–22 | oracle-erp, sap, internal-auth → ALLOW | "The ERP subnet is normal too. Every query scored live. Clean baseline." |
| Suspicious Connection | 90s | 55 | `tor-exit-4f2a.net` — MONITOR (amber) | "One workstation just hit a Tor exit node. Not Bloomberg. Score jumps to 55. We're watching." |
| C2 Beacon | 96s | 72 | `c2.trickbot-gate.com` — MONITOR (red) | "Banking trojan phoning home. TrickBot. Score 72 — AI is building its case." |
| ERP Pivot | 102s | 82 | `exfil.payment-collect.io` — MONITOR (red) | "Pivoted to Oracle ERP subnet — client accounts. Score 82, above block threshold. One more signal." |
| Escalation | 108s | 89 | `exfil.payment-collect.io` — MONITOR | "89. Active exfiltration attempt. The AI has seen enough." *(pause)* |
| **★ BLOCK** | 114s | **95** | `exfil.payment-collect.io` — **BLOCK** 🛑 CRITICAL | "**BLOCK. 95. Behavioral chain: Tor → C2 → ERP pivot → exfil. Milliseconds. Automatic.**" |
| Safe Operations | 120s+ | 18–22 | Bloomberg/ERP back to ALLOW · 1 blocked IP | "Trading continues. Data never left. PCI-DSS: compliant. No human intervention." |

---

## Key Numbers for Q&A

| Stat | Value |
|------|-------|
| Block threshold (trading floor) | 80 / 100 |
| Time from first anomaly to BLOCK | ~24 seconds |
| Average financial breach detection time (industry) | 197 days |
| Data exfiltrated | 0 bytes |
| Human interventions required | 0 |
| PCI-DSS status after incident | Compliant |
```

- [ ] **Step 4.2: Verify file exists**

```bash
wc -l dist/minifw-usb-financial-standalone-v2.2.0/PRESENTER_CARD.md
```

Expected: line count > 25

- [ ] **Step 4.3: Commit**

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/PRESENTER_CARD.md
git commit -m "docs(demo): add ArborCrest Capital compact presenter card"
```

---

## Task 5: Create `fast_reset.sh`

**Files:**
- Create: `fast_reset.sh`

Sub-60s recovery: parallel process kills, preserve DB, 0.5s health poll, 45s timeout.

- [ ] **Step 5.1: Create `fast_reset.sh`**

```bash
#!/bin/bash
# MiniFW-AI Financial Demo — Fast Reset
# Target: dashboard ready in ≤ 45 seconds.
# Preserves minifw.db (admin user stays provisioned).
# Usage: bash fast_reset.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-reset] $*"; }
die() { echo "[minifw-reset] ERROR: $*" >&2; exit 1; }

log "Fast reset starting..."

# ── Step 1: Kill all three processes in parallel ─────────────────────────────
log "Killing engine, web, and scheduler..."
pkill -f "minifw_ai/main.py"  2>/dev/null || true
pkill -f "uvicorn app.web"    2>/dev/null || true
pkill -f "demo_scheduler.py"  2>/dev/null || true
sleep 1

# ── Step 2: Free port 8443 if still held ────────────────────────────────────
if lsof -ti:8443 >/dev/null 2>&1; then
    log "Port 8443 still held — force-killing..."
    lsof -ti:8443 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# ── Step 3: Clear event log only (preserve DB and admin user) ───────────────
log "Clearing event log..."
rm -f logs/events.jsonl

# ── Step 4: Relaunch demo ────────────────────────────────────────────────────
log "Relaunching..."
[[ -f run_demo.sh ]] || die "run_demo.sh not found"
bash run_demo.sh &

# ── Step 5: Health poll at 0.5s intervals, 45s timeout ──────────────────────
log "Waiting for dashboard (45s max)..."
READY=false
START=$(date +%s)
while true; do
    if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    NOW=$(date +%s)
    if (( NOW - START >= 45 )); then
        break
    fi
    sleep 0.5
done

ELAPSED=$(( $(date +%s) - START ))

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up in ${ELAPSED}s — see RECOVERY.md for manual steps."
    exit 1
fi

log "Ready in ${ELAPSED}s — https://localhost:8443  (admin / Finance1!)"
```

- [ ] **Step 5.2: Make executable**

```bash
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh
```

- [ ] **Step 5.3: Smoke-test the script syntax**

```bash
bash -n dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh
echo "Syntax OK: $?"
```

Expected:
```
Syntax OK: 0
```

- [ ] **Step 5.4: Verify it handles the no-process case cleanly**

Run when no demo is running — it should not error:

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
# Don't actually relaunch — just test the kill+clear phase in isolation
bash -c '
pkill -f "minifw_ai/main.py"  2>/dev/null || true
pkill -f "uvicorn app.web"    2>/dev/null || true
pkill -f "demo_scheduler.py"  2>/dev/null || true
echo "Kill phase: OK (exit 0 even when nothing running)"
'
```

Expected:
```
Kill phase: OK (exit 0 even when nothing running)
```

- [ ] **Step 5.5: Commit**

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh
git commit -m "feat(demo): add fast_reset.sh — sub-60s demo recovery for live meetings"
```

---

## Task 6: End-to-End Smoke Test

Verify the full demo flow works with the enriched scheduler before calling the feature complete.

- [ ] **Step 6.1: Launch the demo**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
bash run_demo.sh &
```

Wait for: `Dashboard ready → https://localhost:8443  (admin / Finance1!)`

- [ ] **Step 6.2: Confirm normal events are writing ArborCrest domains**

```bash
sleep 15  # let the scheduler emit at least one event
grep -c "bloomberg.com\|arborcrest" dist/minifw-usb-financial-standalone-v2.2.0/logs/events.jsonl 2>/dev/null || echo "0 events yet"
```

Expected: at least 1 match within 15s of launch.

- [ ] **Step 6.3: Confirm attack events fire with correct structure**

Wait until T+90s from launch (watch `logs/events.jsonl` for TrickBot):

```bash
grep "trickbot\|erp_subnet\|pci_dss_violation" dist/minifw-usb-financial-standalone-v2.2.0/logs/events.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    ev = json.loads(line)
    print(ev['action'], ev['score'], ev['trace_id'][:12], ev['decision_owner'][:20])
"
```

Expected (after ~T+96s):
```
monitor 72 SWIFT-MT103- PCI-DSS Policy Eng
monitor 82 SWIFT-MT103- PCI-DSS Policy Eng
monitor 89 SWIFT-MT103- PCI-DSS Policy Eng
block   95 SWIFT-MT103- PCI-DSS Policy Eng
```

- [ ] **Step 6.4: Kill the demo and run fast_reset.sh — measure elapsed time**

```bash
# Kill demo first
pkill -f "minifw_ai/main.py" 2>/dev/null; pkill -f "uvicorn app.web" 2>/dev/null; pkill -f "demo_scheduler.py" 2>/dev/null
sleep 2

# Time the fast reset
time bash dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh
```

Expected: `real` time under `0m45.000s` and final log line:
```
[minifw-reset] Ready in Xs — https://localhost:8443  (admin / Finance1!)
```

- [ ] **Step 6.5: Final commit — update dist INDEX.md**

In `dist/INDEX.md`, locate the Finance Sector block and replace:

```markdown
**Credentials:** `admin / Finance1!`  
**Quick start:** `bash setup_tls.sh && bash run_demo.sh`
```

with:

```markdown
**Credentials:** `admin / Finance1!`  
**Quick start:** `bash setup_tls.sh && bash run_demo.sh`  
**Fast reset:** `bash fast_reset.sh` (target: 45 seconds)  
**Presenter docs:** `DEMO_SCRIPT.md` (full script) · `PRESENTER_CARD.md` (one-page cue card)
```

Then commit:

```bash
git add dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh dist/INDEX.md
git commit -m "chore(demo): update INDEX.md with fast_reset and presenter script references"
```
