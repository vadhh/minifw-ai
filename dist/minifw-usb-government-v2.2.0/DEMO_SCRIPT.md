# MiniFW-AI Government Demo — Presenter Script
**Scenario:** National sovereign infrastructure — APT28 C2 beacon + Tor relay blocked in real time
**Duration:** ~5 minutes live demo
**Audience:** CISO, CTO, Permanent Secretary, IT Security Lead, Procurement Officer

---

## Before the Demo

    docker compose -f docker/docker-compose.usb-government.yml ps

All three containers (engine, web, injector) must show `Up`. Then confirm:
- https://localhost:8449 loads login page
- Login admin / Government1! — dashboard shows Government sector
- Event feed populates with allow events within 30 seconds

---

## Phase 1 — Clean Baseline (first 20 seconds)

**What the audience sees:** data.gov, nist.gov, parliament.gov — all score 18–22, all green.

**Say:**
> "This is a government network on a normal working day. Parliamentary records queries, NIST standards lookups, open data portal — all legitimate sovereign traffic. Everything scoring 18 to 22. Zero alerts."

> "There are four network segments here. The classified segment — 10.1.0.0/24 — blocks at score 70. That's the tightest threshold in the suite. Internal blocks at 75. The citizen-facing guest network at 65. These aren't arbitrary numbers — they reflect the threat model of each segment. Classified data has no tolerance for ambiguity."

---

## Phase 2 — Government Phishing Portal (near miss)

**What happens:** `gov-login-verify.com` from 10.0.0.50 appears — score 40, ALLOW (below internal monitor threshold of 45). This is intentional.

**Say:**
> "This is a government portal phishing domain — `gov-login-verify.com`. Score 40. Notice it's allowed, not blocked. It's below the internal monitor threshold of 45. This is a talking point, not a failure. MiniFW-AI is showing you where you need to tighten the feed — add this domain to the deny list and it scores 40 and fires a monitor. The system is telling you what it can't catch without better data."

---

## Phase 3 — APT28 C2 Beacon (classified segment)

**What happens:** `apt28-c2.sovereign-exfil.ru` from 10.1.0.20 — BLOCK, score 75, classified segment.

**Say:**
> "There it is. Score 75. BLOCK. APT28 C2 beacon from the classified segment."

> "The classified threshold is 70. Feed match 40 plus YARA 35 equals 75 — five points above the classified block line. The YARA rule GovAptC2 matched on `apt28-c2` and `sovereign-exfil`. Both are known APT28 C2 naming conventions."

> "This is the detection that matters most in a government context. A state-sponsored actor who has already breached the perimeter is beaconing out to their command infrastructure. The beacon was blocked before the attacker received confirmation the implant was active."

**Click into Event Details.**
> "Detection Method: AI SCORED. The score breakdown is right there — feed match, YARA contribution, segment: classified. This is auditable. When the incident review happens, this log entry is your evidence."

---

## Phase 4 — Tor Relay (citizen-facing guest network)

**What happens:** `tor-state-relay.onion-gw.net` from 192.168.200.5 — BLOCK, score 75, guest segment.

**Say:**
> "Second block. This one is from the citizen-facing guest network — a visitor device, 192.168.200.5. Score 75, which crosses the guest threshold of 65."

> "Tor on a government guest network violates sovereignty policy regardless of intent. The YARA rule GovTorRelay matched on `tor-state-relay` and `onion-gw`. A legitimate visitor has no operational reason to route through the Tor network from inside a government building."

---

## Phase 5 — Classified Document Leak Site (monitor)

**What happens:** `govdocs-leak.onion.to` from 10.1.0.30 — MONITOR, score 40.

**Say:**
> "Monitor event from the classified segment — a government document leak site. Score 40, which hits the classified monitor threshold of 40. The AI flagged it, didn't block it. A human reviewer would see this in the event feed and investigate which device on the classified network queried a leak site."

> "This is the difference between autonomous blocking and monitored alerting. For a block you need certainty. For an alert you need a signal. This is a signal."

---

## Phase 6 — APT Burst (cascade block)

**What happens:** 250 queries for `apt28-c2.sovereign-exfil.ru` from 10.1.0.99 — BLOCK score 100.

**Say:**
> "The attacker is now running a burst attempt — 250 DNS queries in 5 seconds. The burst tracker fires at 40 queries per minute on the government profile. Score goes to 100. All 250 queries blocked. IP isolated."

> "Government policy has the strictest burst threshold in the suite — 40 QPM vs 50 for financial, 50 for hospital. That's configurable. If you want to tighten it further, it's a single value in policy.json."

---

## Q&A Responses

**"How do we know the YARA rules are up to date?"**
> "The YARA rules are mounted as a read-only volume from the USB drive. Updating them is as simple as editing the .yar file on the USB and restarting the engine container. No rebuild needed. You can push updated rules to all deployed units by updating the USB image and pushing to whatever distribution mechanism you use."

**"What is the classified segment — how does it know which devices are on it?"**
> "Subnet-based. The classified segment is 10.1.0.0/24. Any DNS query sourced from that subnet is evaluated against the classified policy: block threshold 70, monitor threshold 40. Mapping subnets to segments is a one-line change in policy.json. If your classified network is a different CIDR, you change the value — no code change."

**"What's the audit trail look like for a FOIA request or incident review?"**
> "Every event is written to structured JSONL — timestamp, source IP, domain, score, reasons array, segment, and severity. The log is append-only during the demo run. For production deployment, the .deb package configures log rotation with the retention period you set in policy.json — default 365 days for government."

**"Does this integrate with SIEM?"**
> "The JSONL format is directly ingestible by Splunk, Elastic, and any SIEM that accepts structured log files. The fields are stable — no schema migration between versions. The block events include everything you'd index: IP, domain, score, reasons, segment, timestamp."

---

## Timing Reference

| Time    | Event |
|---------|-------|
| T+0     | Clean baseline — data.gov, nist.gov, parliament.gov |
| T+15s   | gov-login-verify.com — ALLOW* (near miss, score 40, below monitor 45) |
| T+25s   | **BLOCK** — apt28-c2.sovereign-exfil.ru, score 75, classified |
| T+35s   | **BLOCK** — tor-state-relay.onion-gw.net, score 75, guest |
| T+45s   | MONITOR — govdocs-leak.onion.to, score 40, classified |
| T+55s   | **BLOCK cascade** — APT burst 250 queries, score 100 |
| T+65s+  | Sustained normal, 3+ blocks in counter |
