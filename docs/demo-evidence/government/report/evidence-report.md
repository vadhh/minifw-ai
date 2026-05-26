# MiniFW-AI — Government Sector Evidence Report
**Scenario:** National Sovereign Infrastructure — APT28 C2 beacon + Tor relay blocked
**Version:** 2.2.0  
**Date:** 2026-05-26

---

## Before the Attacks

Sovereign network — four segments: classified (10.1.0.0/24, block 70), internal
(10.0.0.0/8, block 75), guest (192.168.200.0/24, block 65), DMZ (10.10.0.0/24, block 72).

Normal sovereign traffic scores 18–22. data.gov, nist.gov, parliament.gov — zero
alerts from any of them. The government YARA rules carry patterns for APT naming
conventions and sovereignty policy violations; nothing in the normal traffic set
matches any of them.

---

## Near Miss — Government Phishing Portal

`gov-login-verify.com` from 10.0.0.50 (internal) scored 40. The internal monitor
threshold is 45. Score 40 is below it — so this was allowed.

This is intentional transparency. The AI scored the domain as suspicious (feed match
on a known phishing pattern). It didn't reach the monitor threshold. The solution is
to add the domain to the deny feed or lower the internal threshold. The near-miss
event is visible in the feed for exactly this reason: it tells the operator where the
feed needs extension.

---

## Block 1 — APT28 C2 Beacon (classified segment)

**Source:** 10.1.0.20 — classified network device  
**Segment policy:** classified block threshold = **70**

A device on the classified segment queried `apt28-c2.sovereign-exfil.ru` — a domain
matching two strings in the `GovAptC2` YARA rule: `apt28-c2` and `sovereign-exfil`.
Feed match 40 + YARA 35 = 75. Classified threshold is 70. Block fired on the first
DNS query.

```json
{
  "ts": "2026-05-26T09:00:25",
  "segment": "classified",
  "client_ip": "10.1.0.20",
  "domain": "apt28-c2.sovereign-exfil.ru",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "gov_apt_c2_yara", "classified_segment_apt_beacon"],
  "sector": "government",
  "severity": "critical",
  "trace_id": "GOV-SOV-C2A05E4F",
  "decision_owner": "Sovereignty Policy Engine"
}
```

The attacker had established an implant on the classified network device. The C2 beacon
was the first outbound communication after implantation — the signal that the implant
was alive and ready for commands. That beacon was blocked. The attacker never received
confirmation the implant was active.

The classified segment threshold of 70 is 5 points below the internal threshold of 75
for this reason: classified data has zero tolerance for ambiguity. The 5-point delta
is the risk budget difference between classified and internal operations.

---

## Block 2 — Tor Relay (citizen-facing guest network)

**Source:** 192.168.200.5 — visitor/citizen device  
**Segment policy:** guest block threshold = **65**

A device on the citizen-facing guest network queried `tor-state-relay.onion-gw.net`.
Feed match 40 + YARA (`GovTorRelay`: `tor-state-relay` + `onion-gw`) 35 = 75. Guest
threshold 65. Blocked on first query.

```json
{
  "ts": "2026-05-26T09:00:35",
  "segment": "guest",
  "client_ip": "192.168.200.5",
  "domain": "tor-state-relay.onion-gw.net",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "gov_tor_relay_yara", "sovereignty_policy_violation"],
  "sector": "government",
  "severity": "critical",
  "trace_id": "GOV-SOV-D3B16F5A",
  "decision_owner": "Sovereignty Policy Engine"
}
```

Sovereignty policy prohibits Tor access from government premises on any segment.
The guest threshold of 65 means the Tor relay was blocked without the visitor's
device ever connecting to the Tor network.

---

## Block 3 — APT Burst Cascade

**Source:** 10.1.0.99 — classified network  
**Type:** DNS burst — 250 queries in ~5 seconds

A second classified-network device sent 250 DNS queries for `apt28-c2.sovereign-exfil.ru`
in rapid succession — a beaconing tool that retries aggressively when initial queries fail.
The government burst threshold is 40 QPM (the strictest in the suite). Score overridden
to 100. All 250 queries blocked. IP isolated.

```json
{
  "ts": "2026-05-26T09:00:55",
  "segment": "classified",
  "client_ip": "10.1.0.99",
  "domain": "apt28-c2.sovereign-exfil.ru",
  "action": "block",
  "score": 100,
  "reasons": ["dns_burst_threshold_exceeded", "dns_feed_match", "gov_apt_c2_yara", "burst_cascade_block"],
  "sector": "government",
  "severity": "critical",
  "trace_id": "GOV-SOV-F5D38B7C",
  "decision_owner": "Sovereignty Policy Engine"
}
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Classified block threshold | 70 (tightest in suite) |
| APT C2 blocked at score | 75 |
| C2 confirmation received by attacker | No |
| Tor access established | No |
| Burst threshold (government) | 40 QPM |
| False positives (data.gov, nist.gov, parliament.gov) | 0 |
| Human interventions | 0 |
| Audit trace IDs | GOV-SOV-* per event |
| Log retention (production) | 365 days |

---

## What This Proves for a Government Buyer

**APT detection on first beacon.** The classified network block fired on the single
DNS lookup that initiated the C2 connection. The attacker established an implant —
they had already breached the perimeter. The C2 beacon was the next step. MiniFW-AI
blocked it before the implant received its first instruction. No data left the network.
No command was executed.

**Segmented policy is operationally meaningful.** The classified segment blocks at 70.
The internal network blocks at 75. The guest network at 65. These are not cosmetic
labels — they are enforced simultaneously by the same engine. A device that moves
from the internal network to the classified subnet is immediately subject to the
tighter policy. No reconfiguration needed.

**Sovereignty policy is enforceable.** Tor on a government guest network is a
sovereignty violation regardless of the visitor's intent. The Tor relay block was
automatic, immediate, and logged with a sovereignty policy reason code. If asked to
demonstrate that the government site enforces a Tor prohibition, this event log is
the evidence.

**Full audit trail for incident review.** Every event — allow, monitor, block —
carries a GOV-SOV-* trace ID, a source IP, a domain, a score, a reasons array, and
a decision owner. The JSONL log is directly ingestible by any SIEM. For a FOIA
request, a parliamentary inquiry, or a post-incident review, the log is the
contemporaneous record.
