# MiniFW-AI — Establishment Sector Evidence Report
**Scenario:** Crown Hotel Group — office monitors + guest WiFi instant blocks
**Version:** 2.2.0  
**Date:** 2026-05-26

---

## The Dual-Threshold Architecture

The establishment policy has two fundamentally different philosophies on the same network:

**Office LAN (192.168.1.0/24, block threshold 80):** Staff devices, known endpoints.
The AI monitors suspicious traffic and surfaces it for human review. Feed-match alone (40)
is not sufficient for an autonomous block. Even feed plus YARA (75) is not sufficient.
The assumption is that a known device needs more evidence before being blocked.

**Guest WiFi (172.16.1.0/24, block threshold 40):** Unknown devices, customers and
visitors. A single feed-match (score 40) is sufficient for an autonomous block. The
AI does not wait for YARA confirmation. The assumption is that you know nothing about
a guest device, so the bar for action is the lowest possible.

---

## Office Events — Four Monitors, Zero Blocks

```
192.168.1.50   login-paypal-secure-verify.com  monitor  score 40   phishing feed match
192.168.1.100  locky-decrypt-files.xyz         monitor  score 75   ransomware C2 + YARA
192.168.1.200  xmrig.c2-miner.io               monitor  score 75   crypto miner + YARA
10.0.0.50      generic-c2-beacon.ru            monitor  score 40   generic C2 feed
```

Every one of these was below the office threshold of 80. Each one is a monitor event
visible in the feed for a human reviewer to act on. The AI flagged all four. It blocked
none — because the office network policy says 80.

If the threshold were 70, the ransomware and crypto miner events (score 75) would have
been blocks, not monitors. That's a policy choice, not an AI limitation.

---

## Guest WiFi Events — Instant Blocks

```json
{
  "ts": "2026-05-26T09:00:40",
  "segment": "guest",
  "client_ip": "172.16.1.99",
  "domain": "login-paypal-secure-verify.com",
  "action": "block",
  "score": 40,
  "reasons": ["dns_feed_match", "guest_segment_zero_tolerance"],
  "sector": "establishment",
  "severity": "critical",
  "trace_id": "SME-EST-C2A05E4F",
  "decision_owner": "Establishment Policy Engine"
}
```

Score 40. BLOCK. The same score that produced a MONITOR on the office network
produced a BLOCK on guest WiFi — because guest threshold equals 40. One signal.
No waiting for YARA. No accumulating evidence. The domain is on the feed; the
device is unknown; it is blocked.

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Office block threshold | 80 |
| Guest WiFi block threshold | 40 |
| Office events at score 75 | MONITOR (5 below block) |
| Guest events at score 40 | BLOCK (at threshold exactly) |
| POS / DMZ threshold | 70 |
| False positives (Office365) | 0 |
| Human interventions | 0 |
| Audit trace ID format | SME-EST-* |

---

## What This Proves for an Establishment Buyer

**You can protect your network without blocking your staff.** Ransomware C2 on the
office network got a monitor event, not a block. Staff kept working. The event is in
the feed for the IT manager to investigate. If you want that to be a block, lower the
office threshold to 70 — one line change in policy.json.

**Guest WiFi is protected at the strictest possible threshold.** Any domain on the
threat feed triggers an immediate block on a guest device. The hotel has no liability
for what a guest's infected phone does after the block fires. The block event, timestamped
and logged, is the record that the hotel acted immediately.

**POS systems have their own policy.** The DMZ segment (threshold 70) sits between
office (80) and guest (40). POS terminals, back-office servers, payment processing
infrastructure — all enforced at 70. A feed-match alone (40) doesn't block them. Feed
plus YARA (75) does. This gives POS traffic more protection than office staff while
keeping the threshold below the 80 that would require significant signal accumulation.
