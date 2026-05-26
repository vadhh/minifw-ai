# Attack Score Timeline — Crown Hotel Group
**Demo run:** 2026-05-26  
**Scenario:** Office phishing + ransomware + guest WiFi blocks

---

## Normal Traffic (office segment)

```
09:00:01  192.168.1.10  office365.com  score  0   ░░░░░░░░░░░░░░░░░░░░  ALLOW  office
```

---

## Office Monitors (below block threshold of 80)

```
09:00:10  192.168.1.50   login-paypal-secure-verify.com  score  40  ████████░░░░░░░░░░░░  MONITOR  feed=40
09:00:20  192.168.1.100  locky-decrypt-files.xyz         score  75  ███████████████░░░░░  MONITOR  feed+YARA
09:00:30  192.168.1.200  xmrig.c2-miner.io               score  75  ███████████████░░░░░  MONITOR  feed+YARA (crypto miner)
09:00:35  10.0.0.50      generic-c2-beacon.ru            score  40  ████████░░░░░░░░░░░░  MONITOR  feed=40
```

All four office events stayed in MONITOR. Office threshold is 80. Even ransomware
C2 plus YARA (75) is five points short of an autonomous block on the office network.

---

## Guest WiFi Blocks (threshold 40 — immediate)

```
09:00:40  172.16.1.99  login-paypal-secure-verify.com  score  40  ████████░░░░░░░░░░░░  BLOCK  guest (threshold 40)
09:00:50  172.16.1.99  login-paypal-secure-verify.com  score 100  BLOCK cascade (burst ×250)
```

The same score (40) that produced a MONITOR on the office network produced a BLOCK
on guest WiFi — because the guest threshold is 40. One feed-match is sufficient
evidence to block a guest device. The AI does not give an unknown device benefit of the doubt.

---

## The Dual-Threshold Story

```
Office (staff, known devices)    block at 80  ← ransomware C2 at score 75 = MONITOR
Guest WiFi (unknown devices)     block at 40  ← same feed-match score 40 = BLOCK

Score 40 outcome:
  Office staff → MONITOR  (flag for human review)
  Guest device → BLOCK    (isolated immediately)
```

The score is the same. The policy is different. The engine enforces both simultaneously.
