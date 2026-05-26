# Attack Score Timeline — National Sovereign Infrastructure
**Demo run:** 2026-05-26  
**Scenario:** APT28 C2 beacon + Tor relay + burst attack

---

## Normal Traffic (internal and classified segments)

```
09:00:01  10.0.0.10   data.gov         score 19  ████░░░░░░░░░░░░░░░░  ALLOW  internal
09:00:03  10.0.0.11   nist.gov         score 21  ████░░░░░░░░░░░░░░░░  ALLOW  internal
09:00:05  10.0.0.12   parliament.gov   score 18  ████░░░░░░░░░░░░░░░░  ALLOW  internal
09:00:09  10.1.0.10   nist.gov         score 19  ████░░░░░░░░░░░░░░░░  ALLOW  classified
```

---

## Near Miss — Phishing Portal (internal segment, threshold 75)

```
09:00:15  10.0.0.50   gov-login-verify.com  score 40  ████████░░░░░░░░░░░░  ALLOW*  ← feed=40, monitor threshold=45, NOT flagged
```

Score 40 is below the internal monitor threshold of 45. This domain scores high enough
to be suspicious but not enough to trigger a monitor event on the internal segment.
Talking point: adding it to the deny feed triggers a monitor at score 40. The AI is
showing where the feed needs to be extended.

---

## Block 1 — APT28 C2 Beacon (classified segment, threshold 70)

```
09:00:25  10.1.0.20   apt28-c2.sovereign-exfil.ru  score 75  ███████████████░░░░░  BLOCK  classified
```

Feed match 40 + YARA (`GovAptC2`: `apt28-c2` + `sovereign-exfil`) 35 = 75.
Classified threshold is 70. Five points of headroom. The C2 beacon was blocked
before the attacker received confirmation the implant was active.

**From first external query to block: single DNS event.**

---

## Block 2 — Tor Relay (guest/citizen-facing network, threshold 65)

```
09:00:35  192.168.200.5   tor-state-relay.onion-gw.net  score 75  ███████████████░░░░░  BLOCK  guest
```

Feed match 40 + YARA (`GovTorRelay`: `tor-state-relay` + `onion-gw`) 35 = 75.
Guest threshold is 65. Sovereignty policy: Tor access from government premises is
prohibited regardless of segment.

---

## Monitor — Classified Document Leak Site (classified segment)

```
09:00:45  10.1.0.30   govdocs-leak.onion.to  score 40  ████████░░░░░░░░░░░░  MONITOR  classified
```

Score 40 hits the classified monitor threshold of 40 exactly. The YARA rule
`GovDataLeak` matched on `govdocs-leak`. Not enough to block autonomously but
enough for a human reviewer to investigate which classified-network device queried
a government document leak site.

---

## Block 3 — APT Burst Cascade (classified segment)

```
09:00:55  10.1.0.99   apt28-c2.sovereign-exfil.ru ×250  score 100  BLOCK cascade
```

250 DNS queries in ~5 seconds. Government burst threshold: 40 QPM.
Score overridden to 100. All 250 queries blocked. IP isolated.

---

## Evidence Summary

| Metric | Block 1 (APT C2) | Block 2 (Tor Relay) | Block 3 (Burst) |
|--------|------------------|---------------------|-----------------|
| Source IP | 10.1.0.20 | 192.168.200.5 | 10.1.0.99 |
| Segment | classified | guest | classified |
| Threshold | 70 | 65 | 70 |
| Score at block | 75 | 75 | 100 |
| YARA rule | GovAptC2 | GovTorRelay | GovAptC2 |
| C2 confirmation sent | No | — | No |
| Audit trace ID | GOV-SOV-C2A05E4F | GOV-SOV-D3B16F5A | GOV-SOV-F5D38B7C |
