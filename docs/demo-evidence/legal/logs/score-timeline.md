# Attack Score Timeline — Clifton & Associates LLP
**Demo run:** 2026-05-26  
**Scenario:** Ransomware C2 + Tor relay + privilege breach

---

## Normal Traffic

```
09:00:01  10.20.0.10  westlaw.com      score 19  ████░░░░░░░░░░░░░░░░  ALLOW  partner
09:00:03  10.20.0.11  lexisnexis.com   score 21  ████░░░░░░░░░░░░░░░░  ALLOW  partner
09:00:05  10.20.1.10  courts.gov       score 18  ████░░░░░░░░░░░░░░░░  ALLOW  associate
```

---

## Monitor — Cloud Upload (paralegal segment, threshold 70)

```
09:00:15  10.20.2.10  wetransfer-legal.io  score 40  ████████░░░░░░░░░░░░  MONITOR  ← feed=40, paralegal monitor=38, flagged
```

Score 40 exceeds the paralegal monitor threshold of 38. Flagged for review.
Not blocked — score hasn't reached the paralegal block threshold of 70.
The AI is surfacing the event for a human decision.

---

## Block 1 — Tor Relay (client room, threshold 62)

```
09:00:25  192.168.200.5  tor-exit-relay.onion-gw.net  score 75  ███████████████░░░░░  BLOCK  client (threshold 62)
```

Feed 40 + YARA (`LegalTorExitRelay`: `tor-exit-relay` + `onion-gw`) 35 = 75. Thirteen points above client threshold of 62.

---

## Block 2 — Ransomware C2 (associate segment, threshold 72)

```
09:00:35  10.20.1.20  clio-encrypt.c2-server.ru  score 75  ███████████████░░░░░  BLOCK  associate (threshold 72)
```

Feed 40 + YARA (`LegalRansomwareC2`: `clio-encrypt`) 35 = 75. Three points above associate threshold of 72. Note: the associate threshold of 72 was set precisely so that feed+YARA (75) fires cleanly — confirmed in policy.json comment.

**C2 beacon blocked before attacker received implant confirmation.**

---

## Block 3 — Privilege Violation (paralegal segment, threshold 70)

```
09:00:45  10.20.2.50  opposing-counsel.harvest.io  score 75  ███████████████░░░░░  BLOCK  paralegal (threshold 70)
```

Feed 40 + YARA (`LegalPrivilegeViolation`: `opposing-counsel.harvest`) 35 = 75. Five points above paralegal threshold.

**Zero bytes of privileged case data exfiltrated.**

---

## Block 4 — Burst Cascade (associate)

```
09:00:55  10.20.1.20  clio-encrypt.c2-server.ru ×200  score 100  BLOCK cascade
```

200 queries, 50 QPM burst threshold hit. Score overridden to 100.

---

## Threshold Architecture

```
Partner    ─────────────────────────────────────────────────────────── 85
                                                 ↑ feed+YARA (75) doesn't reach partner
Associate  ─────────────────────────────────── 72  ← feed+YARA (75) fires here
Paralegal  ──────────────────────────────── 70      ← feed+YARA (75) fires here
Client     ────────────────────────────  62         ← feed+YARA (75) fires here
Guest      ───────────────────────────  60          ← feed+YARA (75) fires here
           
           0   10   20   30   40   50   60   70   80   90   100
```

Partners are protected from autonomous blocks at the feed+YARA score level.
Associates, paralegals, client rooms, and guests are not.
