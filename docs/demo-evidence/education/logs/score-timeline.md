# Attack Score Timeline — Westgate Academy
**Demo run:** 2026-05-26  
**Scenario:** Student VPN bypass + guest content filter evasion

---

## Normal Traffic (student and staff segments)

```
09:00:01  10.10.0.10   khanacademy.org    score 19  ████░░░░░░░░░░░░░░░░  ALLOW  student
09:00:03  10.10.0.11   bbc.co.uk          score 21  ████░░░░░░░░░░░░░░░░  ALLOW  student
09:00:05  10.10.0.12   wikipedia.org      score 18  ████░░░░░░░░░░░░░░░░  ALLOW  student
09:00:07  192.168.1.10 google.co.uk       score 20  ████░░░░░░░░░░░░░░░░  ALLOW  staff
```

Zero monitor events from legitimate education traffic. SafeSearch-enforced domains
score in the 18–22 band regardless of segment.

---

## Attack Sequence — VPN Bypass (student segment, threshold 70)

```
09:00:20  10.10.0.20   instagram.com              score  40  ████████░░░░░░░░░░░░  MONITOR  ← social media
09:00:22  10.10.0.50   nordvpn.com                score  40  ████████░░░░░░░░░░░░  MONITOR  ← VPN service
09:00:24  10.10.0.50   nordvpn-bypass.proxy.io    score  75  ███████████████░░░░░  BLOCK    ← YARA: vpn-bypass + -bypass.proxy
```

The key escalation is nordvpn.com → nordvpn-bypass.proxy.io. The VPN service domain
itself scores 40 and stays in monitor. The bypass tunnel domain hits the YARA rule
`EducationVpnProxy` on two strings (`nordvpn-bypass` and `-bypass.proxy`), adding 35
points to the feed match score of 40, reaching 75. That crosses the student threshold of 70.

**VPN tunnel never opened. Student blocked in 4 seconds from first VPN query.**

---

## Attack Sequence — Guest Content Filter Evasion (guest segment, threshold 60)

```
09:00:26  192.168.100.10  filter-bypass.student.io  score  75  ███████████████░░░░░  BLOCK  ← YARA: filter-bypass.student
```

Single-event block on the guest network. The domain matched `EducationContentFilter`
on the string `filter-bypass.student`. Feed match 40 + YARA 35 = 75, which crosses
the guest threshold of 60 immediately.

**The visitor/parent didn't even see a second DNS query. Blocked on first contact.**

---

## Burst Attack — VPN Proxy (200 queries from single IP)

```
09:00:35  10.10.0.200  nordvpn-bypass.proxy.io x200  score 100  BLOCK (burst cascade)
```

200 DNS queries in 5 seconds from 10.10.0.200. The burst tracker fires at 50 queries
per minute threshold, adding the burst flag and setting score to 100 regardless of
other signals. All 200 queries blocked. IP isolated.

---

## Evidence Summary

| Metric                        | Block #1 (VPN)          | Block #2 (Guest)        | Block #3 (Burst)        |
|-------------------------------|-------------------------|-------------------------|-------------------------|
| Source IP                     | 10.10.0.50              | 192.168.100.10          | 10.10.0.200             |
| Segment                       | student                 | guest                   | student                 |
| Block threshold               | 70                      | 60                      | 70 (burst overrides)    |
| Score at block                | 75                      | 75                      | 100                     |
| YARA rule triggered           | EducationVpnProxy       | EducationContentFilter  | EducationVpnProxy       |
| VPN/proxy tunnel opened       | No                      | No                      | No                      |
| Restricted content accessed   | No                      | No                      | No                      |
| SafeSearch bypass succeeded   | No                      | No                      | No                      |
| Human intervention            | None                    | None                    | None                    |
| Audit trace ID                | EDU-SAFE-C2A05E4F       | EDU-SAFE-D3B16F5A       | EDU-SAFE-F5D38B7C       |
