# MiniFW-AI — Education Sector Evidence Report
**Scenario:** Westgate Academy — student VPN bypass and content filter evasion  
**Version:** 2.2.0  
**Date:** 2026-05-26

---

## Before the Attempts

Westgate Academy's network has three segments: student (10.10.0.0/16, block at 70),
guest (192.168.100.0/24, block at 60), and staff (192.168.1.0/24, block at 80).

Normal educational traffic scores 18–22 across all segments. Khan Academy, BBC,
Wikipedia, Google — zero alerts, zero monitors, zero blocks. This is the baseline
the AI learned, and it never generates false positives against it.

Sample allow events from the clean baseline:

```
khanacademy.org    10.10.0.10   score 19  allow  EDU-SAFE-3A71C204
bbc.co.uk          10.10.0.11   score 21  allow  EDU-SAFE-7E29A103
wikipedia.org      10.10.0.12   score 18  allow  EDU-SAFE-9C88F501
google.co.uk       192.168.1.10 score 20  allow  EDU-SAFE-2B44D607
```

---

## Block 1 — Student VPN Bypass (student segment)

**Source:** 10.10.0.50 — student device  
**Segment policy:** student block threshold = **70**

A student queried nordvpn.com first — score 40, monitor only. Thirty seconds later
they queried `nordvpn-bypass.proxy.io` — a domain specifically built to tunnel through
school content filters. The YARA rule `EducationVpnProxy` matched on two strings:
`nordvpn-bypass` and `-bypass.proxy`. Feed match 40 + YARA 35 = 75, which crossed
the student threshold of 70.

```
10.10.0.20   instagram.com             monitor  score 40  social_media_student_network
10.10.0.50   nordvpn.com               monitor  score 40  vpn_service_student_network
10.10.0.50   nordvpn-bypass.proxy.io   BLOCK    score 75  dns_feed_match, education_vpn_proxy_yara
```

The block decision, raw:

```json
{
  "ts": "2026-05-26T09:00:24",
  "segment": "student",
  "client_ip": "10.10.0.50",
  "domain": "nordvpn-bypass.proxy.io",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "education_vpn_proxy_yara", "content_filter_bypass_attempt"],
  "sector": "education",
  "severity": "critical",
  "trace_id": "EDU-SAFE-C2A05E4F",
  "decision_owner": "SafeSearch Policy Engine"
}
```

The VPN tunnel was never established. The student was blocked in the DNS lookup phase —
before a single byte of tunneled traffic left the school network.

---

## Block 2 — Guest Network Content Filter Evasion

**Source:** 192.168.100.10 — guest/visitor device  
**Segment policy:** guest block threshold = **60**

A visitor on the guest WiFi queried `filter-bypass.student.io` — a domain whose name
alone is sufficient evidence. The `EducationContentFilter` YARA rule matched on
`filter-bypass.student`. Feed match 40 + YARA 35 = 75, crossing the guest threshold
of 60 on the first query.

```json
{
  "ts": "2026-05-26T09:00:26",
  "segment": "guest",
  "client_ip": "192.168.100.10",
  "domain": "filter-bypass.student.io",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "education_content_filter_yara", "guest_network_content_evasion"],
  "sector": "education",
  "severity": "critical",
  "trace_id": "EDU-SAFE-D3B16F5A",
  "decision_owner": "SafeSearch Policy Engine"
}
```

The guest network threshold of 60 is lower than student (70) because the school has
less certainty about who is on that network. A legitimate visitor has no reason to
query a domain named `filter-bypass.student.io`. The AI doesn't need to know who
the visitor is — the behavior is enough.

---

## Block 3 — Burst Attack (cascade block)

**Source:** 10.10.0.200 — student device  
**Type:** DNS burst — 200 queries in 5 seconds

A student sent 200 DNS queries for `nordvpn-bypass.proxy.io` in 5 seconds, attempting
to overwhelm the filter. The burst tracker fires at 50 queries per minute, forcing
the score to 100 regardless of other signals. All 200 queries were blocked. The IP
was isolated.

```json
{
  "ts": "2026-05-26T09:00:35",
  "segment": "student",
  "client_ip": "10.10.0.200",
  "domain": "nordvpn-bypass.proxy.io",
  "action": "block",
  "score": 100,
  "reasons": ["dns_burst_threshold_exceeded", "dns_feed_match", "education_vpn_proxy_yara", "burst_cascade_block"],
  "sector": "education",
  "severity": "critical",
  "trace_id": "EDU-SAFE-F5D38B7C",
  "decision_owner": "SafeSearch Policy Engine"
}
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Student block threshold | 70 |
| Guest block threshold | 60 |
| Score at VPN bypass block | 75 |
| Score at guest block | 75 |
| Score at burst block | 100 |
| VPN tunnels opened | 0 |
| Restricted content accessed | 0 bytes |
| False positives (Khan Academy, BBC, Wikipedia) | 0 |
| Human interventions | 0 |
| YARA rules triggered | EducationVpnProxy, EducationContentFilter |
| Audit trace IDs generated | 3 |

---

## What This Proves for a School Buyer

**Pattern-based detection beats blocklists.** NordVPN.com was monitored, not blocked —
it's a legitimate service that could be used outside school hours. `nordvpn-bypass.proxy.io`
was blocked because the domain name encodes the intent. A blocklist approach requires
someone to add every new bypass domain manually. YARA catches patterns: any domain
matching `nordvpn-bypass` or `-bypass.proxy` is blocked regardless of what new domain
the bypass service registers tomorrow.

**Segment-aware policy means appropriate response.** The guest WiFi blocked at 60.
The student network blocked at 70. Staff have headroom to 80. One system, three
policies, no manual per-device configuration.

**Safeguarding audit trail is built in.** Every event — allow, monitor, block —
carries a timestamp, source IP, domain, score, reasons array, and a trace ID
prefixed `EDU-SAFE-*`. If a governor, parent, or Ofsted inspection asks for
evidence of what a student was trying to access and what action was taken, the
log is the answer. Not "we think the filter caught it" — a structured, timestamped
decision record.

**No cloud dependency.** The YARA rules, ML model, and threat feed all run locally.
The school's network does not need internet access for the firewall to function.
Useful for schools with air-gapped or heavily segmented network architectures.
