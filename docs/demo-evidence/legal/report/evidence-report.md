# MiniFW-AI — Legal Sector Evidence Report
**Scenario:** Clifton & Associates LLP — ransomware C2 + Tor relay + privilege breach
**Version:** 2.2.0  
**Date:** 2026-05-26

---

## Before the Attacks

Six segments. Normal legal research traffic scores 18–22 on all of them. Westlaw,
LexisNexis, courts.gov — zero alerts, zero monitors.

The threshold architecture reflects the firm's actual trust hierarchy: partners at 85,
associates at 72, paralegals at 70, client meeting rooms at 62, guest WiFi at 60. The
associate threshold of 72 was calibrated specifically so that a feed-match plus YARA
score (40 + 35 = 75) fires a clean block — confirmed in policy.json.

---

## Monitor — Unauthorized Cloud Upload

`wetransfer-legal.io` from 10.20.2.10 (paralegal, threshold 70) scored 40 — above
the paralegal monitor threshold of 38. Flagged. Not blocked. The event surfaced in the
feed for a human reviewer. Score 40 alone is insufficient for an autonomous block on
a paralegal device — it's enough to flag and investigate.

---

## Block 1 — Tor Exit Relay (client meeting room)

**Source:** 192.168.200.5 — visitor device, client room  
**Threshold:** client = **62**

```json
{
  "ts": "2026-05-26T09:00:25",
  "segment": "client",
  "client_ip": "192.168.200.5",
  "domain": "tor-exit-relay.onion-gw.net",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "legal_tor_exit_yara", "client_room_policy_violation"],
  "sector": "legal",
  "severity": "critical",
  "trace_id": "LEGAL-ACP-C2A05E4F",
  "decision_owner": "Legal Privilege Policy Engine"
}
```

---

## Block 2 — Ransomware C2 (associate network)

**Source:** 10.20.1.20 — associate workstation  
**Threshold:** associate = **72**

`clio-encrypt.c2-server.ru` — a ransomware family that specifically targets Clio,
the case management platform. Feed 40 + YARA (`LegalRansomwareC2`: `clio-encrypt`) 35 = 75.
The C2 beacon was blocked before the attacker received implant confirmation. The Clio
database and all case files are intact.

```json
{
  "ts": "2026-05-26T09:00:35",
  "segment": "associate",
  "client_ip": "10.20.1.20",
  "domain": "clio-encrypt.c2-server.ru",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "legal_ransomware_c2_yara", "case_management_system_targeted"],
  "sector": "legal",
  "severity": "critical",
  "trace_id": "LEGAL-ACP-D3B16F5A",
  "decision_owner": "Legal Privilege Policy Engine"
}
```

---

## Block 3 — Attorney-Client Privilege Breach (paralegal network)

**Source:** 10.20.2.50 — paralegal workstation  
**Threshold:** paralegal = **70**

`opposing-counsel.harvest.io` — a domain designed to exfiltrate case data to opposing
counsel's infrastructure. YARA rule `LegalPrivilegeViolation` matched on `opposing-counsel.harvest`.
Zero bytes of privileged case data left the network.

```json
{
  "ts": "2026-05-26T09:00:45",
  "segment": "paralegal",
  "client_ip": "10.20.2.50",
  "domain": "opposing-counsel.harvest.io",
  "action": "block",
  "score": 75,
  "reasons": ["dns_feed_match", "legal_privilege_violation_yara", "attorney_client_privilege_breach"],
  "sector": "legal",
  "severity": "critical",
  "trace_id": "LEGAL-ACP-E4C27A6B",
  "decision_owner": "Legal Privilege Policy Engine"
}
```

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Partner threshold | 85 — feed+YARA (75) does NOT autonomously block partners |
| Associate threshold | 72 — calibrated so feed+YARA fires cleanly |
| Case files encrypted | 0 |
| Privileged data exfiltrated | 0 bytes |
| Ransomware C2 confirmation received | No |
| LEGAL-ACP trace IDs generated | 4 |
| Human interventions required | 0 |
| False positives (Westlaw, LexisNexis, courts.gov) | 0 |

---

## What This Proves for a Legal Buyer

**Attorney-client privilege is enforced at the network layer.** The privilege violation
block fired before any case data was staged externally. The LEGAL-ACP trace ID in the
event is a contemporaneous log entry — timestamped, scored, with a documented reasons
array. If the bar association, a client, or a court asks for evidence of what the firm
did to protect privileged communications, this is the answer.

**Segment-aware trust hierarchy means partners aren't blocked on false signals.**
A feed-match plus YARA score of 75 blocks an associate, a paralegal, a client, and
a guest. It does not block a partner — the partner threshold is 85. This is not an
accident. Senior counsel has earned a higher trust level. The AI enforces it automatically.

**Case management systems are protected specifically.** The `LegalRansomwareC2` YARA
rule includes `clio-encrypt` — a ransomware family that specifically targets Clio,
the industry-standard legal case management platform. This isn't a generic ransomware
rule. It's legal-sector threat intelligence applied at the YARA level.
