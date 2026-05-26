# MiniFW-AI — Technical Client Q&A
**For:** Sales calls, technical buyers, procurement reviews, CTO/CISO conversations  
**Version:** 2.2.0

---

## "Does this inspect encrypted traffic?"

**Short answer:** DNS-first. It does not decrypt TLS. It doesn't need to.

**Full answer:**  
MiniFW-AI detects threats at the DNS resolution layer, not by decrypting payload.
Every device on the network must resolve a domain name before making a connection.
That DNS query is unencrypted (or observable via DoH interception at the gateway)
and happens before the TLS handshake. The system intercepts that query and scores it.

For TLS connections that bypass DNS (direct IP, hardcoded IPs), the engine also
watches flow data via `conntrack` and can score by ASN deny-list and IP reputation.
The TLS SNI extension (sent in plaintext during the handshake) is also extracted
via Zeek and scored separately — adding up to +35 points if the SNI matches a
threat feed.

**What this means in practice:**  
A ransomware beacon to `c2.locky-decrypt-files.xyz` is detectable at the DNS layer
before any TLS connection is established. The block fires before the session exists.
For malware that uses hardcoded IPs without DNS, the flow collector and ASN deny-list
are the backstop.

---

## "What about false positives?"

**Short answer:** The scoring model is additive and requires multiple signals to block.
A single low-confidence signal produces a monitor event, not a block.

**Full answer:**  
The scoring pipeline adds points from independent signals:
- DNS feed match: +40 (known bad domain)
- TLS SNI match: +35
- ASN deny-list: +15
- DNS burst (volumetric): +10
- MLP behavioural model: 0–30
- YARA pattern match: 0–35

A domain must score above the segment's block threshold before an autonomous block fires.
In the hospital demo, that threshold is 80 for staff and 45 for medical devices.
Office365.com scores 0. Internal clinical domains score 0. The false-positive count
in all demo evidence packs is zero.

If a false positive does occur:
1. The event appears as a MONITOR or BLOCK in the dashboard
2. An operator can release the block with one click
3. The block auto-expires after 86,400 seconds (24 hours) via the ipset TTL
4. The threshold can be raised in `policy.json` without a service restart

The system is tunable per-segment. A known safe domain can be added to a local
whitelist feed (`config/feeds/allow_domains.txt`), and it will score 0 permanently.

---

## "Can this run offline?"

**Short answer:** Yes. Fully air-gapped operation is supported.

**Full answer:**  
All detection logic runs on-device:
- Threat intelligence feeds are loaded from local flat files at startup
  (`config/feeds/deny_domains.txt`, `deny_ips.txt`, `deny_asns.txt`)
- The MLP model is a serialised binary file loaded into RAM at startup
- YARA rules are compiled from local `.yar` files at startup
- nftables and ipset enforce decisions via kernel calls — no network needed

There is no cloud dependency, no telemetry, no call-home, and no license server.
The feeds are updated by copying new files to the feeds directory and sending
`SIGHUP` to the engine process (or restarting the service).

For air-gapped environments, the feed update process is:
1. Pull updated feeds on an internet-connected machine
2. Copy to USB
3. Transfer to the gateway
4. `sudo systemctl reload minifw-engine` (production) or restart the demo

---

## "Can this work without agents?"

**Short answer:** Yes. No agents. No endpoint software. No device enrollment.

**Full answer:**  
MiniFW-AI sits on the network gateway (or a dedicated Linux appliance on the LAN).
It observes DNS queries using one of four backends:
- `dnsmasq` log parsing (production, most common)
- `journald` query log
- UDP DNS listener (passive tap)
- `none` (demo/flow-only mode)

Every device on the network — phone, laptop, IoT device, POS terminal, medical device —
is covered without any software installed on the device. This is the critical property
for IoT and IoMT environments where you cannot install agents on the devices
(ventilators, infusion pumps, payment terminals, CCTV cameras).

The firewall engine runs as a systemd service (`minifw-engine`) on the gateway.
The web dashboard runs as a separate service (`minifw-web`) — also on the gateway.
Client devices never know MiniFW-AI exists.

---

## "How fast is blocking?"

**Short answer:** Typically under one second from DNS query to nftables DROP rule.

**Full answer:**  
The detection loop is event-driven, not batch:
1. DNS event arrives (from dnsmasq log, journald, or UDP tap)
2. Event passes through the scoring pipeline synchronously
3. If score ≥ threshold → `ipset_add()` is called immediately
4. `ipset_add()` inserts the IP into the kernel ipset via a subprocess call to `ipset add`
5. The nftables ruleset references the ipset — the DROP rule takes effect instantly

The time from DNS query to block is dominated by the log-tail polling interval
(configurable, default ~500ms) plus the subprocess call to `ipset add` (~20ms).
Under normal load, total latency is 200ms–800ms.

In practice, the attacker's next DNS query (or the TCP connection attempt after
the C2 domain resolved) hits the DROP rule. The C2 server receives no SYN packet.
The attacker's session never establishes.

**Hard Gate bypass:** For volumetric attacks (PPS threshold, DNS burst), the hard gate
fires immediately — score is forced to 100 and the block is written before the MLP
or YARA steps run.

---

## "Can logs be exported?"

**Short answer:** Yes. All events are JSONL, all blocks have audit trace IDs,
and the dashboard has a download endpoint.

**Full answer:**  
Every decision (allow, monitor, block) is written to JSONL log files:
- `logs/events.jsonl` — complete event stream (domain, IP, score, reasons, action)
- `logs/audit.jsonl` — block-only audit trail with trace IDs

Each JSONL record is a single JSON object per line — trivially parseable by any log
aggregator (Splunk, Elastic, Graylog, Datadog, AWS CloudWatch).

Each block record contains:
- `ts` — ISO 8601 timestamp
- `trace_id` — sector-specific unique ID (e.g., `HIPAA-PHI-C2A05E4F`, `GOV-SOV-D3B16F5A`)
- `client_ip`, `domain`, `score`, `reasons`, `action`, `severity`
- `decision_owner` — policy engine that made the decision

The web dashboard provides:
- A live event feed (auto-refreshing)
- Per-event drill-down with full JSON
- Block management (release, search, filter)

For SIEM integration: the JSONL files are written atomically and can be tailed
by any log shipper (Filebeat, Fluentd, Vector) without a dedicated connector.
For compliance exports (HIPAA audit, PCI-DSS log review): copy `logs/audit.jsonl`
and filter by `"action": "block"`. The trace IDs provide a correlation key across
all incident response tooling.

---

## Pricing / Positioning Context

These answers assume you are talking to a **technical buyer** who wants to understand
the architecture. For a **non-technical buyer**, lead with outcomes (blocked, logged,
no downtime) and defer technical depth to a follow-up call.

For compliance buyers (HIPAA, PCI-DSS, Cyber Essentials):
- The trace IDs are the audit evidence
- The JSONL logs are the contemporaneous record
- The block events prove "immediate action" on detection

For IT managers:
- No agents to manage
- Threshold tunable without restart
- Recovery (fast_reset) is under 60 seconds
