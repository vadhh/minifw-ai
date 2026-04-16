# MiniFW-AI — Demo Master Script

**Version:** 2.2.0
**Duration:** ~45 minutes full | ~15 minutes per mode
**Audience:** Technical evaluators, IT leads, security officers

---

# INTRODUCTION

## Opening Statement

> "What you're about to see is a single AI-powered firewall engine deployed across three
> completely different regulated industries — healthcare, SME, and gambling — without changing
> a single line of engine code.
>
> The same threat detection pipeline. The same YARA scanner. The same AI scoring model.
> What changes is the product identity, the threat feeds, the enforcement policy, and the
> compliance layer — all driven by a single environment variable: `PRODUCT_MODE`.
>
> We're going to walk through each mode, trigger real threats, watch the engine decide,
> and confirm the block hits the kernel."

---

## What We Are Demonstrating

MiniFW-AI is a DNS-layer AI firewall with three core capabilities:

1. **Real-time threat detection** — DNS query inspection using deny-feeds, YARA signatures,
   MLP scoring, ASN/IP blocking, and burst detection — all in a single decision pipeline.

2. **Sector-aware enforcement** — the engine knows which network segment a device is on
   and applies the correct threshold. The same domain that gets monitored on the office
   network gets blocked immediately on the guest network.

3. **Multi-sector product packaging** — one engine binary, one dashboard codebase, three
   distinct regulated products. Policy, feeds, YARA rules, thresholds, and UI labels all
   swap via `PRODUCT_MODE`.

---

# PROBLEM

## The Problem We Are Solving

> "Regulated industries each face a version of the same problem: they need a firewall that
> understands their compliance context — not just a generic block/allow list."

| Industry | Compliance Requirement | What generic firewalls miss |
|----------|----------------------|----------------------------|
| **Healthcare** | HIPAA — patient data must not leak; IoMT devices are critical infrastructure | No IoMT subnet awareness; no payload redaction; no healthcare-specific threat feeds |
| **SME** | Data protection, ransomware resilience | Signature-only detection misses C2 beacons; no per-segment enforcement |
| **Gambling** | Regulatory domain blocking, staff conduct audit trail | Cannot separate gambling enforcement from general malware detection; no wildcard domain patterns |

> "The alternative is buying three separate products, maintaining three separate policy sets,
> and training three separate teams. MiniFW-AI solves this with one engine, one dashboard,
> and one configuration file per sector."

---

## The Detection Pipeline (One Slide / One Minute)

Every DNS query goes through this chain — in every mode:

```
DNS Query received
       │
       ▼
Hard Gate check       → Immediate block=100 if matched (known-bad IP/ASN override)
       │
       ▼
Deny-Feed match       → +40 if domain in sector threat feed
       │
       ▼
YARA scan             → 0–35 based on raw query byte patterns
       │
       ▼
TLS/SNI match         → +35 if SNI in deny list (Zeek-sourced)
       │
       ▼
MLP inference         → 0–30 based on flow features
       │
       ▼
ASN / IP deny         → +15 each if registered
       │
       ▼
Burst detection       → +10 if query rate anomaly
       │
       ▼
Segment threshold     → Compare final score to Monitor / Block threshold for this network zone
       │
       ├── score < monitor_threshold  →  ALLOW
       ├── score < block_threshold    →  MONITOR  (log + alert)
       └── score ≥ block_threshold    →  BLOCK    (nft kernel drop + log)
```

> "Most-severe result wins. All layers run to completion — a YARA hit does not short-circuit
> the DNS feed check. Every threat signal that fired is recorded in the event reasons."

---

# DEMO

---

## PRE-DEMO CHECKLIST

Before presenting, confirm:

- [ ] Docker running, ports 8443 / 8444 / 8445 free
- [ ] `./demo.sh hospital up` started and healthy (wait for `[INJECTOR] Loop 1`)
- [ ] `./demo.sh sme up` started (or ready to start on screen)
- [ ] `./demo.sh gambling up` started (or ready to start on screen)
- [ ] Browser open to `https://localhost:8443` — certificate warning accepted
- [ ] Terminal split: browser on left, `docker compose logs -f` on right

---

## MODE A — HOSPITAL

**Start command:**
```bash
cd docker && ./demo.sh hospital up
```

**Login:** `https://localhost:8443` → `admin` / `Hospital1!`

---

### A-0. Mode Badge — Point Out First

> "Before we touch a single event — look at the navbar. It says:
> `Mode: Hospital — HIPAA · IoMT · Healthcare` in red.
> The sidebar shows `HOSPITAL`. The IoMT Alerts menu item is visible.
>
> This is server-side rendered via Jinja2 — no JavaScript fetch, no delay.
> The moment the container starts with `PRODUCT_MODE=minifw_hospital`, every page
> carries this identity."

---

### A-1. Dashboard — Firewall Status Panel

| Row | Expected | Talking point |
|-----|----------|---------------|
| Firewall Engine | **Active** (green) | Detected via audit log sentinel across Docker containers |
| Detection Mode | **AI Enhanced** | DNS + YARA + MLP pipeline active |
| Burst Protection | **Active** | Per-IP query rate tracking enabled |
| Zeek TLS/SNI | **Inactive** | Zeek not running in demo — expected |
| DNS Collector | **Active** | Receiving injected queries |
| Flow Tracking | **Inactive** | `MINIFW_DISABLE_FLOWS=1` — Docker has no real traffic |

> "Flow Tracking showing Inactive is expected and correct in this demo environment.
> In production deployment it would be Active, feeding the MLP scorer."

---

### A-2. Wait for First Injector Loop (~33 seconds)

Watch terminal for:
```
minifw_injector | [INJECTOR] Loop 1 complete — 256 events injected
```

Dashboard should show:
- **System Intelligence:** YARA Hits: 1+
- **Protection Summary:** Blocked: 250+, Threats Detected: 254+

---

### A-3. Scenario Walkthrough — Events Page (`/admin/events`)

Navigate to Events. Walk through each row:

---

**Scenario A-1 — Benign Traffic (ALLOW)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `192.168.1.1` |
| Action | **Allowed** |
| Score | 0 |

> "Score zero — clean traffic, Windows Update. But look at the domain: `[REDACTED]`.
> In hospital mode, `redact_payloads: true` applies to *every* event — allowed, monitored,
> and blocked alike. Under HIPAA, even a list of domains a device was allowed to visit
> can constitute patient-linked metadata. The engine redacts before the log is written."

---

**Scenario A-2 — IoMT Device Contacts Ransomware C2 (MONITOR, critical)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.0.5` |
| Action | **Monitor** |
| Score | 40 |
| Severity | **critical** |
| Reasons | `dns_denied_domain`, `iomt_device_alert` |

> "`10.20.0.5` is in the IoMT subnet `10.20.0.0/24` — medical devices.
> The actual domain is `lockbit-blog.com`, in `healthcare_threats.txt`.
> Two things happen simultaneously: the domain is `[REDACTED]` (HIPAA redaction),
> and severity is forced to `critical` because the engine detects this is an IoMT device.
> A medical device reaching out to a ransomware domain is a critical incident regardless
> of whether the score crosses the block threshold."

---

**Scenario A-3 — Phishing from Workstation (MONITOR, info)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Severity | info |
| Reasons | `dns_denied_domain` |

> "Same score as A-2: 40. Same action: Monitor. But severity is `info`, not `critical`.
> `192.168.1.50` is a staff workstation — not an IoMT device.
> The domain is `my-chart-login.com` — a fake MyChart patient portal phishing page.
> A staff member clicking a phishing link is serious, but it is not the same incident
> priority as a ventilator or infusion pump phoning home to ransomware infrastructure.
> Same score. Different triage. That distinction is automatic."

---

**Scenario A-4 — YARA + DNS Combined Hit from IoMT (MONITOR, critical)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.1.10` |
| Action | **Monitor** |
| Score | 75 |
| Severity | **critical** |
| Reasons | `yara_MedicalRansomware`, `dns_denied_domain`, `iomt_device_alert` |

> "Score 75 — three reasons. Let me break down how we got here.
> Domain is `RyukReadMe.example.com`.
>
> First: DNS feed match against `healthcare_threats.txt` → +40.
> Second: YARA scanned the raw bytes of the DNS query and found the string `RyukReadMe`
> — that triggers the `MedicalRansomware` rule → +35.
> Total: 75.
>
> These two layers ran independently and simultaneously. YARA does not care whether the
> DNS feed already flagged it. Every detection layer reports its finding.
>
> Third: `10.20.1.10` is in IoMT subnet `10.20.1.0/24` → severity boosted to critical.
>
> The YARA counter in System Intelligence just incremented. That is a live YARA scan
> of every DNS query — not a known-bad list lookup, not a hash check. Byte-level
> payload inspection in real time."

---

**Scenario A-5 — EHR Ransomware C2 from IoMT Device (MONITOR, critical)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.0.5` |
| Action | **Monitor** |
| Score | 40 |
| Severity | **critical** |
| Reasons | `dns_denied_domain`, `iomt_device_alert` |

> "Same device as A-2 — `10.20.0.5`. Different domain: `ehr-software-update.com`,
> a known EHR-targeting ransomware C2 in `healthcare_threats.txt`.
>
> Two critical IoMT alerts in a single 33-second loop from the same device IP.
> In a live SOC, that is an immediate incident — same device, two separate ransomware
> domains, back to back. The engine logged both. The severity on both is critical.
> An on-call analyst has everything they need to isolate that device."

---

**Scenario A-6 — Data Broker Burst, Enforcement (BLOCK, ×250)**

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `172.16.0.99` |
| Action | **Blocked** |
| Score | 50 |
| Segment | mednet |
| Reasons | `dns_denied_domain`, `burst_behavior` |

> "This is the enforcement scenario. `172.16.0.99` is on the `mednet` segment —
> `172.16.0.0/16`, the clinical network. Block threshold for mednet: 80, minus the
> hospital sector's −5 block adjustment = **effective threshold of 40**.
>
> First DNS query for `medrecords-transfer.io` — a data-broker exfiltration endpoint
> in `healthcare_threats.txt`: dns_denied +40 = score 40. That meets the threshold.
> The engine calls:
> `nft add element inet minifw minifw_block_v4 { 172.16.0.99 }`
> Kernel-level drop. Zero application processing on subsequent packets.
>
> Burst fires: +10 → score climbs to 50. 250 queries per loop.
> Watch the Blocked counter on the dashboard. That jump is real."

---

**CLI Verification — Confirm the Block Hit the Kernel**

```bash
docker exec minifw_engine nft list set inet minifw minifw_block_v4
```

Expected output:
```
table inet minifw {
    set minifw_block_v4 {
        type ipv4_addr
        flags timeout
        timeout 1d
        elements = { 172.16.0.99 timeout 1d expires ... }
    }
}
```

> "The decision happened in the application. The enforcement happened in the kernel.
> `172.16.0.99` is in the nftables block set. Any subsequent packet from that IP
> is dropped before it reaches any process."

---

**Raw Log Verification**

```bash
docker exec minifw_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool
```

Expected key fields:
```json
{
  "domain":       "[REDACTED]",
  "severity":     "critical",
  "sector":       "hospital",
  "product_mode": "minifw_hospital"
}
```

> "Every field. Every event. Structured JSON. SIEM-ready on day one."

---

## MODE B — SME

**Start command:**
```bash
cd docker && ./demo.sh sme up
```

**Login:** `https://localhost:8444` → `admin` / `SME_Demo1!`

---

### B-0. Mode Badge

> "Navbar: `Mode: SME — Establishment · Balanced Protection` in blue.
> IoMT Alerts menu item is gone — it is hidden via a Jinja2 conditional that checks
> `product_mode == minifw_hospital`. No code change. Template-level product isolation."

---

### B-3. Scenario Walkthrough — Events Page

---

**Scenario B-1 — Benign Traffic (ALLOW)**

| Field | Value |
|-------|-------|
| Domain | `office365.com` |
| Client IP | `192.168.1.10` |
| Action | **Allowed** |
| Score | 0 |

> "Domain shows in plain text. No HIPAA redaction. In SME mode you want exact
> domains — your incident response team needs to know what site an employee visited,
> not a redacted placeholder."

---

**Scenario B-2 — Phishing from Employee Workstation (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `login-paypal-secure-verify.com` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Reasons | `dns_denied_domain` |

> "Domain visible. Compare to the hospital event for the same domain class — there
> it would be `[REDACTED]`. Here it is `login-paypal-secure-verify.com`. Your
> security team can act on that immediately."

---

**Scenario B-3 — Ransomware C2 + YARA (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `Locky.decrypt-files.net` |
| Client IP | `192.168.1.100` |
| Action | **Monitor** |
| Score | 75 |
| Reasons | `yara_SmeRansomware`, `dns_denied_domain` |

> "Two layers. DNS: +40. YARA `SmeRansomware` found `Locky` in the raw query bytes: +35.
> Total: 75. Office block threshold is 80. We are 5 points below a block.
>
> That gap is a policy decision, not a limitation. One configuration change —
> lower the office block threshold from 80 to 75 — and this is an immediate block.
> The engine does not change. Only the threshold value changes."

---

**Scenario B-4 — Cryptominer C2 + YARA (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `xmrig-pool.crypto-mine.io` |
| Client IP | `192.168.1.200` |
| Action | **Monitor** |
| Score | 75 |
| Reasons | `yara_SmeCryptoMiner`, `dns_denied_domain` |

> "`xmrig` in the hostname triggers `SmeCryptoMiner` YARA rule: +35. DNS: +40. Score 75.
>
> Two different YARA rules fired in the same injector loop: ransomware and cryptominer.
> YARA runs per-query with no inter-rule cooldown. The YARA Hits counter in System
> Intelligence is now at 2."

---

**Scenario B-5 — Generic C2 Beacon (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `c2-data-collect.net` |
| Client IP | `10.0.0.50` |
| Action | **Monitor** |
| Score | 40 |
| Reasons | `dns_denied_domain` |

> "No YARA match here. Pure feed-based detection. `c2-data-collect.net` is in
> `deny_domains.txt`: +40. Score 40, office threshold 80 — monitored.
>
> Shows the engine catches C2 beacons without needing a YARA signature.
> Feed coverage alone is sufficient for known-bad domains."

---

**Scenario B-6 — Guest Network Burst, Enforcement (BLOCK, ×250)**

| Field | Value |
|-------|-------|
| Domain | `ads-malware-tracker.net` |
| Client IP | `172.16.1.99` |
| Action | **Blocked** |
| Score | 50 |
| Segment | guest |
| Reasons | `dns_denied_domain`, `burst_behavior` |

> "Same domain class as B-2 through B-5 — but the IP is `172.16.1.99`, guest WiFi.
> Guest block threshold: 40. First query: dns_denied +40 = score 40 ≥ 40 → BLOCK.
> `nft add element inet minifw minifw_block_v4 { 172.16.1.99 }`
>
> The same domain from `192.168.1.50` (office) scores 40 and gets monitored.
> From `172.16.1.99` (guest) it scores 40 and gets blocked.
> Same score. Different threshold. Network zone is the deciding factor."

---

**CLI Verification**

```bash
docker exec minifw_sme_engine nft list set inet minifw minifw_block_v4
docker exec minifw_sme_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool
```

---

## MODE C — GAMBLING

**Start command:**
```bash
cd docker && ./demo.sh gambling up
```

**Login:** `https://localhost:8445` → `admin` / `Gambling1!`

---

### C-0. Mode Badge + Key Config

> "Navbar: `Mode: Gambling — Regulatory Enforcement · Domain Blocking` in purple.
> System Intelligence panel reads: **Establishment Sector** — gambling runs on the
> establishment sector engine with two additional environment variables:
>
> `GAMBLING_ONLY=1` — flags this as a regulatory enforcement deployment.
> `ALLOWED_DETECTION_TYPES=gambling` — this is the critical one.
>
> It tells the engine: ignore every base deny-feed hit. Only score on `gambling_domains.txt`.
> A gambling operator's firewall should not fire on generic phishing domains from a
> shared threat intel feed. Only gambling-domain violations are relevant here."

---

### C-1. Scenario Walkthrough — Events Page

---

**Scenario C-1 — Benign Work Traffic (ALLOW)**

| Field | Value |
|-------|-------|
| Domain | `office365.com` |
| Client IP | `192.168.1.10` |
| Action | **Allowed** |
| Score | 0 |

> "`office365.com` is not in `gambling_domains.txt`. With `ALLOWED_DETECTION_TYPES=gambling`
> the engine completely suppresses base deny-feed scoring. Score zero. Allowed.
>
> In hospital or SME mode this would still score zero — but the mechanism is different.
> Here we have explicitly told the engine: treat everything that isn't a gambling domain
> as noise. This keeps the compliance report clean and focused."

---

**Scenario C-2 — Employee Accesses Sports-Betting Site (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `williamhill.com` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Segment | office |
| Reasons | `dns_denied_domain` |

> "`williamhill.com` matched `gambling_domains.txt`. dns_denied: +40.
> Office block threshold is 80 — score 40 is a MONITOR, not a block.
>
> This is a deliberate compliance design. The gambling operator needs to know
> *which employee, from which IP, looked up which gambling domain, at what time*.
> Blocking silently loses the audit trail. Monitoring builds it.
>
> If policy changes — say, after a compliance review — block threshold drops to 40
> and every office gambling lookup becomes an immediate block. One config line."

---

**Scenario C-3 — Second Employee, Online Casino (MONITOR)**

| Field | Value |
|-------|-------|
| Domain | `pokerstars.com` |
| Client IP | `192.168.1.75` |
| Action | **Monitor** |
| Score | 40 |
| Segment | office |
| Reasons | `dns_denied_domain` |

> "Two separate employees caught in the same 33-second injector loop.
> `192.168.1.50` → `williamhill.com`. `192.168.1.75` → `pokerstars.com`.
> Per-IP tracking. Individual audit entries. Compliance staff can filter the
> Events page by source IP and pull a per-employee report in one click."

---

**Scenario C-4 — Guest Network Burst on Betting Site (BLOCK, ×250)**

| Field | Value |
|-------|-------|
| Domain | `bet365.com` |
| Client IP | `172.16.1.99` |
| Action | **Blocked** |
| Score | 50 |
| Segment | guest |
| Reasons | `dns_denied_domain`, `burst_behavior` |

> "Guest WiFi. Block threshold 40. First DNS query for `bet365.com`: dns_denied +40 =
> score 40 ≥ 40 → immediate BLOCK. No warning. No second chance.
> `nft add element inet minifw minifw_block_v4 { 172.16.1.99 }`
> Burst adds +10 → score 50. 250 queries. The Blocked counter jumps on the dashboard.
>
> A guest querying a gambling domain on a gambling operator's network is not an audit
> event — it is an enforcement event. The network zone makes that distinction automatically."

---

**Scenario C-5 — Wildcard Pattern Match, Guest (BLOCK)**

| Field | Value |
|-------|-------|
| Domain | `lucky777.casino` |
| Client IP | `172.16.2.10` |
| Action | **Blocked** |
| Score | 40 |
| Segment | guest |
| Reasons | `dns_denied_domain` |

> "`lucky777.casino` is not an explicit entry in `gambling_domains.txt`.
> It matched the `*.casino` wildcard pattern — any domain with a `.casino` TLD
> is blocked the moment any guest device looks it up.
>
> The feed does not need a finite list of every casino domain that has ever existed.
> Pattern-based enforcement means zero-day gambling domains are covered automatically.
> The moment `.casino` was added to the feed, every future casino domain was covered."

---

**CLI Verification**

```bash
docker exec minifw_gambling_engine nft list set inet minifw minifw_block_v4
docker exec minifw_gambling_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool
```

Expected gambling event:
```json
{
  "domain":       "bet365.com",
  "severity":     "info",
  "sector":       "establishment",
  "product_mode": "minifw_gambling"
}
```

> "Sector is `establishment`. Product mode is `minifw_gambling`.
> Same sector engine. Different product identity. That is the architecture."

---

# EXPLANATION

## How One Engine Becomes Three Products

> "Everything you just saw ran on identical engine code. Let me show you exactly what
> `PRODUCT_MODE` changes — and what it does not change."

**What changes per mode:**

| Component | Hospital | SME | Gambling |
|-----------|----------|-----|----------|
| Threat feed | `healthcare_threats.txt` | `deny_domains.txt` | `gambling_domains.txt` |
| YARA ruleset | `hospital_rules.yar` | `sme_rules.yar` | `sme_rules.yar` |
| Payload redaction | `[REDACTED]` on all events | Plaintext | Plaintext |
| IoMT subnet detection | Active (`10.20.0.0/16`) | Off | Off |
| Detection filter | All types | All types | `gambling` only |
| mednet / strict segment | `mednet` block=40 | `guest` block=40 | `guest` block=40 |
| Dashboard badge | Red — Hospital | Blue — SME | Purple — Gambling |
| IoMT Alerts menu item | Visible | Hidden | Hidden |
| Port | 8443 | 8444 | 8445 |

**What does not change:**

- Engine source code
- Scoring pipeline (DNS → YARA → SNI → MLP → ASN → IP → Burst)
- Decision logic (most-severe-wins)
- nftables enforcement call
- Events schema
- Dashboard codebase
- Audit log format

---

## The Full Event-to-Block Flow

```
DNS query arrives at collector
         │
         ▼
Engine evaluates all layers simultaneously
         │
         ▼
Decision recorded in events.jsonl
         │
  ┌──────┴──────┐
  │             │
ALLOW/        BLOCK
MONITOR         │
  │             ▼
  │     nft add element inet minifw
  │     minifw_block_v4 { <IP> }
  │             │
  ▼             ▼
Events page   Kernel drops
shows row     all packets from IP
              (timeout: 1 day)
```

> "The log and the enforcement happen together. There is no async queue between the
> decision and the kernel rule. The block is in the kernel before the next packet arrives."

---

## Segment Threshold Reference

**Hospital:**

| Segment | Monitor | Block |
|---------|---------|-------|
| `internal` | 30 | 80 |
| `mednet` | 10 | **40** (−5 hospital adj) |
| `guest` | 20 | 65 |
| `default` | 40 | 85 |

**SME / Gambling:**

| Segment | Monitor | Block |
|---------|---------|-------|
| `office` | 45 | 80 |
| `dmz` | 35 | 70 |
| `guest` | 20 | **40** |
| `default` | 45 | 80 |

---

# CLOSING

## Summary — What We Demonstrated

| Step | Where it happened |
|------|------------------|
| **Event appears** | Events page — domain, IP, timestamp, score, reasons |
| **Decision taken** | Action column — Allow / Monitor / Block |
| **Block occurs** | nftables kernel set — confirmed via `nft list set` |
| **Log visible** | `events.jsonl` — structured JSON, SIEM-ready |

All four steps visible in all three modes. No simulation. No mock data.
The injector generates DNS queries; the engine processes them as if they were real traffic.

---

## Closing Statement

> "Three regulated industries. Three compliance requirements. Three enforcement policies.
> One engine.
>
> Hospital mode never sees a gambling domain. Gambling mode never fires on a HIPAA
> payload. SME mode gives you full domain visibility for incident response while
> hospital mode redacts everything at the point of logging.
>
> The sector lock is immutable at runtime — it is set at container start and cannot be
> changed without redeploying. Your hospital product cannot accidentally become an SME
> product because someone changed a setting. The identity is baked in at deploy time.
>
> If you want to go deeper: we can look at the YARA ruleset, walk through the MLP
> scoring model, or discuss how the sector threshold adjustments are configured.
> We can also run the API WAF mode — that is a separate demo for the edge protection story."

---

## Next Steps

| Option | Command |
|--------|---------|
| Add a custom domain to the deny feed | Edit `config/feeds/deny_domains.txt`, restart engine |
| Lower SME office block threshold to 75 | Edit `config/modes/minifw_establishment/policy.json` |
| Run API WAF mode | `./demo.sh api` → `http://localhost:8001` |
| Stop all demos | `./demo.sh hospital down && ./demo.sh sme down && ./demo.sh gambling down` |
| Wipe and reset | `./demo.sh hospital clean && ./demo.sh sme clean && ./demo.sh gambling clean` |

---

## Troubleshooting Quick Reference

| Symptom | Fix |
|---------|-----|
| No events on dashboard | Wait 33s for first injector loop; check `docker compose logs injector` |
| Engine exits immediately | Check `docker compose logs engine`; verify `cap_add: [NET_ADMIN, NET_RAW]` |
| YARA Hits counter stays 0 | Check `docker compose logs engine` for YARA compilation errors |
| Mode badge shows "Unknown" | `PRODUCT_MODE` not set — check docker-compose environment block |
| Hospital domains showing plaintext | `PRODUCT_MODE` or `MINIFW_SECTOR` not set to hospital |
| Flow Tracking shows Active | `MINIFW_DISABLE_FLOWS=1` not set in engine container |
| Port conflict | Hospital=8443, SME=8444, Gambling=8445 — adjust in docker-compose if needed |

---

*MiniFW-AI v2.2.0 — Demo Master Script*
