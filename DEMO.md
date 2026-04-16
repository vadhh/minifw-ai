# MiniFW-AI — Demo Walkthrough

**Version:** 2.2.0  
**Duration:** ~15 minutes per mode  
**Audience:** Technical evaluators, IT leads, security officers

---

## Modes

| Command | PRODUCT_MODE | Sector | Port | Password |
|---------|-------------|--------|------|----------|
| `./demo.sh hospital` | `minifw_hospital` | hospital | 8443 | `Hospital1!` |
| `./demo.sh sme` | `minifw_establishment` | establishment | 8444 | `SME_Demo1!` |
| `./demo.sh gambling` | `minifw_gambling` | establishment + GAMBLING_ONLY=1 | 8445 | `Gambling1!` |
| `./demo.sh api` | `ritapi_advanced` | — (edge WAF) | 8001 | see ritapi-advanced/.env.demo |

---

## Prerequisites

- Docker and Docker Compose installed
- Ports 8443 / 8444 / 8445 / 8001 free on localhost (only the one you run)
- ~5 minutes for the initial image build (cached on subsequent runs)

---

## 1. Start the Demo

```bash
cd /path/to/minifw-ai/docker

./demo.sh hospital     # HIPAA · IoMT · Healthcare   → https://localhost:8443
./demo.sh sme          # SME · Balanced protection   → https://localhost:8444
./demo.sh gambling     # Regulatory enforcement      → https://localhost:8445
./demo.sh api          # API Protection WAF          → http://localhost:8001
```

All four modes can run simultaneously — they use separate ports and volumes.

**Actions** (second argument, default `up`):

```bash
./demo.sh hospital up      # build + start (foreground)
./demo.sh hospital down    # stop
./demo.sh hospital clean   # stop + wipe logs
./demo.sh hospital logs    # attach to logs
./demo.sh hospital ps      # show running containers
```

Watch for healthy startup:

```
minifw_engine  | [SECTOR_LOCK] Loaded from PRODUCT_MODE=minifw_hospital: sector=hospital
minifw_engine  | [ENGINE] Starting MiniFW-AI hospital sector daemon...
minifw_engine  | [FLOW] Flow tracking disabled via MINIFW_DISABLE_FLOWS=1
minifw_web     | [WEB] Dashboard → https://localhost:8443   login: admin / Hospital1!
minifw_injector| [INJECTOR] Loop 1
```

> **Note:** `MINIFW_DISABLE_FLOWS=1` is set in the demo containers — conntrack flow tracking is skipped because Docker containers have no real traffic. Flow Tracking will show **Inactive** on the dashboard; this is expected.

> **Note:** The browser will show a self-signed certificate warning. Accept it to continue.

---

## 2. Log In

| Mode | URL | Username | Password |
|------|-----|----------|----------|
| Hospital | `https://localhost:8443` | `admin` | `Hospital1!` |
| SME | `https://localhost:8444` | `admin` | `SME_Demo1!` |
| Gambling | `https://localhost:8445` | `admin` | `Gambling1!` |
| API | `http://localhost:8001` | — | see `.env.demo` |

---

## 3. Mode Badge — What to Point Out First

Every page shows a **Mode badge** in the top navbar and a **mode pill** under the sidebar
logo. Both are server-side rendered via Jinja2 globals (`mode_ui`) — no JS fetch delay.
The badge renders the mode icon, `Mode: <Label>`, and the sublabel (`— HIPAA · IoMT · Healthcare` etc.).

| Mode | Badge label | Color |
|------|-------------|-------|
| Hospital | `Mode: Hospital — HIPAA · IoMT · Healthcare` | Red |
| SME | `Mode: SME — Establishment · Balanced Protection` | Blue |
| Gambling | `Mode: Gambling — Regulatory Enforcement · Domain Blocking` | Purple |
| API | `Mode: API Protection — Edge WAF · L7 · Bot Detection` | Indigo |

The **System Intelligence** panel header also shows the sector via `/api/sector-lock`,
updated with the full `mode_label` and `mode_color`.

---

## 4. Key Differences Between Modes

| Feature | Hospital | SME | Gambling |
|---------|----------|-----|----------|
| `PRODUCT_MODE` | `minifw_hospital` | `minifw_establishment` | `minifw_gambling` |
| Sector | hospital | establishment | establishment |
| `GAMBLING_ONLY` | — | — | **1** |
| `ALLOWED_DETECTION_TYPES` | — | — | `gambling` (suppresses base deny feeds) |
| HIPAA payload redaction | **Yes** — `[REDACTED]` | No | No |
| IoMT detection | **Yes** — `severity=critical` | No | No |
| IoMT Alerts menu item | **Visible** | Hidden | Hidden |
| Extra feed | `healthcare_threats.txt` | base feeds only | `gambling_domains.txt` |
| YARA ruleset | `hospital_rules.yar` | `sme_rules.yar` | `sme_rules.yar` |
| Monitor threshold (office) | 30 (−20 adj) | 45 | 45 |
| Block threshold (office) | 80 (−5 adj) | 80 | 80 |
| Strict segment | `mednet` block=40 | `guest` block=40 | `guest` block=40 |
| Port | 8443 | 8444 | 8445 |

**Talking point:** Same engine, same AI pipeline, same YARA + MLP + DNS scoring.
`PRODUCT_MODE` changes what data loads — policies, feeds, YARA rules, thresholds —
without touching any engine code.

---

---

# PART A — Hospital Mode

---

## A-1. Dashboard Overview

### Mode badge
Navbar shows `Mode: Hospital — HIPAA · IoMT · Healthcare` in red (hospital icon).
Sidebar pill shows `HOSPITAL`. IoMT Alerts menu item is visible — it is rendered only
when `mode_ui.product_mode == "minifw_hospital"` (Jinja2 conditional, not JS).

### Sector lock
Reads **Hospital Sector** in the System Intelligence panel.
Factory-locked via `sector_lock.py`; `PRODUCT_MODE=minifw_hospital` set at container start.

### Firewall Status panel

| Row | Expected value |
|-----|----------------|
| Firewall Engine | Active (green) — detected via audit log sentinel (cross-container Docker) |
| Detection Mode | AI Enhanced |
| Burst Protection | Active |
| Zeek TLS/SNI | Inactive (Zeek off in demo) |
| DNS Collector | Active |
| Flow Tracking | Inactive (`MINIFW_DISABLE_FLOWS=1` set in container) |

### System Intelligence counters (after first injector loop, ~33s)

| Counter | Expected | Source |
|---------|----------|--------|
| Hard Gates | 0 | None triggered |
| AI Blocks | 0 | MLP needs flow data (disabled) |
| YARA Hits | 1+ | Scenario 4 — `MedicalRansomware` |
| DNS Tunnels | 0 | Not triggered |
| Port Scans | 0 | Not triggered |
| Tor / Anon | 0 | Finance feature |
| SNI Blocks | 0 | Zeek off |

### Protection Summary (after one loop)
- **Total Allowed:** 1 (Windows Update)
- **Total Blocked:** 250+ (mednet burst)
- **Threats Detected:** 254+

---

## A-2. Hospital Scenarios

### Scenario 1 — Benign Traffic (ALLOW)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `192.168.1.1` |
| Action | **Allowed** |
| Score | 0 |

**What to say:** "Normal workstation update traffic. Score zero. Even the allowed domain is
`[REDACTED]` — in hospital mode `redact_payloads: true` applies to every single event.
Under HIPAA, even a list of allowed domains can constitute patient-linked metadata."

---

### Scenario 2 — IoMT Device Contacts Ransomware C2 (MONITOR, critical)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.0.5` |
| Action | **Monitor** |
| Score | 40 |
| Severity | **critical** |
| Reasons | `dns_denied_domain`, `iomt_device_alert` |

**What to say:** "`10.20.0.5` is in the IoMT subnet (`10.20.0.0/24`). The actual domain is
`lockbit-blog.com` — in the `healthcare_threats.txt` feed. Two things happen: the domain is
`[REDACTED]` (HIPAA redaction active in hospital mode), and severity is `critical` because
the engine applies `alert_severity_boost` to any IoMT device anomaly — regardless of whether
the action is monitor or block."

---

### Scenario 3 — Phishing from Workstation (MONITOR, info)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Severity | info |
| Reasons | `dns_denied_domain` |

**What to say:** "Domain is `my-chart-login.com` — a fake MyChart login phishing page in
`healthcare_threats.txt`. Same score as scenario 2, but `192.168.1.50` is a regular
workstation — severity stays `info`. IoMT anomaly = critical, staff phishing click = info.
Same score, different triage priority. The security team can sort by severity and act
on the critical IoMT events first."

---

### Scenario 4 — YARA + DNS Combined Hit from IoMT (MONITOR, critical)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.1.10` |
| Action | **Monitor** |
| Score | 75 |
| Severity | **critical** |
| Reasons | `yara_MedicalRansomware`, `dns_denied_domain`, `iomt_device_alert` |

**What to say:** "Domain is `RyukReadMe.example.com`. Two detection layers fired
independently. DNS matched `healthcare_threats.txt`: +40. YARA scanned the raw query
bytes and found the string `RyukReadMe` — triggers the `MedicalRansomware` rule: +35.
Total score 75. YARA runs on every DNS query in real time — not a known-bad list,
live payload inspection. And `10.20.1.10` is in IoMT subnet `10.20.1.0/24` → severity
boosted to critical."

---

### Scenario 5 — EHR Ransomware C2 from IoMT Device (MONITOR, critical)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `10.20.0.5` |
| Action | **Monitor** |
| Score | 40 |
| Severity | **critical** |
| Reasons | `dns_denied_domain`, `iomt_device_alert` |

**What to say:** "Same IoMT device (`10.20.0.5`) as scenario 2, different domain —
`ehr-software-update.com`, a known EHR-targeting ransomware C2 in `healthcare_threats.txt`.
Score 40, severity critical. Two IoMT alerts in one loop from the same device is a strong
incident signal — in a live SOC this would page the on-call team immediately."

---

### Scenario 6 — Data Broker Burst, Enforcement (BLOCK, ×250)

| Field | Value |
|-------|-------|
| Domain | `[REDACTED]` |
| Client IP | `172.16.0.99` |
| Action | **Blocked** |
| Score | 50 |
| Segment | mednet |
| Reasons | `dns_denied_domain`, `burst_behavior` |

**What to say:** "Domain is `medrecords-transfer.io` — a data-broker exfiltration endpoint
in `healthcare_threats.txt`. `172.16.0.99` is on `mednet` (172.16.0.0/16) — configured
block threshold 45, minus the hospital sector's −5 block adjustment = **effective 40**.
First DNS query: dns_denied +40 = score 40 ≥ 40 → BLOCK immediately. Burst fires: +10 →
score climbs to 50. Engine calls `nft add element inet minifw minifw_block_v4 { 172.16.0.99 }` —
kernel-level drop, zero app overhead. 250 queries per loop make the blocked-count dramatic
in the dashboard."

---

## A-3. Hospital Scoring Reference

| Layer | Weight | Active in demo |
|-------|--------|----------------|
| DNS deny match (healthcare feed) | +40 | Yes |
| YARA signature match | 0–35 | Yes (scenario 4) |
| TLS SNI deny match | +35 | No (Zeek off) |
| MLP inference | 0–30 | No (no flow data) |
| ASN deny | +15 | No |
| IP deny | +15 | No |
| DNS burst | +10 | Yes (scenario 6) |
| Hard gate | =100 | No |

| Segment | Monitor | Block |
|---------|---------|-------|
| `internal` | 30 | 80 |
| `mednet` | 10 | **40** |
| `default` | 40 | 85 |
| `guest` | 20 | 65 |

---

---

# PART B — SME Mode

---

## B-1. Dashboard Overview

### Mode badge
Navbar shows `Mode: SME — Establishment · Balanced Protection` in blue (building icon).
Sidebar pill shows `SME`. IoMT Alerts menu item is **hidden** — the Jinja2 conditional
for `mode_ui.product_mode == "minifw_hospital"` evaluates false in SME mode.

### System Intelligence counters (after first loop)

| Counter | Expected |
|---------|----------|
| YARA Hits | 2+ (scenarios 3 + 4 — `SmeRansomware`, `SmeCryptoMiner`) |
| All others | 0 |

### Protection Summary
- **Total Allowed:** 1 (office365.com)
- **Total Blocked:** 250+ (guest burst)
- **Threats Detected:** 254+

---

## B-2. SME Scenarios

### Scenario 1 — Benign Traffic (ALLOW)

| Field | Value |
|-------|-------|
| Domain | `office365.com` |
| Client IP | `192.168.1.10` |
| Action | **Allowed** |
| Score | 0 |

**What to say:** "Domain shown in plain text — no HIPAA redaction in SME mode.
Everything logged as-is for standard audit."

---

### Scenario 2 — Phishing from Employee Workstation (MONITOR, info)

| Field | Value |
|-------|-------|
| Domain | `login-paypal-secure-verify.com` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Reasons | `dns_denied_domain` |

**What to say:** "Domain visible in log. Compare to hospital mode — same event would
show `[REDACTED]`. In SME you want exact domains for incident response."

---

### Scenario 3 — Ransomware C2 + YARA (MONITOR, info)

| Field | Value |
|-------|-------|
| Domain | `Locky.decrypt-files.net` |
| Client IP | `192.168.1.100` |
| Action | **Monitor** |
| Score | 75 |
| Reasons | `yara_SmeRansomware`, `dns_denied_domain` |

**What to say:** "Two layers fired. DNS: +40. YARA `SmeRansomware` found `Locky` string: +35.
Score 75, office block threshold 80 — 5-point margin. One config change would make this a block."

---

### Scenario 4 — Cryptominer C2 + YARA (MONITOR, info)

| Field | Value |
|-------|-------|
| Domain | `xmrig-pool.crypto-mine.io` |
| Client IP | `192.168.1.200` |
| Action | **Monitor** |
| Score | 75 |
| Reasons | `yara_SmeCryptoMiner`, `dns_denied_domain` |

**What to say:** "`xmrig` in the hostname triggers the `SmeCryptoMiner` YARA rule: +35.
dns_denied: +40. Total 75 — same 5-point margin from the block threshold as scenario 3.
Two different YARA rules fired in the same loop: ransomware + cryptominer. The YARA engine
scans every DNS query independently; no per-rule cooldown."

---

### Scenario 5 — Generic C2 Beacon (MONITOR, info)

| Field | Value |
|-------|-------|
| Domain | `c2-data-collect.net` |
| Client IP | `10.0.0.50` |
| Action | **Monitor** |
| Score | 40 |
| Reasons | `dns_denied_domain` |

**What to say:** "`10.0.0.50` is an internal server (`10.0.0.0/8` → office segment). DNS
hit on `deny_domains.txt`: +40. No YARA match — pure feed-based detection. Score 40 is
below the office block threshold of 80, so it's monitored. Shows the engine catches C2
beacons even without a YARA signature — feed coverage alone is sufficient."

---

### Scenario 6 — Guest Network Burst, Enforcement (BLOCK, ×250)

| Field | Value |
|-------|-------|
| Domain | `ads-malware-tracker.net` |
| Client IP | `172.16.1.99` |
| Action | **Blocked** |
| Score | 40 → 50 |
| Segment | guest |
| Reasons | `dns_denied_domain`, `burst_behavior` |

**What to say:** "`172.16.1.99` is guest WiFi — block threshold 40. First query for
`ads-malware-tracker.net`: dns_denied +40 = score 40 ≥ 40 → immediate BLOCK. Engine
calls `nft add element inet minifw minifw_block_v4 { 172.16.1.99 }`. Burst adds +10 →
score climbs to 50. 250 queries per loop — dashboard blocked count jumps visibly.
Compare to office scenarios 2–5: same deny-list domain from a workstation would only
monitor. Network zone determines enforcement level."

---

## B-3. SME Scoring Reference

| Segment | Monitor | Block |
|---------|---------|-------|
| `office` | 45 | 80 |
| `dmz` | 35 | 70 |
| `guest` | 20 | **40** |
| `default` | 45 | 80 |

No sector threshold adjustment for establishment (0/0).

---

---

# PART C — Gambling Mode

---

## C-1. What This Mode Demonstrates

`PRODUCT_MODE=minifw_gambling` activates regulatory gambling domain enforcement.
Two extra env vars are set in the container:

| Var | Value | Effect |
|-----|-------|--------|
| `GAMBLING_ONLY` | `1` | Flags this as a regulatory enforcement deployment |
| `ALLOWED_DETECTION_TYPES` | `gambling` | Suppresses all non-gambling deny-feed hits; only `gambling_domains.txt` scores |

Policy: `config/modes/minifw_gambling/policy.json` — same segment layout as SME but
`office` threshold deliberately held at 80 so employee violations are monitored (audit trail)
rather than blocked outright.

**Talking point:** "Same engine as hospital and SME. Two environment variables — `PRODUCT_MODE`
and `ALLOWED_DETECTION_TYPES` — switch the product identity, feeds, policy, and dashboard label.
The hospital never sees gambling events. The gambling operator never sees HIPAA-tier IoMT logic.
This is how you sell the same platform to three completely different regulated industries."

---

## C-2. Dashboard Overview

### Mode badge
Navbar shows `Mode: Gambling — Regulatory Enforcement · Domain Blocking` in purple
(shield-exclamation icon). Sidebar pill shows `GAMBLING`.
System Intelligence panel shows **Establishment Sector** (gambling runs on the establishment
sector + `GAMBLING_ONLY=1`).

IoMT Alerts menu item is **hidden**.

### System Intelligence counters (after first loop, ~35 s)

| Counter | Expected |
|---------|----------|
| YARA Hits | 0 (no YARA signature fires — gambling domains are plain labels, not malware strings) |
| All others | 0 |

### Protection Summary (after one loop)
- **Total Allowed:** 1 (office365.com — non-gambling domain, suppressed by `ALLOWED_DETECTION_TYPES`)
- **Total Blocked:** 251 (250 bet365 burst + 1 lucky777.casino)
- **Threats Detected:** 253 (2 office monitors + 251 blocks)

---

## C-3. Gambling Scenarios

### Scenario 1 — Benign Work Traffic (ALLOW)

| Field | Value |
|-------|-------|
| Domain | `office365.com` |
| Client IP | `192.168.1.10` |
| Action | **Allowed** |
| Score | 0 |

**What to say:** "`office365.com` is not in `gambling_domains.txt`. With `ALLOWED_DETECTION_TYPES=gambling`
the engine ignores base deny-list hits entirely — score stays zero. This is intentional: a gambling
operator's deployment should not fire on every generic phishing domain from the base feed.
Only gambling-domain violations matter here."

---

### Scenario 2 — Employee Accesses Sports-Betting Site (MONITOR, office)

| Field | Value |
|-------|-------|
| Domain | `williamhill.com` |
| Client IP | `192.168.1.50` |
| Action | **Monitor** |
| Score | 40 |
| Segment | office |
| Reasons | `dns_denied_domain` |

**What to say:** "`williamhill.com` matched `gambling_domains.txt` — dns_denied fires: +40.
Office block threshold is 80 — score 40 is a MONITOR, not a block. The operator builds an
audit trail of exactly which employee, from which IP, looked up which gambling site.
Policy can be tightened to block at 40 with one config change."

---

### Scenario 3 — Second Employee, Online Casino (MONITOR, office)

| Field | Value |
|-------|-------|
| Domain | `pokerstars.com` |
| Client IP | `192.168.1.75` |
| Action | **Monitor** |
| Score | 40 |
| Segment | office |
| Reasons | `dns_denied_domain` |

**What to say:** "Two separate employees caught in the same loop — per-IP tracking. Same
score, same threshold, but distinct IPs: `192.168.1.50` and `192.168.1.75`. The events
page lets compliance staff filter by source IP in one click."

---

### Scenario 4 — Guest Network Burst on Betting Site (BLOCK, ×250)

| Field | Value |
|-------|-------|
| Domain | `bet365.com` |
| Client IP | `172.16.1.99` |
| Action | **Blocked** |
| Score | 40 → 50 |
| Segment | guest |
| Reasons | `dns_denied_domain`, `burst_behavior` |

**What to say:** "`172.16.1.99` is on the guest WiFi segment — block threshold 40.
First DNS query for `bet365.com`: dns_denied +40 = score 40 ≥ 40 → immediate BLOCK.
Engine calls `nft add element inet minifw minifw_block_v4 { 172.16.1.99 }`. The 250-query
burst adds +10 → score climbs to 50. Kernel-level enforcement; zero application overhead."

---

### Scenario 5 — Wildcard Pattern Match, Guest (BLOCK)

| Field | Value |
|-------|-------|
| Domain | `lucky777.casino` |
| Client IP | `172.16.2.10` |
| Action | **Blocked** |
| Score | 40 |
| Segment | guest |
| Reasons | `dns_denied_domain` |

**What to say:** "`lucky777.casino` matches the `*.casino` glob pattern in `gambling_domains.txt`
— the feed does not need an explicit entry for every casino domain. Any `.casino` TLD is
blocked the moment a guest device looks it up. Pattern-based enforcement, not just a finite
list."

---

## C-4. Gambling Scoring Reference

| Segment | Monitor | Block |
|---------|---------|-------|
| `office` | 45 | 80 |
| `dmz` | 35 | 70 |
| `guest` | 20 | **40** |
| `default` | 45 | 80 |

No sector threshold adjustment for establishment (0/0).

Feed loaded: `gambling_domains.txt` (betting, casino, poker, lottery, `*.bet`, `*.casino`)

---

---

# PART D — Shared CLI Verification

## D-1. Confirm nftables Block Set

```bash
# Hospital
docker exec minifw_engine nft list set inet minifw minifw_block_v4

# SME
docker exec minifw_sme_engine nft list set inet minifw minifw_block_v4

# Gambling
docker exec minifw_gambling_engine nft list set inet minifw minifw_block_v4
```

Expected:

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

---

## D-2. Inspect Raw Event Log

```bash
# Hospital
docker exec minifw_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool

# SME
docker exec minifw_sme_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool

# Gambling
docker exec minifw_gambling_engine \
  tail -n 5 /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool
```

Hospital event (key fields):
```json
{
  "domain":   "[REDACTED]",
  "severity": "critical",
  "sector":   "hospital",
  "product_mode": "minifw_hospital"
}
```

SME event:
```json
{
  "domain":   "Locky.decrypt-files.net",
  "severity": "info",
  "sector":   "establishment",
  "product_mode": "minifw_establishment"
}
```

Gambling event:
```json
{
  "domain":   "bet365.com",
  "severity": "info",
  "sector":   "establishment",
  "product_mode": "minifw_gambling"
}
```

---

## D-3. Confirm PRODUCT_MODE in Container

```bash
docker exec minifw_engine env | grep PRODUCT_MODE
# PRODUCT_MODE=minifw_hospital

docker exec minifw_sme_engine env | grep PRODUCT_MODE
# PRODUCT_MODE=minifw_establishment

docker exec minifw_gambling_engine env | grep PRODUCT_MODE
# PRODUCT_MODE=minifw_gambling
```

---

## D-4. Inspect Audit Log

```bash
docker exec minifw_engine \
  head -n 5 /opt/minifw_ai/logs/audit.jsonl | python3 -m json.tool
```

First entry is the daemon start record. Subsequent entries are IP block and stop events.

---

## D-5. Events / Logs Page

The Events page (`/admin/events`) is **server-side rendered** — rows are embedded in the
HTML at page load, no AJAX fetch required. Stats (Allowed / Blocked / Threats / Total)
are also pre-computed server-side from up to 10 000 events.

- Up to **500 rows** are rendered in the initial HTML; a warning banner appears when the
  total exceeds 500: *"Showing most recent 500 of X total events"*
- The page **auto-refreshes every 30 seconds** (full page reload).
- DataTables operates on the pre-rendered DOM rows — no server-side processing mode.
- All static assets (jQuery, Bootstrap, DataTables, SweetAlert2) are **locally bundled**
  under `app/web/static/vendor/` — no CDN dependency, works offline.

---

## D-6. Stop / Clean

```bash
./demo.sh hospital down
./demo.sh sme down
./demo.sh gambling down

# Wipe volumes for a clean run
./demo.sh hospital clean
./demo.sh sme clean
./demo.sh gambling clean
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard shows no events | Wait 30s for first injector loop; check `docker compose logs injector` |
| Engine exits immediately | Check `docker compose logs engine`; likely nftables capability — ensure `cap_add: [NET_ADMIN, NET_RAW]` |
| Connection refused on port | Web container still initialising; wait 10s and retry |
| YARA Hits counter stays 0 | Check `docker compose logs engine` for YARA compilation errors |
| Mode badge shows "Unknown" | `PRODUCT_MODE` not set — check docker-compose environment block |
| Flow Tracking shows Active in Docker | `MINIFW_DISABLE_FLOWS=1` not set in engine container — add it to disable conntrack |
| SME/Gambling domains not redacted | Correct — redaction only active in `minifw_hospital` |
| Hospital domains visible | `PRODUCT_MODE` or `MINIFW_SECTOR` not set to hospital; check engine logs |
| Port conflict | Hospital=8443, SME=8444, Gambling=8445 — change in the relevant docker-compose if needed |
| `./demo.sh api` fails | Confirm ritapi-advanced project is at `../../ritapi/ritapi-adv sc/ritapi-advanced/` |
