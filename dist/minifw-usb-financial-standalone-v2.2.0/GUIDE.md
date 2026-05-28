# MiniFW-AI Financial — Full Product Guide

**Scenario:** ArborCrest Capital — $4B wealth management firm  
**Compliance:** PCI-DSS · TLS 1.2+ enforcement · Tor/anonymizer blocking  
**Dashboard:** https://localhost:8443  
**Credentials:** `admin` / `Finance1!`

---

## Overview

MiniFW-AI Financial is the PCI-DSS–aligned sector build of the MiniFW-AI behavioral firewall engine. It is deployed at ArborCrest Capital, a $4 billion wealth management firm operating two critical network segments:

| Segment | Subnet | Description |
|---------|--------|-------------|
| trading | 10.50.0.0/24 | Trading floor workstations — tightest enforcement |
| internal | 192.168.1.0/24, 10.0.0.0/8 | ERP and back-office finance systems |

The engine defends against the four highest-severity threats in financial sector networks:

- **Banking trojan C2** — TrickBot, Emotet, and related command-and-control beacons
- **Card data exfiltration** — DNS tunneling and HTTP-over-DNS patterns toward payment-harvesting infrastructure
- **Tor and anonymizer traffic** — exit node lookups that bypass perimeter logging, violating PCI-DSS Requirement 10
- **ERP subnet pivoting** — lateral movement from a compromised trading floor endpoint into the internal finance network

The dashboard runs on **HTTPS port 8443** using a locally-issued CA certificate, reflecting the strict TLS 1.2+ posture required in production deployments. All enforcement decisions are logged to an immutable JSONL audit trail suitable for PCI-DSS evidence packs.

---

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.10+ | `python3 --version` to check |
| openssl | any recent | Required by `setup_tls.sh` |
| libnss3-tools | any | Required for `certutil` (Chrome/Firefox trust store) |
| Port 8443 | free | `ss -tlnp \| grep 8443` to verify |
| sudo access | required | `setup_tls.sh` installs the demo CA into system trust |

**Supported platforms:** Linux (amd64/arm64), macOS (Intel/Apple Silicon), WSL2 on Windows 10/11.

On Debian/Ubuntu, install dependencies with:

```bash
sudo apt-get install openssl libnss3-tools
```

On macOS (Homebrew):

```bash
brew install openssl nss
```

---

## Quick Start

### First-time setup (TLS certificate generation)

Run once before the first demo. Requires `sudo` to install the demo CA into the system trust store:

```bash
bash setup_tls.sh
```

This generates `certs/minifw-ca.crt`, `certs/server.crt`, and `certs/server.key` under the package directory, and registers the CA with the local certificate store so that Chrome, Firefox, and `curl` trust the demo HTTPS endpoint without warnings.

### Starting the demo

```bash
bash run_demo.sh
```

**Expected terminal output:**

```
[minifw] Admin user already exists — skipping creation.
[minifw] Starting Financial Demo...
[minifw] Engine started (PID <N>)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
```

(On first run, `Admin user created.` appears instead of the "already exists" line.)

If the dashboard does not respond within 20 seconds, the script exits with:

```
[minifw] ERROR: Dashboard did not start in 20s — see logs/web.log
```

### Logging in

Open a browser and navigate to **https://localhost:8443**.  
Log in with username `admin` and password `Finance1!`.

> **Note:** Allow approximately 90 seconds after startup before the attack sequence fires. The first 60 seconds show normal trading-floor and ERP traffic (all `allow`, score ~20). The attack chain begins at T+60s and escalates to a hard block by T+75s.

---

## Dashboard Walkthrough

### Live Event Feed

The event feed table refreshes in real time from `logs/events.jsonl`. Column definitions:

| Column | Description |
|--------|-------------|
| Time | ISO-8601 timestamp of the DNS event |
| Domain | Queried domain name |
| Client IP | Source IP — maps to a subnet/segment |
| Score | Aggregate threat score (0–100+) |
| Decision | `allow`, `monitor`, or `block` |
| Reason | Pipe-delimited list of contributing signals |
| Segment | Policy segment derived from client IP (`trading`, `internal`, `guest`, `dmz`, `default`) |

### Score Composition

Scores are computed as a weighted sum of signals. Maximum additive score exceeds 100; the engine caps enforcement decisions at the configured thresholds.

| Signal | Max Weight | Description |
|--------|-----------|-------------|
| DNS feed match | +40 | Domain found in a deny feed (financial_fraud.txt, tor_exit_nodes.txt, etc.) |
| TLS / SNI match | +35 | Server Name Indication matches a blocked pattern |
| ASN deny | +15 | Source or destination AS number in deny_asn.txt |
| IP denied | +15 | Source IP in deny_ips.txt |
| DNS burst | +10 | Queries-per-minute exceeds burst threshold |
| MLP inference | 0–30 | Neural net anomaly score from trained behavioral model |
| YARA scan | 0–35 | Payload match against financial-sector YARA ruleset |

### Decision Thresholds by Segment

Derived from `config/policy.json`:

| Segment | Monitor threshold | Block threshold | Notes |
|---------|------------------|-----------------|-------|
| trading | 45 | 80 | Trading floor — tightest enforcement |
| internal | 45 | 80 | ERP / back-office finance systems |
| dmz | 50 | 75 | Perimeter-facing services |
| default | 55 | 85 | All other subnets |
| guest | 35 | 65 | Client/visitor WiFi — Tor exit nodes always blocked |

### AI Threat Synthesis Panel

The AI Threat Synthesis Panel (top-right card on the dashboard) consolidates detection data, kernel enforcement status, and AI reasoning into a single real-time view. During the attack demo it displays:

- Active PCI-DSS violation indicators (card exfil pattern, Tor anonymizer, C2 beacon)
- Enforcement state transitions from `BASELINE_PROTECTION` to `AI_ENHANCED_PROTECTION`
- Per-event reasoning text generated from reason codes
- A severity badge that escalates from `info` → `critical` as the attack chain progresses

---

## Threat Scenarios

### ArborCrest Capital — 5-Step Attack Chain

A threat actor compromises a trading-floor workstation (10.50.0.1) and attempts to exfiltrate payment card data through a DNS-based C2 channel.

#### Timeline

| Phase | Time window | Traffic type | Actions observed |
|-------|-------------|--------------|-----------------|
| Normal operations | T+0 – T+60s | Bloomberg feeds, Reuters, SWIFT, NASDAQ, Refinitiv, internal auth | `allow` (score ~20) |
| Attack build-up | T+60s – T+75s | Tor exit → TrickBot C2 → card exfil escalation → hard block | `monitor` → `monitor` → `monitor` → `block` |
| Post-block steady state | T+75s+ | Normal trading traffic resumes; attacker IP held in ipset | `allow` (firewall holding) |

#### Step-by-Step Attack Chain

**Step 1 — Tor exit node contact (T+60s)**

| Field | Value |
|-------|-------|
| Domain | `tor-exit-4f2a.net` |
| Client IP | 10.50.0.1 (trading floor) |
| Score | 55 |
| Decision | `monitor` |
| Reasons | `anonymizer_traffic`, `trading_floor_anomaly` |

A trading-floor workstation queries a known Tor exit node. Score 55 crosses the trading segment's monitor threshold (45). PCI-DSS Requirement 10 mandates logging all network access; Tor traffic is flagged as an anonymizer attempting to evade audit trails.

**Step 2 — TrickBot C2 beacon (T+65s)**

| Field | Value |
|-------|-------|
| Domain | `c2.trickbot-gate.com` |
| Client IP | 10.50.0.1 |
| Score | 70 |
| Decision | `monitor` |
| Reasons | `dns_feed_match`, `banking_trojan_c2`, `financial_fraud_feed` |

The same host beacons to a known TrickBot command-and-control domain listed in `config/feeds/financial_fraud.txt`. DNS feed match contributes +40; the MLP model independently flags the query cadence pattern. Score 70 remains below the trading block threshold (80) — the engine holds on monitor while gathering corroborating signals.

**Step 3 — Payment card exfiltration attempt (T+70s)**

| Field | Value |
|-------|-------|
| Domain | `exfil.payment-collect.io` |
| Client IP | 10.50.0.1 |
| Score | 78 |
| Decision | `monitor` |
| Reasons | `dns_feed_match`, `card_exfil_pattern`, `pci_boundary_risk` |

A second domain associated with card harvesting infrastructure is queried. YARA rules match a card-exfil pattern in the DNS payload. Score 78 is still 2 points below the trading block threshold — the engine escalates severity to prepare for hard enforcement.

**Step 4 — Hard block: PCI-DSS violation confirmed (T+73s)**

| Field | Value |
|-------|-------|
| Domain | `exfil.payment-collect.io` |
| Client IP | 10.50.0.1 |
| Score | 95 |
| Decision | `block` |
| Reasons | `dns_feed_match`, `card_exfil_pattern`, `pci_dss_violation`, `trading_floor_block` |

A repeat query to the same exfil domain, now with compounding signal weight from MLP and YARA, pushes the score to 95 — well above the trading block threshold of 80. The engine writes an ipset rule that silently drops all further traffic from 10.50.0.1 for 86,400 seconds (24 hours). A `critical` severity entry is written to the audit log.

**Step 5 — Firewall holding (T+75s+)**

Normal trading-floor traffic from other hosts resumes immediately (`allow`, score ~20). The attacker's IP (10.50.0.1) remains in the block ipset; all subsequent queries from that host are dropped without reaching the scoring pipeline. The dashboard continues updating with clean traffic, demonstrating that enforcement did not disrupt legitimate operations.

---

## Configuration

### Policy file

Location: `config/policy.json`

The policy controls segment thresholds, score weights, and enforcement parameters. Key excerpt (do not modify for the demo — use `fast_reset.sh` to restore defaults):

```json
{
  "_mode": "minifw_financial",
  "_sector": "finance",
  "_note": "PCI-DSS compliance. Tor/anonymizer blocking. Strict TLS 1.2+ enforcement.",
  "segments": {
    "trading":  { "block_threshold": 80, "monitor_threshold": 45 },
    "internal": { "block_threshold": 80, "monitor_threshold": 45 },
    "guest":    { "block_threshold": 65, "monitor_threshold": 35 },
    "dmz":      { "block_threshold": 75, "monitor_threshold": 50 },
    "default":  { "block_threshold": 85, "monitor_threshold": 55 }
  },
  "minimum_tls_version": "1.2"
}
```

### Threat feeds

Located in `config/feeds/`. Key files for the financial sector:

| Feed file | Purpose |
|-----------|---------|
| `financial_fraud.txt` | Banking trojan C2 domains, card-skimmer infrastructure |
| `tor_exit_nodes.txt` | Known Tor exit node domains and IPs |
| `deny_domains.txt` | General high-confidence malicious domains |
| `deny_ips.txt` | Blocked IP addresses |
| `deny_asn.txt` | Blocked autonomous system numbers |
| `asn_prefixes.txt` | ASN-to-prefix mapping for enrichment |
| `crypto_scams.txt` | Cryptocurrency scam and fraud infrastructure |
| `allow_domains.txt` | Allowlist (bypasses scoring) |

Feeds are plain-text, one entry per line. Reload takes effect on next engine restart.

### Scheduler customization

The attack timeline is defined in `scheduler/demo_scheduler.py`. Key parameters:

- **Phase 1 duration:** 60 seconds (modify `while time.monotonic() - start < 60`)
- **Inter-attack delay:** 5 seconds per step (modify `write_attack_sequence(writer, delay=5.0)`)
- **Normal traffic entries:** `NORMAL_TRAFFIC` list — add/remove domains and IPs
- **Attack sequence:** `ATTACK_SEQUENCE` list — adjust scores, reasons, and domains per step

After editing, restart the demo with `bash fast_reset.sh && bash run_demo.sh`.

---

## Admin Reference

### Log files and key paths

| Path | Description |
|------|-------------|
| `logs/events.jsonl` | All scored events (JSONL, append-only) — primary demo feed |
| `logs/audit.jsonl` | Immutable policy audit trail — PCI-DSS evidence |
| `logs/scheduler.log` | Scheduler phase output and error messages |
| `logs/web.log` | Uvicorn access and error log for the dashboard |
| `logs/engine.log` | FirewallEngine daemon stdout/stderr |
| `minifw.db` | SQLite database — users, RBAC, session tokens |
| `certs/` | TLS certificates (CA, server key/cert) — chmod 700 |
| `fast_reset.sh` | Wipe `logs/` and `minifw.db`, re-run provisioning |
| `teardown_demo.sh` | Full teardown — kills processes, removes venv artifacts |

### Database reset

To reset the demo to a clean state (clears all events, re-creates the admin user):

```bash
bash fast_reset.sh
```

Then start fresh with `bash run_demo.sh`.

### Regenerating TLS certificates

If the CA or server cert expires or is corrupted:

```bash
bash setup_tls.sh
```

The script is safe to re-run — it regenerates all certificates and re-installs the CA into the system trust store.

### Stopping the demo

Press **Ctrl+C** in the terminal running `run_demo.sh`. The script's `cleanup` trap sends `SIGTERM` to the engine, web server, and scheduler processes, then prints `[minifw] Demo stopped.`

---

## Troubleshooting

**TLS cert not found**

```
[minifw] ERROR: TLS cert not found. Run: bash setup_tls.sh
```

Run `bash setup_tls.sh` (requires sudo). The script generates `certs/server.crt` and `certs/server.key`.

---

**Port 8443 in use**

```
ERROR: [Errno 98] address already in use
```

Find and stop the conflicting process:

```bash
ss -tlnp | grep 8443
kill <PID>
```

Then re-run `bash run_demo.sh`.

---

**Browser certificate warning (NET::ERR_CERT_AUTHORITY_INVALID)**

The demo CA was not added to the browser trust store. Re-run `bash setup_tls.sh` with sudo. On systems where `certutil` is unavailable, manually import `certs/minifw-ca.crt` into the browser's certificate authority settings.

---

**Python version too old**

```
[minifw] ERROR: python3 not found
```

or syntax errors during startup. Verify with `python3 --version`. Python 3.10 or newer is required. On Ubuntu 20.04, install via the deadsnakes PPA:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get install python3.11
```

---

**ModuleNotFoundError (uvicorn, fastapi, etc.)**

```
[minifw] ERROR: uvicorn not installed — run: pip install -r requirements.txt
```

The venv is missing dependencies. Either activate the venv manually and install, or let `run_demo.sh` auto-activate it:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

---

**No attack events after 2 minutes**

Check the scheduler log:

```bash
cat logs/scheduler.log
```

If the file is empty or missing, the scheduler did not start. Verify `python3 scheduler/demo_scheduler.py` runs without errors from the package directory. Common cause: `MINIFW_SECRET_KEY` not set (run via `bash run_demo.sh`, not directly).

---

**Dashboard did not start in 20s**

```
[minifw] ERROR: Dashboard did not start in 20s — see logs/web.log
```

Inspect the web log:

```bash
cat logs/web.log
```

Common causes: port 8443 already in use, missing TLS certs, or a Python import error. Fix the root cause and re-run `bash run_demo.sh`.

---

## Production Deployment

### One-line installer

```bash
curl -fsSL https://packages.minifw.ai/install.sh | sudo bash -s -- --sector finance
```

This downloads the signed `.deb`, verifies the GPG signature against key `BDB471E1FB46F58A`, and installs the package.

### Manual dpkg install

```bash
# Build the .deb from source
bash build_deb.sh finance

# Install
sudo dpkg -i dist/minifw-ai-finance_2.2.0_amd64.deb
```

### Production paths

| Resource | Path |
|----------|------|
| Configuration | `/opt/minifw_ai/config/policy.json` |
| Log directory | `/opt/minifw_ai/logs/` |
| Dashboard | `https://<host>:8443` (systemd-managed, starts on boot) |
| Admin credentials | Set via `/opt/minifw_ai/.env` — change `MINIFW_ADMIN_PASSWORD` before first login |
| Sector lock | `/opt/minifw_ai/sector_lock.json` — immutable after first boot |

In production, the firewall daemon runs as a systemd service (`minifw-ai.service`) with root privileges for nftables enforcement. The web admin panel runs as an unprivileged service (`minifw-web.service`) on the same host.
