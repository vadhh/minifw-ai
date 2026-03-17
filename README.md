# MiniFW-AI — AI Behavioral Firewall Engine

MiniFW-AI is an AI-powered behavioral firewall engine deployed on Linux gateway
hardware. It detects unknown network threats by building behavioral models of
normal traffic and flagging deviations using hard rule gates, threat intelligence
scoring, ML inference (MLP), and YARA pattern matching. Enforcement is performed
at the packet level via nftables/ipset across six vertically-locked sectors
(hospital, education, government, finance, legal, establishment).

The same `.deb` package supports all six sectors. The active sector is set once
at deployment and locked for the lifetime of that installation.

## Requirements

- **OS**: Ubuntu 22.04+ / Debian 12+ (any Linux with nftables support)
- **Python**: 3.10+
- **Root access**: Required for nftables enforcement and conntrack reading
- **Hardware**: 4+ CPU cores, 8 GB RAM, 100 GB disk, 1 Gbps NIC
- **System packages** (installed automatically by the `.deb`): `python3`, `python3-venv`, `nftables`, `openssl`
- **Recommended**: `dnsmasq` (for DNS log-based threat detection)

## Installation

### Step 1 — Verify the package

Before installing, confirm the package has not been tampered with:

```bash
# Import the signing key
gpg --import minifw-ai-release.asc

# Verify GPG signature (adjust filename for your sector/version)
gpg --verify minifw-ai_2.1.0_amd64.deb.asc minifw-ai_2.1.0_amd64.deb
# Expected: "Good signature from MiniFW-AI Release ..."

# Verify SHA-256 checksum
sha256sum -c minifw-ai_2.1.0_amd64.deb.sha256
# Expected: "minifw-ai_2.1.0_amd64.deb: OK"
```

See [docs/release-verification.md](docs/release-verification.md) for full details.

---

### Step 2 — Set the sector (before or after install)

The default sector is `establishment`. To deploy for a different sector,
decide now — see [Changing the Sector](#changing-the-sector) below.

---

### Step 3 — Install system dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv nftables openssl dnsmasq
```

---

### Step 4 — Install the package

```bash
sudo dpkg -i minifw-ai_2.1.0_amd64.deb
```

The installer automatically:
1. Creates a Python virtual environment and installs all dependencies
2. Generates a random JWT secret key and admin password → `/etc/minifw/minifw.env`
3. Generates a self-signed TLS certificate → `/etc/minifw/tls/`
4. Creates the `admin` user in the database (password printed to console — save it)
5. Loads the `nf_conntrack` kernel module and persists it across reboots
6. Restricts Grafana to localhost (if installed)
7. Disables CUPS print service
8. Enables and starts `minifw-ai` and `minifw-ai-web` services

> **Save the admin password** printed during install. It is also stored in
> `/etc/minifw/minifw.env` (readable only by root).

---

### Step 5 — Enable DNS logging

DNS-based threat detection requires dnsmasq to write query logs:

```bash
# If not already in /etc/dnsmasq.conf:
echo "log-queries" | sudo tee -a /etc/dnsmasq.conf
echo "log-facility=/var/log/dnsmasq.log" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

---

### Step 6 — Connect the network interface

Plug the ethernet cable into the gateway NIC (`enp1s0`, `enp3s0`, or `enp4s0`).
Configure the interface via netplan:

```bash
# Example: /etc/netplan/01-minifw.yaml
network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: true   # or set a static IP

sudo netplan apply
```

---

### Step 7 — Verify the installation

```bash
# Services running
systemctl status minifw-ai minifw-ai-web

# Engine is processing events
journalctl -u minifw-ai -f

# nftables enforcement table created
sudo nft list table inet minifw

# Prometheus metrics available
curl -s http://localhost:9090/metrics | grep minifw_ai_flows

# Dashboard accessible
# Open https://localhost:8443 in a browser
# Login: admin / <password from install>
```

---

### Step 8 — Change admin password

On first login at `https://localhost:8443`, the system will prompt for a
password change. Alternatively via the dashboard: **Users → admin → Change Password**.

---

### Uninstall

```bash
sudo dpkg -r minifw-ai      # remove (keeps /etc/minifw, feeds, and logs)
sudo dpkg -P minifw-ai      # purge (removes everything including secrets)
```

---

### Building the Package

```bash
bash scripts/build_deb.sh [sector]
# Default sector: establishment
# Examples:
#   bash scripts/build_deb.sh hospital
#   bash scripts/build_deb.sh finance
# Output: build/minifw-ai_2.1.0_amd64.deb
# Checksum: build/minifw-ai_2.1.0_amd64.deb.sha256
```

---

## Changing the Sector

The `.deb` package supports all six sectors. The sector is set in the systemd
service unit and locked at daemon startup — it cannot be changed at runtime.

### Available sectors

| Sector | Use case | Monitor / Block threshold | Special behaviour |
|--------|----------|--------------------------|-------------------|
| `establishment` | General commercial, SME, retail | 60 / 90 (default) | Balanced |
| `hospital` | Hospitals, clinics | **40 / 85** (stricter) | HIPAA payload redaction, IoMT device alerts (severity=critical), `healthcare_threats.txt` feed, hospital YARA rules |
| `finance` | Banks, financial institutions | 60 / **80** (stricter) | Tor/anonymizer blocking |
| `education` | Schools, universities | 60 / 90 | SafeSearch enforcement |
| `government` | Government networks | 60 / 90 | Geo-IP restrictions |
| `legal` | Law firms | 60 / 90 | Exfiltration monitoring |

### How to set the sector

**Option A — Build a sector-specific package (recommended)**

```bash
bash scripts/build_deb.sh hospital
sudo dpkg -i build/minifw-ai_2.1.0_amd64.deb
# The sector is baked into the package — no post-install edits needed.
```

Valid sectors: `hospital`, `education`, `government`, `finance`, `legal`, `establishment`

**Option B — After install**

```bash
# Edit the live service unit
sudo nano /etc/systemd/system/minifw-ai.service
# Change: Environment=MINIFW_SECTOR=establishment
# To:     Environment=MINIFW_SECTOR=hospital

# Apply the change
sudo systemctl daemon-reload
sudo systemctl restart minifw-ai

# Confirm the new sector is active
journalctl -u minifw-ai -n 5 | grep SECTOR
```

### Verify the active sector

```bash
journalctl -u minifw-ai | grep "SECTOR_LOCK"
# Expected: [SECTOR_LOCK] Device sector: hospital (LOCKED)

# Or check via the dashboard
# https://localhost:8443/admin/api/sector-lock
```

> **Important:** The sector lock is permanent for a running daemon instance.
> A restart is always required after changing `MINIFW_SECTOR`. Attempting to
> set an invalid sector (or the legacy `gambling` value) will cause the daemon
> to refuse to start.

## Configuration

### Sector Lock

See [Changing the Sector](#changing-the-sector) above for the full sector table,
how to set the sector before or after install, and how to verify it is active.

### DNS Source

Set `MINIFW_DNS_SOURCE` in the systemd unit:

| Source | Description |
|--------|-------------|
| `file` | Tail dnsmasq log (default) |
| `journald` | Stream from systemd-resolved |
| `udp` | Listen on UDP socket |
| `none` | Degraded mode — flow-only, no DNS scoring |

### Threat Feeds

Populate the feed files in `/opt/minifw_ai/config/feeds/`:

```
deny_domains.txt    — blocked domain patterns (fnmatch: *.malware.com)
allow_domains.txt   — whitelisted domains (bypass deny checks)
deny_ips.txt        — blocked IP addresses
deny_asn.txt        — blocked ASNs (e.g. AS12345)
asn_prefixes.txt    — IP-to-ASN mapping (CIDR ASN format)
tor_exit_nodes.txt  — Tor exit IPs (auto-loaded for finance sector)
```

Feed files are marked as conffiles — they are preserved on package upgrade.

### Scoring Weights

Edit `/opt/minifw_ai/config/policy.json` to tune scoring:

| Signal | Default Weight | Description |
|--------|---------------|-------------|
| DNS deny match | +40 | Domain in deny_domains.txt |
| TLS SNI deny match | +35 | SNI in deny_domains.txt |
| ASN deny | +15 | IP's ASN in deny_asn.txt |
| IP deny (Tor) | +15 | IP in deny_ips.txt |
| DNS burst | +10 | QPM exceeds threshold |
| MLP score | 0–30 | ML model confidence |
| YARA score | 0–35 | Pattern match severity |
| Hard gate | =100 | Override: PPS, burst, bot detection |

Decision thresholds (configurable per segment):
- Score < 60 → **allow**
- Score >= 60 → **monitor**
- Score >= 90 → **block** (IP added to nftables)

## Web Admin Panel

The dashboard runs on `https://localhost:8443` with TLS enabled.

Default credentials are generated during installation and stored in
`/etc/minifw/minifw.env`. The admin user is required to change their
password on first login.

Features:
- Live traffic monitoring and event log
- Threat feed management (allow/deny domains, IPs, ASNs)
- Policy configuration editor
- User management with role-based access
- 2FA/TOTP enrollment
- Audit log viewer
- Event export (XLSX)

## Development

### Run Tests

```bash
pip install pytest
python -m pytest testing/ -v                       # all tests
python -m pytest testing/ -m "not integration" -v  # unit tests only
```

### Retrain MLP Model

```bash
python3 scripts/train_mlp.py --data /opt/minifw_ai/logs/flow_records.jsonl
```

## Architecture

```
DNS event → pump_zeek() + pump_flows()
          → StateManager.check_and_transition()
          → FeedMatcher [deny_domains, deny_ips, deny_asn]
          → BurstTracker [QPM tracking]
          → evaluate_hard_threat() [PPS/burst/bot gates]
          → MLPThreatDetector.is_suspicious() [optional]
          → YARAScanner.scan_payload() [optional]
          → score_and_decide() → allow / monitor / block
          → ipset_add() [nftables enforcement on block]
          → EventWriter.write() [JSONL log]
          → Prometheus metrics update
```

Two protection states:
- **BASELINE_PROTECTION** — hard gates only (MLP/YARA disabled)
- **AI_ENHANCED_PROTECTION** — hard gates + MLP + YARA

Auto-transitions based on DNS telemetry health. System fails closed —
if DNS telemetry is lost, it downgrades to BASELINE_PROTECTION (hard gates
remain active, AI modules disabled).

## File Layout

```
/opt/minifw_ai/
├── app/                    # Application code
│   ├── minifw_ai/          # Firewall engine (daemon)
│   ├── web/                # FastAPI web admin
│   ├── models/             # SQLAlchemy models
│   ├── services/           # Business logic
│   ├── controllers/        # Route handlers
│   └── middleware/          # Auth middleware
├── config/
│   ├── policy.json         # Scoring thresholds and weights
│   └── feeds/              # Threat intelligence feeds
├── models/
│   └── mlp_model.pkl       # Pre-trained MLP model
├── yara_rules/             # YARA detection rules
├── prometheus/             # Metrics module
├── scheduler/              # Retraining scheduler
├── logs/                   # Runtime logs (events.jsonl, audit.jsonl)
├── scripts/                # Backup, restore, training tools
├── venv/                   # Python virtual environment (created at install)
└── requirements.txt

/etc/systemd/system/
├── minifw-ai.service       # Firewall engine daemon
└── minifw-ai-web.service   # Web admin panel

/etc/minifw/
├── minifw.env              # Secrets (JWT key, admin password)
└── tls/
    ├── server.key          # TLS private key
    └── server.crt          # TLS certificate
```

## Documentation

| Document | Description |
|----------|-------------|
| [DEVELOPER.md](DEVELOPER.md) | Architecture deep-dive, module reference, 11-stage development model |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [TODO.md](TODO.md) | Stage 4 readiness task list (all complete) |
| [docs/monitoring-mode.md](docs/monitoring-mode.md) | Monitoring mode reference, scoring thresholds, analyst workflow |
| [docs/release-verification.md](docs/release-verification.md) | GPG signing key, package verification steps |
| [docs/rollback.md](docs/rollback.md) | Rollback and emergency removal procedure |
| [docs/report-2026-03-16.md](docs/report-2026-03-16.md) | Establishment deployment readiness report (2026-03-16) |
| [docs/report-2026-03-17-hospital.md](docs/report-2026-03-17-hospital.md) | Hospital sector deployment readiness report (2026-03-17) |

## License

Proprietary — RitAPI V-Sentinel. All rights reserved.
