# MiniFW-AI — AI Behavioral Firewall Engine

MiniFW-AI is an AI-powered behavioral firewall engine deployed on Linux gateway
hardware. It detects unknown network threats by building behavioral models of
normal traffic and flagging deviations using hard rule gates, threat intelligence
scoring, ML inference (MLP), and YARA pattern matching. Enforcement is performed
at the packet level via nftables/ipset across six vertically-locked sectors
(hospital, school, government, finance, legal, establishment).

## Requirements

- **OS**: Ubuntu 22.04+ / Debian 12+ (any Linux with nftables support)
- **Python**: 3.10+
- **Root access**: Required for nftables enforcement and conntrack reading
- **Hardware**: 4+ CPU cores, 8 GB RAM, 100 GB disk, 1 Gbps NIC
- **System packages** (installed automatically by the `.deb`): `python3`, `python3-venv`, `nftables`, `openssl`
- **Recommended**: `dnsmasq` (for DNS log-based threat detection)

## Installation

### Single-Command Install (Recommended)

```bash
sudo dpkg -i minifw-ai_2.0.0_amd64.deb
```

This single command handles everything:

1. Installs application code, ML model, YARA rules, config, and feeds to `/opt/minifw_ai/`
2. Creates a Python virtual environment and installs all dependencies
3. Generates a JWT secret key and random admin password (stored in `/etc/minifw/minifw.env`)
4. Generates a self-signed TLS certificate for the dashboard
5. Creates the `admin` user (super_admin, must change password on first login)
6. Installs and starts both systemd services

The admin password is printed during installation. It is also stored in `/etc/minifw/minifw.env`.

### Verify Installation

```bash
# Check services
systemctl status minifw-ai
systemctl status minifw-ai-web

# Check logs
journalctl -u minifw-ai -f

# Check nftables
sudo nft list table inet minifw

# Check Prometheus metrics (port 9090)
curl -s http://localhost:9090/metrics | head -20

# Access dashboard
# https://localhost:8443
```

### Enable DNS Logging

DNS-based threat detection requires dnsmasq logging:

```bash
sudo apt install -y dnsmasq
echo "log-queries" | sudo tee -a /etc/dnsmasq.conf
echo "log-facility=/var/log/dnsmasq.log" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

### Uninstall

```bash
sudo dpkg -r minifw-ai      # remove (keeps config and data)
sudo dpkg -P minifw-ai      # purge (removes venv, logs, db, /etc/minifw)
```

### Building the Package

```bash
bash scripts/build_deb.sh
# Output: build/minifw-ai_2.0.0_amd64.deb
# Checksum: build/minifw-ai_2.0.0_amd64.deb.sha256
```

## Configuration

### Sector Lock

Each device is locked to a single sector at deployment. Set `MINIFW_SECTOR` in
`/etc/systemd/system/minifw-ai.service`:

| Sector | Description | Special Behavior |
|--------|-------------|------------------|
| `hospital` | Healthcare facilities | HIPAA payload redaction, IoMT alerting |
| `school` | Educational institutions | SafeSearch enforcement |
| `government` | Government networks | Geo-IP restrictions |
| `finance` | Financial institutions | Tor/anonymizer blocking, lower block threshold |
| `legal` | Law firms | Exfiltration monitoring |
| `establishment` | General commercial (default) | Balanced thresholds |

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
GAMBLING_ONLY=1 python -m pytest testing/ -v                       # all tests
GAMBLING_ONLY=1 python -m pytest testing/ -m "not integration" -v  # unit tests only
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

## License

Proprietary — RitAPI V-Sentinel. All rights reserved.
