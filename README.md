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
- **System packages**: `python3`, `python3-venv`, `dnsmasq`, `nftables`
- **RAM**: 512 MB minimum, 1 GB recommended
- **Disk**: 200 MB for application + logs

## Installation on VM / Linux Machine

### Option A: Automated Install (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/vadhh/minifw-ai.git
cd minifw-ai

# 2. Run the install script (installs to /opt/minifw_ai)
sudo bash scripts/install.sh

# 3. Enable DNS logging (required for DNS-based threat detection)
sudo bash scripts/enable_dnsmasq_logging.sh
sudo systemctl restart dnsmasq

# 4. Configure your sector (edit the service file)
#    Options: hospital, school, government, finance, legal, establishment
sudo sed -i 's/MINIFW_SECTOR=establishment/MINIFW_SECTOR=establishment/' \
    /etc/systemd/system/minifw-ai.service

# 5. Install and start the systemd service
sudo bash scripts/install_systemd.sh

# 6. Verify it's running
systemctl status minifw-ai
```

### Option B: Manual Install

```bash
# 1. Clone and enter the repo
git clone https://github.com/vadhh/minifw-ai.git
cd minifw-ai

# 2. Install system dependencies
sudo apt update
sudo apt install -y python3 python3-venv dnsmasq nftables

# 3. Create install directory
sudo mkdir -p /opt/minifw_ai/{logs,config/feeds,models,yara_rules}

# 4. Copy application files
sudo cp -r app /opt/minifw_ai/
sudo cp -r prometheus /opt/minifw_ai/
sudo cp -r scheduler /opt/minifw_ai/
sudo cp config/policy.json /opt/minifw_ai/config/
sudo cp config/feeds/*.txt /opt/minifw_ai/config/feeds/
sudo cp models/mlp_model.pkl /opt/minifw_ai/models/
sudo cp yara_rules/*.yar /opt/minifw_ai/yara_rules/
sudo cp requirements.txt /opt/minifw_ai/

# 5. Create virtual environment and install dependencies
sudo python3 -m venv /opt/minifw_ai/venv
sudo /opt/minifw_ai/venv/bin/pip install --upgrade pip
sudo /opt/minifw_ai/venv/bin/pip install -r /opt/minifw_ai/requirements.txt

# 6. Set up nftables
sudo nft add table inet minifw
sudo nft add set inet minifw minifw_block_v4 \
    '{ type ipv4_addr; flags timeout; timeout 86400s; }'
sudo nft add chain inet minifw forward \
    '{ type filter hook forward priority 0; policy accept; }'

# 7. Enable DNS logging
echo "log-queries" | sudo tee -a /etc/dnsmasq.conf
echo "log-facility=/var/log/dnsmasq.log" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq

# 8. Copy and start systemd service
sudo cp systemd/minifw-ai.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now minifw-ai
```

### Post-Install Verification

```bash
# Check service status
systemctl status minifw-ai

# Check logs
journalctl -u minifw-ai -f

# Check nftables rules are set up
sudo nft list table inet minifw

# Check Prometheus metrics (default port 9090)
curl -s http://localhost:9090/metrics | head -20

# Run self-test script
sudo bash scripts/vsentinel_selftest.sh
```

## Configuration

### Sector Lock

Each device is locked to a single sector at deployment. Set in the systemd unit:

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

```bash
# Start the web admin (separate process)
cd /opt/minifw_ai
PYTHONPATH=/opt/minifw_ai/app /opt/minifw_ai/venv/bin/uvicorn \
    web.app:app --host 0.0.0.0 --port 8080
```

Access at `http://<vm-ip>:8080`. Default credentials are generated during
`install_systemd.sh` and stored in `/etc/minifw/minifw.env`.

## Development

### Run Locally (without root)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit paths as needed
export $(cat .env | xargs)
GAMBLING_ONLY=1 python -m app.minifw_ai
```

### Run Tests

```bash
pip install pytest
python -m pytest testing/ -v                       # all tests
python -m pytest testing/ -m "not integration" -v  # unit tests only
```

### Retrain MLP Model

```bash
# Generate training data
python3 scripts/generate_pretrained_model.py

# Or train on real flow data
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

Auto-transitions based on DNS telemetry health.

## Documentation

| Document | Description |
|----------|-------------|
| [DEVELOPER.md](DEVELOPER.md) | Architecture deep-dive, module reference, 11-stage development model |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [TODO.md](TODO.md) | Stage 4 readiness task list (all complete) |

## License

Proprietary — RitAPI V-Sentinel. All rights reserved.
