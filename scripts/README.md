# MiniFW-AI Scripts

This directory contains setup and utility scripts for MiniFW-AI.

## Setup Scripts

### setup_flow_collector.sh
**Main Setup Script for Flow Collector Testing**

Prepares the environment for running flow collector tests.

```bash
# Run from project root
bash scripts/setup_flow_collector.sh
```

**What it does:**
1. Verifies project structure
2. Checks for required files
3. Creates output directories
4. Sets up Python environment (PYTHONPATH)
5. Shows available test commands

**Usage:**
Always run from project root directory, not from within scripts folder.

---

## Installation Scripts

### install.sh
**Main Installation Script**

Installs MiniFW-AI on the system.

```bash
sudo bash scripts/install.sh
```

### install_systemd.sh
**Systemd Service Installation**

Installs MiniFW-AI as a systemd service.

```bash
sudo bash scripts/install_systemd.sh
```

### Systemd Hardening

#### Hybrid Sector Selection TUI (Purple Screen)

The `installer1.sh` script features an interactive **Hybrid Sector Selection TUI** for choosing the deployment sector at install time. This appears as a purple-themed whiptail menu presenting six sector options:

| Sector | Description |
|--------|-------------|
| **school** | Content filtering, VPN blocking, Safe Search |
| **hospital** | IoMT protection, Critical alert priority |
| **finance** | Anonymizer blocking, High-audit mode |
| **government** | Geo-IP strictness, Long-term retention |
| **legal** | Privileged traffic handling |
| **establishment** | General usage (Shops, Cafes) |

The selected sector is locked into `/etc/minifw/sector.lock` and cannot be changed after deployment, ensuring factory-set security policies remain immutable.

**Usage:**
```bash
# Interactive mode (shows TUI)
sudo bash scripts/installer1.sh

# Automation mode (skip TUI)
sudo bash scripts/installer1.sh hospital
```

---

## Configuration Scripts

### enable_dnsmasq_logging.sh
**Enable DNS Query Logging**

Enables query logging in dnsmasq for MiniFW-AI event collection.

```bash
sudo bash scripts/enable_dnsmasq_logging.sh
```

**What it does:**
- Adds `log-queries` to dnsmasq configuration
- Configures log output to `/var/log/dnsmasq.log`
- Restarts dnsmasq service

### enable_zeek_sni.sh
**Enable Zeek SNI Logging**

Enables TLS SNI (Server Name Indication) logging in Zeek.

```bash
sudo bash scripts/enable_zeek_sni.sh
```

**What it does:**
- Configures Zeek to log TLS SNI data
- Sets up SNI event stream for MiniFW-AI

---

## Simulation Scripts

### simulate_attack.py
**Attack Traffic Simulator**

Generates simulated attack traffic patterns for testing MiniFW-AI detection capabilities.

```bash
python3 scripts/simulate_attack.py [options]
```

**Attack Patterns:**
- DDoS simulation
- Port scanning
- Malicious domain access
- Bot traffic patterns
- Data exfiltration attempts

**Use Cases:**
- Testing threat detection
- Validating ML models
- Stress testing flow collector
- Training data generation

### real_traffic_simulator.py
**Real Traffic Simulator**

Generates realistic normal traffic patterns for balanced testing.

```bash
python3 scripts/real_traffic_simulator.py [options]
```

**Traffic Patterns:**
- Web browsing (HTTP/HTTPS)
- Video streaming
- Gaming traffic
- API calls
- Background services

**Use Cases:**
- Creating balanced datasets
- Testing false positive rates
- Simulating normal network behavior
- Baseline performance testing

---

## Directory Structure

```
scripts/
├── setup_flow_collector.sh      # Main setup script (START HERE)
├── install.sh                   # System installation
├── install_systemd.sh          # Systemd service setup
├── enable_dnsmasq_logging.sh   # DNS logging config
├── enable_zeek_sni.sh          # TLS SNI logging config
├── simulate_attack.py          # Attack traffic simulator
├── real_traffic_simulator.py   # Normal traffic simulator
└── README.md                   # This file
```

## Quick Start

### First Time Setup
```bash
# From project root
bash scripts/setup_flow_collector.sh
```

### Enable Required Services
```bash
# Enable DNS logging (required for flow enrichment)
sudo bash scripts/enable_dnsmasq_logging.sh

# Enable TLS SNI logging (optional, for TLS features)
sudo bash scripts/enable_zeek_sni.sh
```

### Run Traffic Simulation
```bash
# Simulate normal traffic
python3 scripts/real_traffic_simulator.py

# Simulate attacks
python3 scripts/simulate_attack.py
```

## Notes

- All setup scripts should be run from **project root**, not from scripts folder
- Most scripts require root/sudo access for system configuration
- Simulation scripts can run without root access
- Check individual script headers for specific requirements

## Troubleshooting

### "Command not found" errors
Make sure you're running from project root:
```bash
cd /path/to/minifw-ritapi
bash scripts/setup_flow_collector.sh
```

### Permission denied
Use sudo for installation and configuration scripts:
```bash
sudo bash scripts/enable_dnsmasq_logging.sh
```

### Python import errors
Run setup script first:
```bash
bash scripts/setup_flow_collector.sh
```

This will set up PYTHONPATH correctly.
