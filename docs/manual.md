# MiniFW-AI Installation & Staging Manual

## Quick Reference

| Step | Command | Duration |
|------|---------|----------|
| 1. Install | `sudo ./scripts/installer1.sh` | ~5 min |
| 2. Configure | Set sector via TUI | 1 min |
| 3. Verify | `python3 testing/run_tests_tui.py` | 2 min |
| 4. Start | `sudo systemctl start minifw-ai` | instant |

---

## Prerequisites

```bash
# Required
- Ubuntu/Debian Linux (gateway mode)
- Python 3.10+
- Root access

# Network Setup
- dnsmasq running with logging
- Gateway routing configured
```

---

## Step 1: Install

```bash
cd ~/minifw-ai
sudo ./scripts/installer1.sh
```

The installer will:
1. Install system dependencies (nftables, ipset, conntrack)
2. Create Python venv at `/opt/minifw_ai`
3. Deploy configuration files
4. Prompt for **Sector Selection** via TUI

### Sector Selection TUI
```
┌─────────────────────────────────────────┐
│ Select Sector for this Installation:   │
├─────────────────────────────────────────┤
│ ( ) Hospital                            │
│ (*) School                              │
│ ( ) Government                          │
│ ( ) Finance                             │
│ ( ) Legal                               │
│ ( ) Establishment                       │
└─────────────────────────────────────────┘
```

> ⚠️ **IMPORTANT**: Sector is immutable after installation!

---

## Step 2: Verify Installation

### Run Test Suite
```bash
cd ~/minifw-ai
python3 testing/run_tests_tui.py
```

**Expected Results:**
- ✅ 5 tests pass (no setup required)
- ⏭️ 5 tests skip (require root/model/pytest)

### Check Logs
```bash
cat logs/test_results.log
```

### Run Skipped Tests Manually (Optional)
```bash
# Sector Lock (requires pytest)
pip install pytest
PYTHONPATH=app pytest testing/test_sector_lock.py -v

# MLP Inference (requires trained model)
python3 testing/test_mlp_inference.py --model models/mlp_engine.pkl

# Flow Collector (requires root + conntrack)
sudo python3 testing/test_flow_collector.py 60
```

---

## Step 3: Start Service

```bash
# Install systemd service
sudo ./scripts/install_systemd.sh

# Start
sudo systemctl start minifw-ai

# Enable on boot
sudo systemctl enable minifw-ai

# Check status
sudo systemctl status minifw-ai
```

---

## Step 4: Verify Service

### Check Event Logging
```bash
tail -f /opt/minifw_ai/logs/events.jsonl
```

### Check Audit Trail
```bash
tail -f /opt/minifw_ai/logs/audit.jsonl
```

### Start Web Dashboard
```bash
# In separate terminal
cd ~/minifw-ai
python3 -m uvicorn app.web.app:app --host 0.0.0.0 --port 8080
```

Access: `http://<gateway-ip>:8080`

---

## Step 5: Generate Proof Pack

After verification, export evidence for auditors:

```bash
sudo ./scripts/export_proof_pack.sh
```

Output: `proof_pack_YYYYMMDD_HHMMSS.tar.gz`

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: pytest` | `pip install pytest` |
| `No module named 'yara'` | `pip install yara-python` |
| `No module named 'sklearn'` | `pip install scikit-learn` |
| `No module named 'jose'` | `pip install python-jose[cryptography]` |
| `Permission denied` | Run with `sudo` |
| `No module named 'minifw_ai'` | PYTHONPATH wrong. Re-run `sudo ./scripts/installer1.sh` (fixed to use dual path) |
| `No module named 'app.models'` | Same as above - installer generates correct wrapper |
| `cannot import name 'stream_dns_events'` | Update code: `git pull` (fixed in latest version) |
| `Sector Lock error` | Check `MINIFW_SECTOR` env or `/opt/minifw_ai/config/sector_lock.json` |
| `dnsmasq not logging` | Add `log-queries` to `/etc/dnsmasq.conf` |

---

## Install Optional Dependencies

The MiniFW-AI service runs inside an isolated virtual environment at `/opt/minifw_ai/venv`.
**Global pip installs are NOT visible to the service or test runner.**

Install dependencies into the venv:

```bash
# Activate the venv first
source /opt/minifw_ai/venv/bin/activate

# Install all optional packages
pip install pytest scikit-learn yara-python python-jose[cryptography] pandas

# Deactivate when done
deactivate
```

Or use the venv pip directly (without activation):

```bash
sudo /opt/minifw_ai/venv/bin/pip install pytest scikit-learn yara-python python-jose[cryptography] pandas
```

After installing, restart the service:
```bash
sudo systemctl restart minifw-ai
```

---

## Staging Checklist

- [ ] Clone repo to staging gateway
- [ ] Run installer with correct sector
- [ ] Verify all 5 passable tests pass
- [ ] Start systemd service
- [ ] Generate traffic through gateway
- [ ] Check events.jsonl for detections
- [ ] Login to web dashboard
- [ ] Export proof pack for records
