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

## Part 1: Backend Setup (Core Firewall)

The backend is the core detection and enforcement engine. It runs as a systemd service.

### Step 1: Install Backend

```bash
cd ~/minifw-ai
sudo ./scripts/installer1.sh
```

The installer will:
1. Install system dependencies (nftables, ipset, conntrack)
2. Create Python venv at `/opt/minifw_ai`
3. Deploy configuration files
4. Prompt for **Sector Selection** via TUI

#### Sector Selection TUI
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

### Step 2: Verify Installation

#### Run Test Suite
```bash
cd ~/minifw-ai
python3 testing/run_tests_tui.py
```

**Expected Results:**
- ✅ 5 tests pass (no setup required)
- ⏭️ 5 tests skip (require root/model/pytest)

#### Check Logs
```bash
cat logs/test_results.log
```

#### Run Skipped Tests Manually (Optional)
```bash
# Sector Lock (requires pytest)
pip install pytest
PYTHONPATH=app pytest testing/test_sector_lock.py -v

# MLP Inference (requires trained model)
python3 testing/test_mlp_inference.py --model models/mlp_engine.pkl

# Flow Collector (requires root + conntrack)
sudo python3 testing/test_flow_collector.py 60
```

### Step 3: Start Backend Service

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

### Step 4: Verify Backend Service

#### Check Event Logging
```bash
tail -f /opt/minifw_ai/logs/events.jsonl
```

#### Check Audit Trail
```bash
tail -f /opt/minifw_ai/logs/audit.jsonl
```

---

## Part 2: Frontend Setup (Web Dashboard)

The frontend is a FastAPI web application providing the admin dashboard.

### Prerequisites

- Backend (Part 1) must be installed and running
- Log directory access configured

### Step 1: Configure Environment

#### Required Environment Variables

```bash
# Generate and set JWT secret
export MINIFW_SECRET_KEY=$(openssl rand -hex 32)

# Add to /etc/minifw/minifw.env for persistence
echo "MINIFW_SECRET_KEY=$(openssl rand -hex 32)" | sudo tee -a /etc/minifw/minifw.env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `MINIFW_SECRET_KEY` | **Yes** | JWT signing key (hex, 32+ chars) |
| `MINIFW_PRODUCTION` | No | Set to `true` for secure cookies |

> ⚠️ **FAIL-FAST**: The web app will refuse to start without `MINIFW_SECRET_KEY`

#### Fix Log Permissions (for dev/debug)

If running the web app as a non-root user:
```bash
sudo setfacl -R -m u:$USER:rwx /opt/minifw_ai/logs/
sudo setfacl -R -d -m u:$USER:rwx /opt/minifw_ai/logs/
```

### Step 2: Initialize Database

```bash
cd ~/minifw-ai

# Set required env var
export MINIFW_SECRET_KEY="your-secret-key-here"

# Initialize database (creates minifw.db)
python3 -c "from app.database import init_db; init_db()"

# Create admin user
python3 <<EOF
from app.database import SessionLocal
from app.models.user import User, UserRole, SectorType
from app.services.auth.password_service import hash_password

db = SessionLocal()

# Check if admin exists
existing = db.query(User).filter(User.username == "admin").first()
if not existing:
    admin = User(
        username="admin",
        email="admin@minifw.local",
        hashed_password=hash_password("changeme123"),
        role=UserRole.SUPER_ADMIN.value,
        sector=SectorType.ESTABLISHMENT.value,
        is_active=True
    )
    db.add(admin)
    db.commit()
    print("✅ Admin user created: admin / changeme123")
else:
    print("⚠️ Admin user already exists")
db.close()
EOF
```

### Step 3: Run Web Dashboard

#### Development Mode
```bash
cd ~/minifw-ai
python3 -m uvicorn app.web.app:app --host 0.0.0.0 --port 8080 --reload
```

#### Production Mode (Systemd)

Create `/etc/systemd/system/minifw-web.service`:

```ini
[Unit]
Description=MiniFW-AI Web Dashboard
After=network.target minifw-ai.service

[Service]
Type=simple
User=minifw
Group=minifw
WorkingDirectory=/opt/minifw_ai
EnvironmentFile=/etc/minifw/minifw.env
ExecStart=/opt/minifw_ai/venv/bin/uvicorn app.web.app:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable minifw-web
sudo systemctl start minifw-web
```

**Check logs:** `tail -f /opt/minifw_ai/logs/events.jsonl`

| Username | Password | Role |
|----------|----------|------|
| `admin` | `changeme123` | Super Admin |

> 🔒 **Change the default password immediately after first login!**

### Frontend Security Features

The dashboard includes these security measures:

| Feature | Description |
|---------|-------------|
| **safeFetch()** | Global error handler for API calls (401/403/422/500) |
| **AJAX Login** | Graceful error handling for server issues |
| **Server-side Role Check** | Admin pages redirect non-admin users immediately |
| **Cookie Hardening** | `SameSite=Lax`, `Secure` flag in production |

---

## Detection-to-Enforcement Binding (Audit Compliance)

Every firewall block is linked to its triggering detection event via UUID for regulatory compliance.

### Audit Log Structure

**Detection Event** (logged first):
```json
{
  "event_id": "2f026877-c6a8-49ae-8426-29648888ff04",
  "event_type": "DETECTION",
  "detection_type": "THREAT_BEHAVIOR",
  "source_ip": "192.168.1.100",
  "ai_score": 95,
  "confidence": 0.95,
  "model_version": "1.0.0",
  "threshold_applied": 90
}
```

**Enforcement Event** (linked):
```json
{
  "event_type": "ENFORCEMENT",
  "action": "BLOCK",
  "target": "192.168.1.100",
  "triggering_event_id": "2f026877-c6a8-49ae-8426-29648888ff04"
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINIFW_GAMBLING_ONLY` | `0` | Set to `1` for gambling-only detection mode |
| `MINIFW_MODEL_VERSION` | `1.0.0` | AI model version for audit trail |

### Fail-Closed Enforcement

The system raises `RuntimeError` if enforcement is attempted without a valid detection ID, preventing unaudited blocks.

### Verify Binding Tests

```bash
python3 scripts/verify_sprint.py TestDetectionEnforcementBinding -v
```

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
| `error reading bcrypt version` / `bcrypt has no attribute '__about__'` | Downgrade bcrypt: `pip install bcrypt==4.0.1` (passlib requires <4.1.0) |
| `Permission denied: '/opt/minifw_ai/logs/...'` (manual debug) | Grant user access via ACL: `sudo setfacl -R -m u:$USER:rwx /opt/minifw_ai/logs/` |
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
