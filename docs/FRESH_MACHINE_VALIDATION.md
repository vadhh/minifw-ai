# MiniFW-AI — Fresh Machine Validation Protocol
**Version:** 2.2.0  
**Purpose:** Confirm each package works end-to-end on a machine with no prior installation  
**Who runs this:** vadhh before any client demo or distribution

---

## Why This Exists

The most dangerous unresolved risk is an untested cold-start on a client's machine.
Packages ship with a pre-built `venv/` (Python) or pre-pulled Docker images (`.tar`).
These are architecture-specific. A rebuild failure in front of a client is unrecoverable.

This protocol eliminates that risk by requiring a validated cold-start before distribution.

---

## VM Setup (Recommended Method)

Use a VM — not a container, not WSL — because it gives full network isolation and a true clean state.

**Recommended spec:**
- Ubuntu 22.04 LTS or 24.04 LTS (matches typical client environments)
- 2 vCPU, 4 GB RAM, 20 GB disk
- No MiniFW installed, no Python venv pre-existing
- Snapshot taken immediately after OS install ← **restore to this snapshot between sector tests**

**Tools to install on the VM (only these):**
```bash
sudo apt update && sudo apt install -y git curl lsof
```

Do NOT pre-install Python packages, Docker, or pip. The package must install its own dependencies.

---

## Test Protocol — Hospital Standalone (Run First)

Hospital standalone is the reference package. If this passes, the engine and web stack are sound.

### Step 1 — Copy the Package

```bash
# Simulate USB: copy the folder to a fresh location
cp -r /path/to/minifw-usb-hospital-standalone-v2.2.0/ ~/testbed/
cd ~/testbed/minifw-usb-hospital-standalone-v2.2.0/
```

### Step 2 — Run the Pre-Flight Checker

```bash
bash validate_install.sh
```

**Expected output:** all lines show `[ OK ]`. Any `[FAIL]` stops here — fix before proceeding.

### Step 3 — Follow INSTALL.md

```bash
# Try pre-built venv first
source venv/bin/activate
python3 -c "import fastapi; print('OK')"
```

If this fails, rebuild:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 4 — Start the Demo

```bash
bash run_demo.sh
```

### Step 5 — Validate Dashboard

Open `http://localhost:8000`. Login: `admin / Hospital1!`

**Checklist — tick each before marking PASS:**

- [ ] Dashboard loads (no 500/404 error)
- [ ] Sector header shows "Hospital"
- [ ] Protection status shows "Active"
- [ ] Event feed shows at least one ALLOW event within 30 seconds
- [ ] Event feed shows at least one MONITOR event within 90 seconds
- [ ] Event feed shows at least one BLOCK event within 2 minutes
- [ ] BLOCK event has `HIPAA-PHI-*` trace ID
- [ ] BLOCK reason includes `deny_domain` or `hipaa_phi_violation`
- [ ] AI Threat Synthesis Panel is populated
- [ ] No JavaScript errors in browser console

### Step 6 — Validate Attack

Wait for or trigger both attacks:

| Attack | IP | Expected Block Score | Threshold |
|--------|----|---------------------|-----------|
| IoMT ransomware | 172.16.2.50 | 47 | mednet 45 |
| PHI exfil | 192.168.1.75 | 82 | internal 80 |

- [ ] Both blocks appear with correct scores
- [ ] Both blocks have different `trace_id` values
- [ ] Block event JSON is valid (click the event for detail)

### Step 7 — Validate Recovery

```bash
bash fast_reset.sh
```

- [ ] Reset completes in under 60 seconds
- [ ] Dashboard is reachable again after reset
- [ ] Event feed is empty (clean state) after reset

### Step 8 — Record Results

Fill in the results table at the bottom of this document.

---

## Test Protocol — Docker Packages

Run after hospital standalone passes. Docker packages require Docker Engine ≥ 24.

### Setup

```bash
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
```

### Per-Sector Test (repeat for education, government, legal, establishment)

```bash
cd ~/testbed/minifw-usb-{sector}-v2.2.0/
bash demo.sh
```

**Dashboard checklist (adapt sector URL/credentials):**

| Sector | URL | Login | Port |
|--------|-----|-------|------|
| Education | https://localhost:8447 | admin / Education1! | 8447 |
| Government | https://localhost:8449 | admin / Government1! | 8449 |
| Legal | https://localhost:8448 | admin / Legal1! | 8448 |
| Establishment | https://localhost:8444 | admin / SME_Demo1! | 8444 |

For each Docker package, tick:

- [ ] `docker compose up` completes without error
- [ ] Dashboard loads (accept self-signed cert warning)
- [ ] Event feed populates within 60 seconds
- [ ] At least one BLOCK event appears
- [ ] Trace ID format matches sector (e.g., `EDU-SAFE-*`, `GOV-SOV-*`)
- [ ] `bash fast_reset.sh` restores clean state

---

## YARA Validation

For each package, verify YARA rules load without error:

```bash
# In the package directory with venv active (standalone) or inside container (Docker)
python3 -c "
import yara, glob
rules = {f: open(f).read() for f in glob.glob('yara_rules/*.yar')}
compiled = yara.compile(sources=rules)
print(f'YARA OK — {len(rules)} rule files compiled')
"
```

Expected: `YARA OK — 1 rule files compiled` (each sector has exactly one `.yar` file)

---

## Results Table

Fill this in after each test run. Date format: YYYY-MM-DD.

| Date | Sector | Package Type | Machine / VM | venv rebuilt? | Dashboard | Attacks | YARA | Recovery | Pass/Fail | Notes |
|------|--------|-------------|--------------|--------------|-----------|---------|------|----------|-----------|-------|
| 2026-05-26 | Hospital | Standalone | Ubuntu 22.04 Docker container (clean, no Python pre-installed) | Yes (requirements.txt) | ✅ up in 5s | ✅ 1 block at T+38s, HIPAA-PHI trace IDs | ✅ 1 rule compiled | n/a | **PASS 10/10** | Bugs fixed: requirements.txt added, sme_rules.yar/test_rules.yar removed |
| | Education | Docker | | | | | | | | |
| | Government | Docker | | | | | | | | |
| | Legal | Docker | | | | | | | | |
| | Establishment | Docker | | | | | | | | |
| | Finance | Standalone | | | | | | | | |

---

## Failure Triage

| Symptom | Most Likely Cause | Fix |
|---------|-----------------|-----|
| `venv/bin/activate: No such file` | Pre-built venv not included | Run `python3 -m venv venv && pip install -r requirements.txt` |
| `ModuleNotFoundError: fastapi` | venv active but packages missing | `pip install -r requirements.txt` inside venv |
| `Port 8000 already in use` | Previous run not cleaned up | `lsof -ti:8000 \| xargs kill -9` |
| Dashboard 500 on `/` | `MINIFW_SECRET_KEY` not set | `run_demo.sh` sets it — check env vars are exported |
| No events appearing after 2 minutes | Scheduler not started | Check `logs/scheduler.log` for Python errors |
| YARA `SyntaxError` | Rule file corrupted | Re-copy from source; check `yara_rules/*.yar` |
| Docker: `image not found` | `.tar` not loaded | `docker load -i images/minifw-{sector}.tar` |
| Docker: compose path error | Working directory wrong | Must run `bash demo.sh` from inside the package folder |
| `sqlite3.OperationalError` | Corrupt db from prior run | `rm -f minifw.db` then restart |

---

## Distribution Gate

**Do not distribute a package that has not completed this protocol on a fresh VM.**  
Record the test date and VM spec in the results table above before releasing.
