# Healthcare Tutorial + Installation Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the MINIFW-AI Healthcare (hospital) product by adding a full user GUIDE.md and a root-level `build_deb.sh` wrapper — the two remaining items on the hospital product checklist.

**Architecture:** GUIDE.md is a standalone Markdown document placed directly in the hospital demo package directory. The `build_deb.sh` at repo root is a thin 3-line wrapper that delegates to the already-complete `scripts/build_deb.sh`. No new code paths are introduced.

**Tech Stack:** Bash (build_deb.sh wrapper), Markdown (GUIDE.md), dpkg-deb (already used by scripts/build_deb.sh)

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md` | CREATE | Full product guide: setup + dashboard + threat scenarios + config + admin + troubleshooting |
| `dist/minifw-usb-hospital-standalone-v2.2.0/README.txt` | MODIFY | Stub that points to GUIDE.md |
| `dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md` | MODIFY | Stub that points to GUIDE.md |
| `build_deb.sh` | CREATE | Root-level wrapper calling `scripts/build_deb.sh "$@"` |

---

## Task 1: Write GUIDE.md

**Files:**
- Create: `dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md`

- [ ] **Step 1: Create GUIDE.md**

```markdown
# MiniFW-AI Hospital — User Guide

**Version:** 2.2.0 | **Mode:** Demo (offline, no root)

---

## Overview

MiniFW-AI Hospital is an AI-powered behavioral firewall for healthcare gateway hardware. It protects against:

- **Ransomware C2 callbacks** — known command-and-control domains blocked at DNS resolution time
- **HIPAA data exfiltration** — anomalous outbound data patterns to cloud storage and personal email services
- **IoMT anomaly traffic** — unexpected protocol and burst patterns from medical devices

This demo kit runs entirely offline on your laptop. No Docker, no root, no real network interception — a controlled environment for CIO/executive review.

---

## Prerequisites

| Requirement | Check Command | Minimum |
|-------------|---------------|---------|
| Python 3 | `python3 --version` | 3.10+ |
| pip | `pip3 --version` | any |
| Port 8000 free | `ss -tlnp \| grep 8000` | — |

Works on Linux, macOS, and Windows with WSL2.

---

## Quick Start

```bash
bash run_demo.sh
```

Open **http://localhost:8000** and login with `admin` / `Hospital1!`.

**Expected terminal output:**
```
[minifw-demo] Starting MiniFW-AI Hospital Sector Demo...
[minifw-demo] Dashboard → http://localhost:8000
[minifw-demo] Login     → admin / Hospital1!
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Events begin populating within a few seconds. The engine cycles through synthetic healthcare traffic automatically — no interaction required.

**First time on a new machine only** — if `run_demo.sh` fails with `ModuleNotFoundError`:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
bash run_demo.sh
```

---

## Dashboard Walkthrough

### Event Feed

The main table shows every DNS decision made by the engine. Columns:

| Column | Meaning |
|--------|---------|
| **Time** | Timestamp of the DNS query |
| **Domain** | Queried hostname |
| **Client IP** | Source device |
| **Score** | Threat score 0–100 |
| **Decision** | ALLOW / MONITOR / BLOCK |
| **Reason** | Primary detection layer that fired |

**Score composition** (configurable in `policy.json`):

| Layer | Max contribution |
|-------|-----------------|
| DNS feed match (deny list) | +40 |
| TLS/SNI anomaly | +35 |
| ASN block list | +15 |
| DNS burst / qpm spike | +10 |
| MLP classifier | 0–30 |
| YARA payload match | 0–35 |

### Decision Thresholds (Hospital sector defaults)

| Score range | Decision |
|-------------|----------|
| 0–39 | ALLOW |
| 40–69 | MONITOR (logged, not blocked) |
| 70–100 | BLOCK (nftables rule added in production) |

### AI Threat Synthesis Panel

Located on the dashboard home page. Shows:

- **Current protection state:** `BASELINE_PROTECTION` (hard gates only) or `AI_ENHANCED_PROTECTION` (adds MLP + YARA scoring)
- **HIPAA compliance indicators:** detection category mapped to HIPAA rule (e.g., §164.312 Technical Safeguards)
- **Top threat actors:** most frequently blocked domains/IPs in the current session
- **Detection breakdown:** pie chart of which layers contributed to blocks

### Protection State

The engine auto-transitions between two states based on DNS telemetry health:

- **BASELINE_PROTECTION** — hard gates only (deny lists, burst gates, PPS gates). Active on startup.
- **AI_ENHANCED_PROTECTION** — adds MLP inference and YARA scanning on top of hard gates. Activates once the engine has sufficient DNS event volume to trust the feed.

State is shown in the dashboard header and in the AI Threat Synthesis Panel.

---

## Threat Scenarios

The demo cycles through `demo_data/normal_traffic.json` and `demo_data/attack_traffic.json` continuously. Three attack patterns are included:

### 1. Ransomware C2

**What it is:** A Windows host queries a known ransomware command-and-control domain to receive encryption keys.

**Detection path:**
1. `FeedMatcher` checks the domain against `config/feeds/deny_domains.txt` → match
2. Score forced to 100 (hard gate override — `evaluate_hard_threat()`)
3. Decision: **BLOCK**

**What to look for in the event feed:**
- Domain matching `*-c2.*`, `*.onion.*`, or entries in the deny list
- Reason column: `deny_domain`
- Score: 100

### 2. Suspicious API Data Leak

**What it is:** A medical device or workstation makes high-frequency API calls to an external cloud endpoint, consistent with exfiltrating patient records.

**Detection path:**
1. `BurstTracker` detects queries-per-minute (qpm) spike above threshold
2. MLP classifier marks the flow as anomalous (+20–30)
3. Score crosses MONITOR threshold

**What to look for:**
- Domain: cloud storage or analytics endpoints (e.g., `*.s3.amazonaws.com`, `*.analytics.*`)
- Reason: `dns_burst` or `mlp_suspicious`
- Score: 40–70, Decision: MONITOR or BLOCK

### 3. Data Exfiltration via DNS Tunneling

**What it is:** An attacker encodes stolen data in DNS query subdomains (e.g., `encodeddata.evil-tunnel.com`) to exfiltrate past firewall rules that only inspect HTTP.

**Detection path:**
1. `dns_tunnel_detect.py` flags subdomain entropy as high
2. `BurstTracker` registers abnormal qpm
3. YARA rule matches payload pattern in query string (+35)

**What to look for:**
- Domain: long, high-entropy subdomains
- Reason: `yara_match` or `dns_tunnel`
- Score: 75–100, Decision: BLOCK

---

## Configuration

### policy.json

`config/modes/minifw_hospital/policy.json` controls decision thresholds and score weights per segment.

Key fields:

```json
{
  "thresholds": {
    "block": 70,
    "monitor": 40,
    "alert_only": 20
  },
  "score_weights": {
    "feed_match": 40,
    "tls_sni": 35,
    "asn_deny": 15,
    "dns_burst": 10
  }
}
```

Edit thresholds to make the demo more or less aggressive. A `block` threshold of 50 will block more traffic; 90 will allow most traffic through to MONITOR.

### demo_data/

Two files control the synthetic traffic:

- `normal_traffic.json` — benign healthcare traffic (EHR lookups, IoMT heartbeats, NTP, OS updates)
- `attack_traffic.json` — the three attack patterns above

Each entry is a synthetic DNS event. You can add custom entries to inject specific domains or IPs into the simulation.

---

## Admin Reference

| Item | Location |
|------|----------|
| Audit log (JSONL) | `logs/audit.jsonl` |
| Events log | `logs/events.jsonl` |
| SQLite database | `minifw.db` |
| Protection state | `logs/deployment_state.json` |
| Reset demo to clean state | `bash fast_reset.sh` |
| Stop demo | `Ctrl+C` in terminal |

**Reset the database** (if corrupted or you want a clean slate):
```bash
rm -f minifw.db
bash run_demo.sh
```
The database is auto-provisioned on startup.

**MINIFW_SECRET_KEY** is set automatically by `run_demo.sh`. You do not need to configure it for the demo. It is required for production deployments.

---

## Troubleshooting

**Port 8000 already in use:**
```bash
lsof -ti:8000 | xargs kill -9
bash run_demo.sh
```

**Python version too old (`< 3.10`):**
```bash
python3 --version
# Ubuntu/Debian:
sudo apt install python3.11
# macOS:
brew install python@3.11
```

**`ModuleNotFoundError` on startup:**
```bash
source venv/bin/activate
pip install -r requirements.txt
bash run_demo.sh
```

**No events appearing in the dashboard:**
- Check `logs/` for error messages
- Verify `demo_data/normal_traffic.json` and `demo_data/attack_traffic.json` exist
- Verify `MINIFW_SECRET_KEY` is set: `grep SECRET_KEY <(bash -c "source venv/bin/activate && bash run_demo.sh 2>&1 | head -5")`

**Database error on first run:**
```bash
rm -f minifw.db
bash run_demo.sh
```

**Engine starts but dashboard shows no data after 30 seconds:**
```bash
cat logs/events.jsonl | tail -5
```
If empty, check `logs/minifw_engine.log` for startup errors.

---

## Production Deployment

This kit is for offline demos only. For production deployment on gateway hardware:

**One-line installer** (Debian/Ubuntu gateway host, requires root):
```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

The installer prompts for sector selection, downloads the sector-specific `.deb`, verifies the GPG signature, installs, and starts both services automatically.

**Manual .deb install:**
```bash
sudo dpkg -i minifw-ai_2.2.1-hospital_amd64.deb
sudo systemctl status minifw-ai minifw-ai-web
```

- Config: `/opt/minifw_ai/config/modes/minifw_hospital/policy.json`
- Logs: `/opt/minifw_ai/logs/`
- Dashboard: **https://localhost:8443** (TLS, self-signed cert generated on install)
- Credentials: `/etc/minifw/minifw.env` (auto-generated on first install)
```

- [ ] **Step 2: Verify all 9 sections are present**

```bash
for section in "Overview" "Prerequisites" "Quick Start" "Dashboard Walkthrough" \
               "Threat Scenarios" "Configuration" "Admin Reference" \
               "Troubleshooting" "Production Deployment"; do
    grep -q "## ${section}" dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md \
        && echo "OK: ${section}" || echo "MISSING: ${section}"
done
```

Expected output: 9 lines all starting with `OK:`

- [ ] **Step 3: Commit**

```bash
git add dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md
git commit -m "docs(hospital): add full product GUIDE.md — setup, dashboard, threat scenarios, config"
```

---

## Task 2: Stub README.txt and INSTALL.md

**Files:**
- Modify: `dist/minifw-usb-hospital-standalone-v2.2.0/README.txt`
- Modify: `dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md`

- [ ] **Step 1: Replace README.txt with a pointer**

Replace the full content of `dist/minifw-usb-hospital-standalone-v2.2.0/README.txt` with:

```
MiniFW-AI Hospital Demo — v2.2.0
=================================

See GUIDE.md for the full user guide:
  setup, dashboard walkthrough, threat scenarios, configuration,
  admin reference, troubleshooting, and production deployment.

Quick start:
  bash run_demo.sh
  open http://localhost:8000
  login: admin / Hospital1!
```

- [ ] **Step 2: Replace INSTALL.md with a pointer**

Replace the full content of `dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md` with:

```markdown
# MiniFW-AI Hospital — Installation

This document has been consolidated into **GUIDE.md**.

See [GUIDE.md](GUIDE.md) for:
- Prerequisites
- Quick Start
- Troubleshooting
- Production Deployment (.deb + one-line installer)
```

- [ ] **Step 3: Commit**

```bash
git add dist/minifw-usb-hospital-standalone-v2.2.0/README.txt \
        dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md
git commit -m "docs(hospital): consolidate README.txt and INSTALL.md into GUIDE.md stubs"
```

---

## Task 3: Create root-level build_deb.sh wrapper

**Files:**
- Create: `build_deb.sh` (repo root)

**Context:** The full implementation already exists at `scripts/build_deb.sh`. It uses `REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"` which correctly resolves the repo root when invoked from `scripts/`. A root-level wrapper delegates to it so `bash build_deb.sh hospital` works as documented in CLAUDE.md.

- [ ] **Step 1: Verify the target script exists and works from scripts/**

```bash
bash -n scripts/build_deb.sh && echo "syntax OK"
bash scripts/build_deb.sh --help 2>&1 | head -3 || \
    bash scripts/build_deb.sh INVALIDSECTOR 2>&1 | head -3
```

Expected: syntax OK, then an error message containing "Valid sectors:"

- [ ] **Step 2: Create build_deb.sh at repo root**

Create `build_deb.sh` with this exact content:

```bash
#!/usr/bin/env bash
# Wrapper — delegates to scripts/build_deb.sh which contains the full implementation.
exec "$(dirname "$0")/scripts/build_deb.sh" "$@"
```

```bash
chmod +x build_deb.sh
```

- [ ] **Step 3: Test the wrapper with an invalid sector (no dpkg-deb needed)**

```bash
bash build_deb.sh INVALIDSECTOR 2>&1
```

Expected output contains:
```
ERROR: Invalid sector 'INVALIDSECTOR'
Valid sectors: hospital education government finance legal establishment
```

- [ ] **Step 4: Test the wrapper with a valid sector (syntax + argument passing)**

```bash
bash -c "bash build_deb.sh hospital 2>&1 | head -6"
```

Expected: The build header prints with `Sector: hospital`. The build will fail if `dpkg-deb` is not installed — that is acceptable; the point is the wrapper correctly delegates.

```
============================================
 Building minifw-ai 2.2.0-hospital
 Sector:  hospital
 Output:  .../build/minifw-ai_2.2.0-hospital_amd64.deb
============================================
```

- [ ] **Step 5: Commit**

```bash
git add build_deb.sh
git commit -m "feat(packaging): add root-level build_deb.sh wrapper for CLAUDE.md documented usage"
```

---

## Task 4: Final verification

- [ ] **Step 1: Confirm all hospital checklist items are complete**

```bash
echo "=== STATIC ===" && \
    ls dist/minifw-usb-hospital-standalone-v2.2.0/static/index.html && echo "OK"

echo "=== LIVE ===" && \
    ls dist/minifw-usb-hospital-standalone-v2.2.0/run_demo.sh && echo "OK"

echo "=== TUTORIAL ===" && \
    ls dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md && \
    wc -l dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md && echo "OK"

echo "=== INSTALL (one-liner) ===" && \
    ls install.sh && echo "OK"

echo "=== INSTALL (.deb builder) ===" && \
    ls build_deb.sh && bash build_deb.sh INVALIDSECTOR 2>&1 | grep "Valid sectors" && echo "OK"
```

Expected: all 5 checks print `OK`.

- [ ] **Step 2: Confirm no regressions to existing test suite**

```bash
PYTHONPATH=. pytest testing/ -m "not integration" -q 2>&1 | tail -5
```

Expected: `492 passed` (or higher), 0 failed.

- [ ] **Step 3: Final commit if anything was missed**

```bash
git status
# Stage and commit any unstaged changes before declaring done
```
