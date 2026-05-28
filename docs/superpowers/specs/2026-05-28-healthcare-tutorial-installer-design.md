---
name: healthcare-tutorial-installer
description: Design for MINIFW-AI Healthcare (hospital) TUTORIAL (GUIDE.md) and INSTALLATION PROGRAM (build_deb.sh) — two missing deliverables to complete the hospital product checklist
metadata:
  type: project
  status: approved
  date: 2026-05-28
  product: minifw-ai-hospital
---

# MINIFW-AI Healthcare — Tutorial + Installation Program Design

**Date:** 2026-05-28
**Status:** Approved
**Context:** Part of a 6-product completion checklist. Healthcare is the first product to be completed. STATIC and LIVE already exist; TUTORIAL and INSTALLATION PROGRAM are the remaining deliverables.

## What Already Exists

- `dist/minifw-usb-hospital-standalone-v2.2.0/static/index.html` — static HTML demo page ✓
- `dist/minifw-usb-hospital-standalone-v2.2.0/` — full standalone Python demo kit ✓
- `dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md` — setup/run guide (to be absorbed)
- `dist/minifw-usb-hospital-standalone-v2.2.0/README.txt` — basic quick-start (to be replaced)
- `install.sh` at repo root — one-line production installer ✓

## What Needs to Be Built

### Deliverable 1: GUIDE.md (Tutorial)

**File:** `dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md`

A single comprehensive Markdown document that replaces `README.txt` and `INSTALL.md`. Covers the full user journey from zero to operating the dashboard.

#### Sections

1. **Overview**
   - What MiniFW-AI Hospital is: an AI-powered behavioral firewall for healthcare gateway hardware
   - What it protects against: ransomware C2 callbacks, HIPAA data exfiltration, IoMT anomaly traffic
   - Who uses it: IT/security admins, CIOs evaluating the product
   - This demo kit runs entirely offline with no root or Docker required

2. **Prerequisites**
   - Python 3.10+ (`python3 --version`)
   - Port 8000 free (`ss -tlnp | grep 8000`)
   - No Docker, no root, works on Linux/macOS/WSL2

3. **Quick Start**
   - `bash run_demo.sh` → open `http://localhost:8000` → login `admin / Hospital1!`
   - Expected terminal output (so user knows it worked)
   - Absorbs README.txt entirely

4. **Dashboard Walkthrough**
   - Live event feed: columns (timestamp, domain, score, decision, reason)
   - Threat score breakdown: how the 0–100 score is composed (DNS feed +40, TLS SNI +35, ASN +15, burst +10, MLP 0–30, YARA 0–35)
   - AI Threat Synthesis Panel: what it shows, how to read HIPAA detections
   - Protection state indicator: BASELINE_PROTECTION vs AI_ENHANCED_PROTECTION
   - Decision values: ALLOW / MONITOR / BLOCK — what each means operationally

5. **Threat Scenarios**
   - The 3 attack patterns cycling in `demo_data/attack_traffic.json`:
     - Ransomware C2: domain matches deny list, score → 100, hard block
     - Suspicious API leak: TLS SNI anomaly, elevated score, monitor/block depending on threshold
     - Data exfiltration: DNS burst pattern, BurstTracker fires, score escalates
   - What each looks like in the event feed
   - Which detection layer fires for each scenario

6. **Configuration**
   - `config/modes/minifw_hospital/policy.json` — block/monitor/alert thresholds per segment
   - `demo_data/normal_traffic.json` and `attack_traffic.json` — how to edit synthetic traffic
   - `MINIFW_SECRET_KEY` — already set automatically by `run_demo.sh`; only matters for production

7. **Admin Reference**
   - Log location: `logs/audit.jsonl`
   - SQLite DB: `minifw.db` — reset with `rm -f minifw.db` then re-run
   - State file: `logs/deployment_state.json` — cleared by `fast_reset.sh`
   - Stop the demo: `Ctrl+C`

8. **Troubleshooting**
   - Port 8000 in use
   - Python version too old
   - ModuleNotFoundError
   - No events appearing
   - Database error on first run
   - Absorbs INSTALL.md troubleshooting section

9. **Production Deployment (reference)**
   - Brief: this kit is for demos; for production use the `.deb` + one-liner
   - `curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash`
   - Links to `install.sh` at repo root

---

### Deliverable 2: build_deb.sh (Installation Program — .deb builder)

**File:** `build_deb.sh` at repo root (already documented in CLAUDE.md but not yet implemented)

A shell script invoked as `bash build_deb.sh <sector>`. Produces:
- `minifw-ai_<version>-<sector>_amd64.deb`
- `minifw-ai_<version>-<sector>_amd64.deb.sha256`

#### Script Flow

1. **Validate args** — require exactly one sector arg; validate against the 6 valid sectors (`hospital education government finance legal establishment`); print usage and exit 1 on failure
2. **Resolve version** — read from `VERSION` file at repo root if it exists; otherwise extract from `git describe --tags --abbrev=0` and strip leading `v`; export as `VERSION`
3. **Staging directory** — `mktemp -d` for build workspace; set up `PKGROOT=$TMPDIR/minifw-ai_${VERSION}-${SECTOR}_amd64`
4. **DEBIAN/ control files** — create:
   - `DEBIAN/control` — Package, Version, Architecture, Maintainer, Depends (python3, python3-pip, nftables, ipset), Description
   - `DEBIAN/postinst` — runs `python3 /opt/minifw_ai/init_db.py`, then `systemctl enable --now minifw-ai-engine minifw-ai-web`; exits 0 on failure with a warning (daemon may need manual config)
   - `DEBIAN/conffiles` — lists `/etc/minifw/minifw.env` as a config file preserved on upgrade
5. **Install tree** — copy:
   - `app/` → `$PKGROOT/opt/minifw_ai/app/`
   - `config/modes/minifw_<sector>/` → `$PKGROOT/opt/minifw_ai/config/`
   - `requirements.txt` → `$PKGROOT/opt/minifw_ai/`
   - `packaging/lib/systemd/system/minifw-ai-engine.service` + `minifw-ai-web.service` → `$PKGROOT/lib/systemd/system/`
   - `packaging/etc/minifw/minifw.env.example` → `$PKGROOT/etc/minifw/minifw.env` (if not already present)
6. **Permissions** — `chmod 755 DEBIAN/postinst`, `chmod -R 644 opt/`, `chmod 600 etc/minifw/minifw.env`
7. **Build** — `dpkg-deb --build --root-owner-group $PKGROOT .` → outputs `minifw-ai_${VERSION}-${SECTOR}_amd64.deb` in current directory
8. **Checksum** — `sha256sum minifw-ai_${VERSION}-${SECTOR}_amd64.deb > minifw-ai_${VERSION}-${SECTOR}_amd64.deb.sha256`
9. **Print summary** — package path, size, sha256 value

#### Notes
- Requires `dpkg-deb` (install via `apt install dpkg-dev`)
- Does not require root to build; root only needed at install time
- The `packaging/` directory structure (systemd units, env template) needs to be created alongside this script
- Sector lock is baked in via `policy.json` selection; `MINIFW_SECTOR` env var is set in the systemd unit `Environment=` directive

## Implementation Order

1. Write `GUIDE.md` in the hospital demo package
2. Remove/deprecate `README.txt` (replace content with "See GUIDE.md")
3. Remove/deprecate `INSTALL.md` (replace content with "See GUIDE.md")
4. Create `packaging/` directory structure (systemd units, env template)
5. Write `build_deb.sh` at repo root
6. Test: `bash build_deb.sh hospital` produces a valid `.deb`

## Files to Create/Modify

| File | Action |
|------|--------|
| `dist/minifw-usb-hospital-standalone-v2.2.0/GUIDE.md` | CREATE |
| `dist/minifw-usb-hospital-standalone-v2.2.0/README.txt` | MODIFY (stub → points to GUIDE.md) |
| `dist/minifw-usb-hospital-standalone-v2.2.0/INSTALL.md` | MODIFY (stub → points to GUIDE.md) |
| `build_deb.sh` | CREATE |
| `packaging/lib/systemd/system/minifw-ai-engine.service` | CREATE |
| `packaging/lib/systemd/system/minifw-ai-web.service` | CREATE |
| `packaging/etc/minifw/minifw.env.example` | CREATE |
| `packaging/DEBIAN/postinst.template` | CREATE |
