# Demo Package Structure & Credibility Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the hospital standalone package, delete archived packages, strip runtime artifacts, and create `dist/DEMO_PACKAGE_STRUCTURE.md` — all in one coherent commit.

**Architecture:** Git-aware single commit. The standalone's 4 tracked files are moved via `git mv` (preserving history); the archived packages are untracked so `rm -rf` suffices; runtime artifacts inside the standalone are untracked and removed with `find`/`rm`. Two docs files (`INDEX.md`, `DEMO_PACKAGE_STRUCTURE.md`) are edited/created and staged normally.

**Tech Stack:** bash, git

---

### Task 1: Rename the standalone package

**Files:**
- Rename: `dist/minifw-ai-usb-v2.2.0v3/` → `dist/minifw-usb-hospital-standalone-v2.2.0/`

- [ ] **Step 1: Rename the directory via git mv**

```bash
cd /home/sydeco/minifw-ai
git mv dist/minifw-ai-usb-v2.2.0v3 dist/minifw-usb-hospital-standalone-v2.2.0
```

Expected: no output, exit 0.

- [ ] **Step 2: Verify the rename staged correctly**

```bash
git status dist/
```

Expected output includes four `renamed:` lines:
```
renamed: dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh -> dist/minifw-usb-hospital-standalone-v2.2.0/HEALTHCHECK.sh
renamed: dist/minifw-ai-usb-v2.2.0v3/RECOVERY.md -> dist/minifw-usb-hospital-standalone-v2.2.0/RECOVERY.md
renamed: dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh -> dist/minifw-usb-hospital-standalone-v2.2.0/recover_demo.sh
renamed: dist/minifw-ai-usb-v2.2.0v3/run_demo.sh -> dist/minifw-usb-hospital-standalone-v2.2.0/run_demo.sh
```

- [ ] **Step 3: Remove __pycache__ directories from the renamed standalone**

```bash
find dist/minifw-usb-hospital-standalone-v2.2.0 -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; echo "done"
```

Expected: `done`

- [ ] **Step 4: Remove runtime-generated files from the standalone**

```bash
rm -f dist/minifw-usb-hospital-standalone-v2.2.0/minifw.db
rm -f dist/minifw-usb-hospital-standalone-v2.2.0/logs/audit.jsonl
rm -f dist/minifw-usb-hospital-standalone-v2.2.0/logs/engine.log
```

Expected: no output, exit 0.

- [ ] **Step 5: Verify venv is still present and logs dir is now empty**

```bash
ls dist/minifw-usb-hospital-standalone-v2.2.0/venv/bin/python
ls dist/minifw-usb-hospital-standalone-v2.2.0/logs/
```

Expected: first line prints the python symlink path; second line prints nothing (empty dir).

---

### Task 2: Delete archived packages

**Files:**
- Delete (untracked): `dist/minifw-usb-hospital-v2.2.0v1/`
- Delete (untracked): `dist/minifw-usb-hospital-v2.2.0v2/`
- Delete (untracked): `dist/minifw-ai-demo-v2.2.0/`
- Delete (untracked): `dist/minifw-ai-demo-v2.2.0.zip`

- [ ] **Step 1: Delete the archived packages**

```bash
rm -rf dist/minifw-usb-hospital-v2.2.0v1
rm -rf dist/minifw-usb-hospital-v2.2.0v2
rm -rf dist/minifw-ai-demo-v2.2.0
rm -f  dist/minifw-ai-demo-v2.2.0.zip
```

Expected: no output, exit 0.

- [ ] **Step 2: Verify they are gone**

```bash
ls dist/ | sort
```

Expected output (only these entries remain):
```
DEMO_PACKAGE_STRUCTURE.md   ← will exist after Task 4
INDEX.md
minifw-usb-education-v2.2.0
minifw-usb-gambling-v2.2.0
minifw-usb-hospital-standalone-v2.2.0
minifw-usb-hospital-v2.2.0
```

(DEMO_PACKAGE_STRUCTURE.md absent until Task 4 — that's fine at this step.)

---

### Task 3: Update `dist/INDEX.md`

**Files:**
- Modify: `dist/INDEX.md`

- [ ] **Step 1: Read the current file**

Read `dist/INDEX.md` to confirm current content before editing.

- [ ] **Step 2: Replace the full file with the updated content**

Write `dist/INDEX.md` with this content:

```markdown
# MiniFW-AI — Distribution Packages Index

> Last updated: 2026-05-13

---

## Current Packages — v2.2.0

### Hospital Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-hospital-v2.2.0/` | Docker USB Kit | https://localhost:8443 | Requires Docker. For technical buyers. |
| `minifw-usb-hospital-standalone-v2.2.0/` | Standalone (Python) | http://localhost:8000 | No Docker. Best for executive demos. |

**Credentials:** `admin / Hospital1!`  
**Quick start:** `bash demo.sh` (Docker kit) or `bash run_demo.sh` (standalone)

---

### Education Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-education-v2.2.0/` | Docker USB Kit | https://localhost:8447 | Requires Docker. SafeSearch + content policy demo. |

**Credentials:** `admin / Education1!`  
**Quick start:** `bash demo.sh`

---

### Gambling Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-gambling-v2.2.0/` | Docker USB Kit | https://localhost:8446 | Requires Docker. AML + geo-blocking demo. |

**Credentials:** `admin / Gambling1!`  
**Quick start:** `bash demo.sh`

---

## Legacy / Archived

Older packages have been removed. See git history for `dist/minifw-ai-usb-v2.2.0v3` (now `minifw-usb-hospital-standalone-v2.2.0`) and `dist/minifw-usb-hospital-v2.2.0v1/v2` if needed.

---

## Port Allocation

| Sector | Port | Package |
|--------|------|---------|
| Hospital (Docker) | 8443 | minifw-usb-hospital-v2.2.0 |
| Hospital (Standalone) | 8000 | minifw-usb-hospital-standalone-v2.2.0 |
| Education (Docker) | 8447 | minifw-usb-education-v2.2.0 |
| Gambling (Docker) | 8446 | minifw-usb-gambling-v2.2.0 |

---

## Build Commands

```bash
# Rebuild a USB kit from source
bash build_usb.sh hospital      # → dist/minifw-usb-hospital-v2.2.0/
bash build_usb.sh education     # → dist/minifw-usb-education-v2.2.0/
bash build_usb.sh gambling      # → dist/minifw-usb-gambling-v2.2.0/

# Build .deb installer
bash build_deb.sh hospital
bash build_deb.sh education
```

See `build_usb.sh` and `scripts/build_deb.sh` for full options.
```

- [ ] **Step 3: Verify the file was written**

```bash
grep "minifw-usb-hospital-standalone-v2.2.0" dist/INDEX.md
grep "minifw-usb-gambling-v2.2.0" dist/INDEX.md
grep "minifw-usb-hospital-v2.2.0v2" dist/INDEX.md
```

Expected: first two lines return matches; third returns nothing (v2 reference removed).

---

### Task 4: Create `dist/DEMO_PACKAGE_STRUCTURE.md`

**Files:**
- Create: `dist/DEMO_PACKAGE_STRUCTURE.md`

- [ ] **Step 1: Write the file**

Write `dist/DEMO_PACKAGE_STRUCTURE.md` with this content:

```markdown
# MiniFW-AI — Demo Package Structure

> Version: v2.2.0 | GPG key: BDB471E1FB46F58A

This document describes the layout and purpose of each demo package in `dist/`. Use it to orient a new reviewer, prepare a USB handoff, or verify a package is complete before a demo.

---

## Current Packages

| Package | Sector | Type | Port | Credentials | Entry Point |
|---------|--------|------|------|-------------|-------------|
| `minifw-usb-hospital-standalone-v2.2.0/` | Hospital | Standalone (Python, no Docker) | 8000 | `admin / Hospital1!` | `bash run_demo.sh` |
| `minifw-usb-hospital-v2.2.0/` | Hospital | Docker USB Kit | 8443 (HTTPS) | `admin / Hospital1!` | `bash demo.sh` |
| `minifw-usb-education-v2.2.0/` | Education | Docker USB Kit | 8447 (HTTPS) | `admin / Education1!` | `bash demo.sh` |
| `minifw-usb-gambling-v2.2.0/` | Gambling | Docker USB Kit | 8446 (HTTPS) | `admin / Gambling1!` | `bash demo.sh` |

---

## Folder Anatomy

### Docker USB Kit (e.g. `minifw-usb-hospital-v2.2.0/`)

```
minifw-usb-hospital-v2.2.0/
├── demo.sh                          # Entry point — starts containers, polls readiness, opens browser
├── recover_demo.sh                  # Recovery — tears down, restarts, re-runs HEALTHCHECK
├── HEALTHCHECK.sh                   # 11-point verification script (pre-flight and live modes)
├── setup_tls.sh                     # Generates local CA + signs localhost cert; installs in OS trust store
├── RECOVERY.md                      # Manual recovery steps and pre-demo checklist
├── docker/
│   ├── docker-compose.usb-hospital.yml   # Compose file — engine + web + injector services
│   ├── entrypoint-engine.sh              # Engine container startup
│   ├── entrypoint-web.sh                 # Web container startup
│   ├── certs/                            # TLS certs (generated by setup_tls.sh; .gitkeep ships)
│   └── demo-injector/                    # Synthetic traffic injector container
│       ├── Dockerfile
│       └── inject.py
├── config/
│   ├── feeds/                       # Threat intelligence feeds (deny_domains, deny_ips, etc.)
│   └── modes/minifw_hospital/       # Sector policy (policy.json, thresholds)
├── images/
│   └── minifw-hospital.tar          # Pre-built Docker image (load once, runs offline)
└── yara_rules/
    └── hospital_rules.yar           # Sector-specific YARA detection rules
```

### Standalone Kit (`minifw-usb-hospital-standalone-v2.2.0/`)

```
minifw-usb-hospital-standalone-v2.2.0/
├── run_demo.sh                      # Entry point — activates venv, starts engine + web, opens browser
├── recover_demo.sh                  # Recovery — kills stale processes, resets DB, relaunches
├── HEALTHCHECK.sh                   # 11-point verification script (pre-flight and live modes)
├── RECOVERY.md                      # Manual recovery steps and pre-demo checklist
├── INSTALL.md                       # First-time setup instructions
├── app/                             # Full application source (engine daemon + web admin)
├── config/                          # Threat feeds and sector policy
├── demo_data/                       # Synthetic traffic patterns for DEMO_MODE simulator
│   ├── normal_traffic.json
│   └── attack_traffic.json
├── models/
│   └── mlp_model.pkl                # Pre-trained MLP classifier
├── venv/                            # Pre-built Python virtualenv (offline-ready, no pip install needed)
├── yara_rules/                      # YARA detection rules
├── requirements.txt                 # Pinned dependencies (for venv rebuild if needed)
└── logs/                            # Runtime-generated (empty on clean package; created by demo)
```

---

## What Is and Is Not Shipped

| Item | Shipped? | Reason |
|------|----------|--------|
| `venv/` | Yes | Enables offline demos — no pip install required |
| `images/*.tar` | Yes | Docker kits run without internet on first load |
| `__pycache__/` | No | Runtime-generated; rebuilt automatically |
| `logs/` contents | No | Runtime-generated; created fresh each demo run |
| `minifw.db` | No | Runtime-generated SQLite; created fresh on first start |

---

## Reproducibility — Pre-flight Verification

Run before any demo to confirm the package is complete and functional:

```bash
# Any package — pre-flight mode (no demo running required)
bash HEALTHCHECK.sh

# Expected: 11/11 PASS, exit 0
```

A non-zero exit or any FAIL line means the package is incomplete. Common fixes: re-run `setup_tls.sh` (Docker kits) or check `venv/` integrity (standalone).

---

## Build Provenance

| Item | Value |
|------|-------|
| Version tag | `v2.2.0` |
| GPG signing key | `BDB471E1FB46F58A` |
| Rebuild from source | `bash build_usb.sh <sector>` |
| Release verification | `docs/release-verification.md` |

To verify a package was built from the signed release:

```bash
git verify-tag v2.2.0
```
```

- [ ] **Step 2: Verify the file was created**

```bash
grep "minifw-usb-hospital-standalone-v2.2.0" dist/DEMO_PACKAGE_STRUCTURE.md
grep "BDB471E1FB46F58A" dist/DEMO_PACKAGE_STRUCTURE.md
```

Expected: both lines return matches.

---

### Task 5: Stage and commit

- [ ] **Step 1: Stage all changes**

```bash
git add dist/INDEX.md dist/DEMO_PACKAGE_STRUCTURE.md
```

(The `git mv` renames from Task 1 are already staged. The deleted untracked packages need no staging.)

- [ ] **Step 2: Verify staging**

```bash
git status dist/
```

Expected: four `renamed:` lines for the standalone scripts/docs, plus `new file: dist/DEMO_PACKAGE_STRUCTURE.md` and `modified: dist/INDEX.md`. No unexpected additions.

- [ ] **Step 3: Commit**

```bash
git commit -m "$(cat <<'EOF'
chore(dist): rename standalone package, remove archived packages, add DEMO_PACKAGE_STRUCTURE.md

- Rename minifw-ai-usb-v2.2.0v3 → minifw-usb-hospital-standalone-v2.2.0
- Delete archived packages: hospital-v1, hospital-v2, minifw-ai-demo-v2.2.0 + zip
- Remove __pycache__, logs, minifw.db from standalone (venv kept for offline use)
- Add minifw-usb-gambling-v2.2.0 to INDEX.md as current package
- Create dist/DEMO_PACKAGE_STRUCTURE.md with package overview, folder anatomy,
  reproducibility steps, and build provenance

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Verify commit**

```bash
git log --oneline -1
git show --stat HEAD
```

Expected: commit message starts with `chore(dist):`, stat shows the renamed files, INDEX.md modified, DEMO_PACKAGE_STRUCTURE.md added.
