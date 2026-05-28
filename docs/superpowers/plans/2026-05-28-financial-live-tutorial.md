# MINIFW Financial — LIVE Restore + Tutorial Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete MINIFW-AI Financial by (1) restoring the LIVE demo package files that were deleted by git cleanup commit `c2eeba12`, and (2) adding a full-product `GUIDE.md` tutorial.

**Architecture:** All files were previously implemented and committed — they were deleted when a git cleanup operation removed `dist/` contents. Restoration is mechanical: `git show c2eeba12^:<path>` for each file. The GUIDE.md follows the same 9-section structure as the hospital guide, adapted for PCI-DSS / ArborCrest Capital / HTTPS port 8443.

**Tech Stack:** Bash (run_demo.sh, setup_tls.sh, fast_reset.sh), Python 3 (scheduler), Markdown (GUIDE.md)

---

## File Map

| File | Action | Source |
|------|--------|--------|
| `dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/requirements.txt` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/INSTALL.md` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/README.md` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/PRESENTER_CARD.md` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/DEMO_SCRIPT.md` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/RECOVERY.md` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/config/policy.json` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/config/feeds/*.txt` | RESTORE from git | `c2eeba12^` (10 feed files) |
| `dist/minifw-usb-financial-standalone-v2.2.0/demo_data/normal_traffic.json` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/demo_data/attack_traffic.json` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/models/mlp_model.pkl` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/scheduler/__init__.py` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/yara_rules/sme_rules.yar` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/yara_rules/test_rules.yar` | RESTORE from git | `c2eeba12^` |
| `dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md` | CREATE new | New content |
| `dist/minifw-usb-financial-standalone-v2.2.0/README.txt` | MODIFY | Stub → GUIDE.md |

---

## Task 1: Restore LIVE demo files from git history

**Context:** Commit `c2eeba12` deleted all these files as part of a `.gitignore` cleanup. The parent commit `c2eeba12^` (which resolves to commit `6784eac6`) has the last complete state. Use `git show <SHA>:<path>` to restore each file. All paths below are relative to repo root `/home/sydeco/minifw-ai`.

- [ ] **Step 1: Restore shell scripts**

```bash
cd /home/sydeco/minifw-ai
PARENT="c2eeba12^"
PKG="dist/minifw-usb-financial-standalone-v2.2.0"

for f in run_demo.sh fast_reset.sh setup_tls.sh teardown_demo.sh HEALTHCHECK.sh recover_demo.sh; do
    git show "${PARENT}:${PKG}/${f}" > "${PKG}/${f}"
    chmod +x "${PKG}/${f}"
    echo "Restored: ${f}"
done
```

Expected: 6 lines each saying `Restored: <filename>`

- [ ] **Step 2: Restore text/config files**

```bash
PKG="dist/minifw-usb-financial-standalone-v2.2.0"
PARENT="c2eeba12^"

for f in requirements.txt INSTALL.md README.md PRESENTER_CARD.md DEMO_SCRIPT.md RECOVERY.md; do
    git show "${PARENT}:${PKG}/${f}" > "${PKG}/${f}"
    echo "Restored: ${f}"
done
```

Expected: 6 lines each saying `Restored: <filename>`

- [ ] **Step 3: Restore config/ directory**

```bash
PKG="dist/minifw-usb-financial-standalone-v2.2.0"
PARENT="c2eeba12^"

mkdir -p "${PKG}/config/feeds"
git show "${PARENT}:${PKG}/config/policy.json" > "${PKG}/config/policy.json"
echo "Restored: config/policy.json"

for feed in allow_domains.txt apt_indicators.txt asn_prefixes.txt crypto_scams.txt \
            deny_asn.txt deny_domains.txt deny_ips.txt financial_fraud.txt \
            gambling_domains.txt government_sensitive.txt healthcare_threats.txt \
            legal_threats.txt school_blacklist.txt tor_exit_nodes.txt; do
    if git cat-file -e "${PARENT}:${PKG}/config/feeds/${feed}" 2>/dev/null; then
        git show "${PARENT}:${PKG}/config/feeds/${feed}" > "${PKG}/config/feeds/${feed}"
        echo "Restored: config/feeds/${feed}"
    fi
done
```

Expected: policy.json + all feed files printed as restored

- [ ] **Step 4: Restore demo_data/**

```bash
PKG="dist/minifw-usb-financial-standalone-v2.2.0"
PARENT="c2eeba12^"

mkdir -p "${PKG}/demo_data"
git show "${PARENT}:${PKG}/demo_data/normal_traffic.json" > "${PKG}/demo_data/normal_traffic.json"
git show "${PARENT}:${PKG}/demo_data/attack_traffic.json" > "${PKG}/demo_data/attack_traffic.json"
echo "Restored: demo_data/normal_traffic.json"
echo "Restored: demo_data/attack_traffic.json"
```

Expected: 2 lines saying Restored

- [ ] **Step 5: Restore models/ and scheduler/__init__.py and yara_rules extras**

```bash
PKG="dist/minifw-usb-financial-standalone-v2.2.0"
PARENT="c2eeba12^"

mkdir -p "${PKG}/models"
git show "${PARENT}:${PKG}/models/mlp_model.pkl" > "${PKG}/models/mlp_model.pkl"
echo "Restored: models/mlp_model.pkl ($(wc -c < "${PKG}/models/mlp_model.pkl") bytes)"

git show "${PARENT}:${PKG}/scheduler/__init__.py" > "${PKG}/scheduler/__init__.py"
echo "Restored: scheduler/__init__.py"

for yar in sme_rules.yar test_rules.yar; do
    if git cat-file -e "${PARENT}:${PKG}/yara_rules/${yar}" 2>/dev/null; then
        git show "${PARENT}:${PKG}/yara_rules/${yar}" > "${PKG}/yara_rules/${yar}"
        echo "Restored: yara_rules/${yar}"
    fi
done
```

Expected: mlp_model.pkl ~96000 bytes, scheduler/__init__.py and yara files confirmed

- [ ] **Step 6: Verify structure matches spec**

```bash
PKG="dist/minifw-usb-financial-standalone-v2.2.0"
for f in run_demo.sh fast_reset.sh setup_tls.sh requirements.txt \
          config/policy.json config/feeds/deny_domains.txt config/feeds/financial_fraud.txt \
          demo_data/normal_traffic.json demo_data/attack_traffic.json \
          models/mlp_model.pkl scheduler/demo_scheduler.py certs/server.crt; do
    [[ -f "${PKG}/${f}" ]] && echo "OK: ${f}" || echo "MISSING: ${f}"
done
```

Expected: all lines start with `OK:`

- [ ] **Step 7: Commit restored files**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/fast_reset.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/requirements.txt \
           dist/minifw-usb-financial-standalone-v2.2.0/INSTALL.md \
           dist/minifw-usb-financial-standalone-v2.2.0/README.md \
           dist/minifw-usb-financial-standalone-v2.2.0/PRESENTER_CARD.md \
           dist/minifw-usb-financial-standalone-v2.2.0/DEMO_SCRIPT.md \
           dist/minifw-usb-financial-standalone-v2.2.0/RECOVERY.md \
           dist/minifw-usb-financial-standalone-v2.2.0/config/ \
           dist/minifw-usb-financial-standalone-v2.2.0/demo_data/ \
           dist/minifw-usb-financial-standalone-v2.2.0/models/ \
           dist/minifw-usb-financial-standalone-v2.2.0/scheduler/__init__.py \
           dist/minifw-usb-financial-standalone-v2.2.0/yara_rules/
git commit -m "restore(financial): recover LIVE demo files deleted by gitignore cleanup"
```

---

## Task 2: Create GUIDE.md (Tutorial)

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md`

Read `dist/minifw-usb-financial-standalone-v2.2.0/config/policy.json` and `dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh` before writing to ensure accuracy.

- [ ] **Step 1: Create GUIDE.md with these exact 9 sections**

```markdown
# MiniFW-AI Financial — User Guide

**Version:** 2.2.0 | **Sector:** Finance | **Scenario:** ArborCrest Capital

---

## Overview

MiniFW-AI Financial is an AI-powered behavioral firewall for wealth management and trading floor gateway hardware. It enforces PCI-DSS compliance and protects against:

- **Banking trojan C2 callbacks** — TrickBot, Emotet, and financial-sector RAT beacons blocked at DNS resolution
- **Card data exfiltration** — PCI-DSS boundary violations from trading-floor workstations to external endpoints
- **Tor/anonymizer traffic** — anonymizer exit nodes blocked on all financial subnets
- **ERP subnet pivoting** — lateral movement from trading floor (10.50.0.0/24) into Oracle/SAP ERP zone (192.168.1.0/24)

This demo uses the **ArborCrest Capital** scenario: a $4B wealth management firm with a trading floor and Oracle ERP/finance operations. The full attack chain runs automatically — no interaction required.

**Access:** HTTPS on port 8443. TLS certificate is issued by a local demo CA (installed by `setup_tls.sh`).

---

## Prerequisites

| Requirement | Check Command | Minimum |
|-------------|---------------|---------|
| Python 3 | `python3 --version` | 3.10+ |
| openssl | `openssl version` | any |
| libnss3-tools | `certutil -V` | any (for Firefox trust) |
| Port 8443 free | `ss -tlnp \| grep 8443` | — |
| sudo access | `sudo -v` | needed once for TLS setup |

Works on Linux and macOS. Windows: use WSL2.

---

## Quick Start

**One-time TLS setup (first demo only):**
```bash
bash setup_tls.sh
```
This generates a local demo CA and installs it to system trust stores. Requires sudo. Safe to skip on subsequent demos if certs already exist.

**Launch the demo:**
```bash
bash run_demo.sh
```

Browser opens automatically to **https://localhost:8443**. Login: `admin` / `Finance1!`

**Expected terminal output:**
```
[minifw] Starting Financial Demo...
[minifw] Engine started (PID XXXXX)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
```

The demo starts with ~90 seconds of normal trading floor traffic, then the attack sequence fires automatically.

---

## Dashboard Walkthrough

### Event Feed

| Column | Meaning |
|--------|---------|
| **Time** | Timestamp of the DNS query |
| **Domain** | Queried hostname |
| **Client IP** | Source workstation or device |
| **Score** | Threat score 0–100 |
| **Decision** | ALLOW / MONITOR / BLOCK |
| **Reason** | Primary detection layer |
| **Segment** | Network zone (trading, internal, guest, dmz) |

**Score composition** (configurable in `config/policy.json`):

| Layer | Max contribution |
|-------|-----------------|
| DNS feed match (deny list) | +40 |
| TLS/SNI anomaly | +35 |
| ASN block list | +15 |
| DNS burst / qpm spike | +10 |
| MLP classifier | 0–30 |
| YARA payload match | 0–35 |

### Decision Thresholds (ArborCrest segments)

| Segment | MONITOR at | BLOCK at | Subnets |
|---------|-----------|---------|---------|
| trading | 45 | 80 | 10.50.0.0/24 |
| internal | 45 | 80 | 192.168.1.0/24, 10.0.0.0/8 |
| guest | 35 | 65 | 192.168.100.0/24 |
| dmz | 50 | 75 | 10.10.0.0/24 |
| default | 55 | 85 | (catch-all) |

### AI Threat Synthesis Panel

Shows:
- **Protection state:** `BASELINE_PROTECTION` → `AI_ENHANCED_PROTECTION` as telemetry builds
- **PCI-DSS compliance indicators:** detection category mapped to PCI-DSS requirement (e.g., Req 1.3 — inbound/outbound traffic control)
- **Top threat actors:** most-blocked domains/IPs in session
- **Active segments under threat**

---

## Threat Scenarios

The demo uses a 5-step attack chain. `scheduler/demo_scheduler.py` injects events directly into `logs/events.jsonl`, bypassing the need for real network traffic.

### Timeline

| Phase | Duration | Traffic |
|-------|----------|---------|
| T+0 → T+90s | Normal | Bloomberg, Reuters, SWIFT, Refinitiv, NASDAQ, Oracle ERP, SAP |
| T+90s → T+120s | Attack | 5-step sequence targeting 10.50.0.1 |
| T+120s+ | Post-block | Normal trading traffic resumes |

### Attack Chain

**Step 1 — Tor exit node (Score: 55, MONITOR)**
- Domain: `tor-exit-4f2a.net`
- Reason: `anonymizer_traffic`, `trading_floor_anomaly`
- Narrative: A trading-floor workstation queries a Tor exit node — not trading software. Anomaly flagged.

**Step 2 — Banking trojan C2 (Score: 72, MONITOR)**
- Domain: `c2.trickbot-gate.com`
- Reason: `dns_feed_match`, `banking_trojan_c2`, `financial_fraud_feed`
- Narrative: TrickBot beacon matches the financial fraud feed. Score crosses MONITOR threshold.

**Step 3 — ERP subnet pivot (Score: 82, MONITOR)**
- Domain: `exfil.payment-collect.io`
- Reason: `card_exfil_pattern`, `oracle_erp_subnet_pivot`, `pci_dss_boundary_crossed`
- Narrative: Same workstation pivots toward Oracle ERP subnet — PCI-DSS boundary violation in progress.

**Step 4 — Active exfiltration (Score: 89, MONITOR)**
- Domain: `exfil.payment-collect.io` (repeated)
- Reason: `card_exfil_pattern`, `client_portfolio_exfil`, `pci_dss_violation`
- Narrative: Client portfolio data actively being staged for exfil. Score approaching block threshold.

**Step 5 — BLOCK (Score: 95, BLOCK)**
- Domain: `exfil.payment-collect.io` (final)
- Reason: `dns_feed_match`, `card_exfil_pattern`, `pci_dss_violation`, `erp_subnet_block`
- Narrative: **Confirmed PCI-DSS violation. Behavioral chain complete. BLOCK fires on trading segment.**

---

## Configuration

### policy.json

`config/policy.json` controls PCI-DSS enforcement thresholds per network segment.

Key fields (excerpt — simplified for clarity):

```json
{
  "segments": {
    "trading": { "block_threshold": 80, "monitor_threshold": 45 },
    "guest":   { "block_threshold": 65, "monitor_threshold": 35 }
  },
  "features": {
    "dns_weight": 40, "sni_weight": 35, "asn_weight": 15,
    "burst_weight": 10, "mlp_weight": 30, "yara_weight": 35
  }
}
```

Adjust `block_threshold` per segment for tighter or looser enforcement. Trading floor typically runs tightest (80); guest WiFi is more lenient (65).

### config/feeds/

Key financial threat feeds:

| File | Content |
|------|---------|
| `financial_fraud.txt` | Banking trojan C2, phishing domains, fraud infrastructure |
| `crypto_scams.txt` | Crypto fraud domains blocked on PCI-in-scope segments |
| `deny_domains.txt` | Global deny list |
| `tor_exit_nodes.txt` | Tor exit nodes (strict block on trading segment) |

### scheduler/demo_scheduler.py

Controls the attack timeline. Edit `NORMAL_TRAFFIC` to change domain names, or adjust `ATTACK_SEQUENCE` to modify scores and reasons. The scheduler writes directly to `logs/events.jsonl`.

---

## Admin Reference

| Item | Location |
|------|----------|
| Audit log (JSONL) | `logs/audit.jsonl` |
| Events log | `logs/events.jsonl` |
| Scheduler log | `logs/scheduler.log` |
| Web server log | `logs/web.log` |
| Engine log | `logs/engine.log` |
| SQLite database | `minifw.db` |
| TLS certs | `certs/` |
| Stop demo | `Ctrl+C` in terminal |
| Fast reset (≤45s) | `bash fast_reset.sh` |
| Full teardown | `bash teardown_demo.sh` |

**Reset the database** (clean slate):
```bash
rm -f minifw.db
bash run_demo.sh
```
Admin user is re-provisioned automatically on next launch.

**TLS certificate** (if certs expire or need regeneration):
```bash
bash setup_tls.sh
```

---

## Troubleshooting

**TLS cert not found error on startup:**
```bash
bash setup_tls.sh
bash run_demo.sh
```

**Port 8443 already in use:**
```bash
lsof -ti:8443 | xargs kill -9
bash run_demo.sh
```

**Browser shows certificate warning (not trusted):**
```bash
bash setup_tls.sh   # re-installs CA to trust store
```
For Firefox: may need to restart the browser after trust store update.

**Python version too old (`< 3.10`):**
```bash
python3 --version
sudo apt install python3.11
```

**`ModuleNotFoundError` on startup:**
```bash
source venv/bin/activate
pip install -r requirements.txt
bash run_demo.sh
```

**Dashboard starts but no attack events appear after 2 minutes:**
```bash
cat logs/scheduler.log
```
If empty or error shown, restart:
```bash
bash fast_reset.sh
```

**Dashboard did not start in 20s (run_demo.sh exits with error):**
```bash
cat logs/web.log | tail -20
```
Common cause: port 8443 held by a previous demo process. Use `lsof -ti:8443 | xargs kill -9` then rerun.

---

## Production Deployment

This kit is for offline executive demos only. For production deployment on gateway hardware:

**One-line installer** (Debian/Ubuntu, requires root):
```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

Prompts for sector selection, downloads sector-specific `.deb`, verifies GPG signature, installs, and starts services.

**Manual .deb install:**
```bash
sudo dpkg -i minifw-ai_2.2.0-finance_amd64.deb
sudo systemctl status minifw-ai minifw-ai-web
```

- Config: `/opt/minifw_ai/config/modes/minifw_financial/policy.json`
- Logs: `/opt/minifw_ai/logs/`
- Dashboard: **https://localhost:8443** (TLS, self-signed cert generated on install)
- Credentials: `/etc/minifw/minifw.env` (auto-generated on first install)
```

- [ ] **Step 2: Verify all 9 sections present**

```bash
for section in "Overview" "Prerequisites" "Quick Start" "Dashboard Walkthrough" \
               "Threat Scenarios" "Configuration" "Admin Reference" \
               "Troubleshooting" "Production Deployment"; do
    grep -q "## ${section}" dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md \
        && echo "OK: ${section}" || echo "MISSING: ${section}"
done
```

Expected: 9 lines all starting with `OK:`

- [ ] **Step 3: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md
git commit -m "docs(financial): add full product GUIDE.md — PCI-DSS, ArborCrest scenario, 5-step attack chain"
```

---

## Task 3: Stub README.txt

**Files:**
- Modify: `dist/minifw-usb-financial-standalone-v2.2.0/README.txt`

The existing `README.txt` (restored from git history) already has a quick-start format. Replace its content with a stub pointing to GUIDE.md for consistency.

- [ ] **Step 1: Replace README.txt**

```
MiniFW-AI Financial Sector Executive Demo v2.2.0
================================================

See GUIDE.md for the full user guide:
  setup, TLS, dashboard walkthrough, PCI-DSS threat scenarios,
  configuration, admin reference, and troubleshooting.

Quick start:
  bash setup_tls.sh   (first time only — requires sudo)
  bash run_demo.sh
  open https://localhost:8443
  login: admin / Finance1!
```

- [ ] **Step 2: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/README.txt
git commit -m "docs(financial): update README.txt stub to point to GUIDE.md"
```

---

## Task 4: Final verification

- [ ] **Step 1: Confirm all financial checklist items**

```bash
echo "=== STATIC ===" && \
    ls dist/minifw-usb-financial-standalone-v2.2.0/static/index.html && echo "OK"

echo "=== LIVE ===" && \
    ls dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh && \
    ls dist/minifw-usb-financial-standalone-v2.2.0/config/policy.json && \
    ls dist/minifw-usb-financial-standalone-v2.2.0/demo_data/normal_traffic.json && echo "OK"

echo "=== TUTORIAL ===" && \
    ls dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md && \
    wc -l dist/minifw-usb-financial-standalone-v2.2.0/GUIDE.md && echo "OK"

echo "=== INSTALL (one-liner) ===" && \
    ls install.sh && echo "OK"

echo "=== INSTALL (.deb builder) ===" && \
    bash build_deb.sh finance 2>&1 | head -4 | grep -q "finance" && echo "OK" || echo "FAIL"
```

Expected: all 5 checks print `OK`.

- [ ] **Step 2: Test suite**

```bash
PYTHONPATH=. pytest testing/ -m "not integration" -q 2>&1 | tail -3
```

Expected: 0 failed.
