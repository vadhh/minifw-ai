# MINIFW Schools — Tutorial Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete MINIFW-AI Schools by adding a full-product `GUIDE.md` and updating `README.txt` to a stub pointing to it.

**Architecture:** The education demo is Docker-based (not standalone Python like hospital/financial). The GUIDE.md follows the same 9-section structure as the other sector guides, adapted for Docker setup, port 8447, student/staff/guest/admin segments, and the looping injector attack pattern. LIVE and STATIC are already complete — only TUTORIAL and INSTALLATION PROGRAM remain, and build_deb.sh + install.sh already cover the `education` sector.

**Tech Stack:** Markdown (GUIDE.md), Docker Compose (demo runtime), bash (demo.sh, fast_reset.sh)

---

## File Map

| File | Action |
|------|--------|
| `dist/minifw-usb-education-v2.2.0/GUIDE.md` | CREATE |
| `dist/minifw-usb-education-v2.2.0/README.txt` | MODIFY (stub → GUIDE.md) |

---

## Task 1: Create GUIDE.md

**Files:**
- Create: `dist/minifw-usb-education-v2.2.0/GUIDE.md`

Before writing, read:
1. `dist/minifw-usb-education-v2.2.0/config/modes/minifw_school/policy.json` — for accurate thresholds and segment subnets
2. `dist/minifw-usb-education-v2.2.0/demo.sh` — for accurate startup output and credentials
3. `dist/minifw-usb-education-v2.2.0/docker/demo-injector-education/inject.py` — for accurate attack scenarios, domains, scores, decisions

- [ ] **Step 1: Create GUIDE.md with exactly these 9 sections**

Create `dist/minifw-usb-education-v2.2.0/GUIDE.md`:

```markdown
# MiniFW-AI Schools — User Guide

**Version:** 2.2.0 | **Sector:** Education | **Mode:** Docker Demo

---

## Overview

MiniFW-AI Schools is an AI-powered behavioral firewall for K-12 and university gateway hardware. It enforces school-appropriate internet policies and protects against:

- **VPN/proxy bypass attempts** — students trying to circumvent content filters via VPN clients and proxy services
- **Content filter evasion** — domains specifically designed to bypass school filtering infrastructure
- **Gambling and adult content** — bet365 and similar sites blocked on student and guest networks
- **Social media on restricted segments** — Instagram, TikTok and similar flagged on student networks
- **Burst/DDoS-style circumvention** — high-frequency DNS queries to a single bypass domain trigger burst detection

The demo loops continuously — events replay every ~33 seconds, so every dashboard visit shows live activity.

**Access:** HTTPS on port 8447. Accept the browser's self-signed certificate warning.

---

## Prerequisites

| Requirement | Check Command | Notes |
|-------------|---------------|-------|
| Docker Engine | `docker --version` | Docker Desktop on Windows/macOS |
| Docker Compose v2 | `docker compose version` | Must print v2.x, not v1 |
| Port 8447 free | `ss -tlnp \| grep 8447` | — |
| WSL2 (Windows only) | Docker Desktop settings | Required for Windows users |

**Windows:** Install Docker Desktop with WSL2 integration enabled.
**Linux:** `sudo systemctl start docker` if daemon is not running.
**macOS:** Open Docker Desktop before running `demo.sh`.

---

## Quick Start

```bash
bash demo.sh
```

**First run on a new machine** loads Docker images from `images/minifw-education.tar` (~2–3 minutes, one-time). Subsequent runs start immediately.

Open **https://localhost:8447** and login with `admin` / `Education1!`

Accept the self-signed certificate warning in your browser.

**Expected terminal output:**
```
[minifw-demo] education
─────────────────────────────────────────────────────
Dashboard : https://localhost:8447
Login     : admin / Education1!
Sector    : education

Ctrl+C to stop.
```

**Wait ~33 seconds** for the first injector loop to populate events in the dashboard. The injector starts after an 8-second warm-up delay and completes one full loop (6 scenario events + burst) before the 10-second inter-loop sleep.

**Stop the demo:**
```bash
Ctrl+C
```
The script prints the cleanup command. To force-stop manually:
```bash
docker compose -f docker/docker-compose.usb-education.yml down
```

---

## Dashboard Walkthrough

### Event Feed

| Column | Meaning |
|--------|---------|
| **Time** | Timestamp of the DNS query |
| **Domain** | Queried hostname |
| **Client IP** | Source device (student, staff, guest, or admin subnet) |
| **Score** | Threat score 0–100 |
| **Decision** | ALLOW / MONITOR / BLOCK |
| **Reason** | Primary detection layer that fired |
| **Segment** | Network zone the client IP maps to |

**Score composition** (configurable in `config/modes/minifw_school/policy.json`):

| Layer | Max contribution |
|-------|-----------------|
| DNS feed match (deny list) | +40 |
| TLS/SNI anomaly | +35 |
| ASN block list | +15 |
| IP deny list | +15 |
| DNS burst / qpm spike | +10 |
| MLP classifier | 0–30 |
| YARA payload match | 0–35 |

### Decision Thresholds (School sector)

| Segment | MONITOR at | BLOCK at | Subnets |
|---------|-----------|---------|---------|
| student | 35 | 70 | 10.10.0.0/16 |
| guest | 30 | 60 | 192.168.100.0/24 |
| staff | 50 | 80 | 192.168.1.0/24 |
| admin | 55 | 85 | 10.0.0.0/24 |
| default | 50 | 80 | (catch-all) |

Student and guest segments have the tightest thresholds — a score of 35 is enough to flag on the student network, and 60 is enough to block on guest.

### AI Threat Synthesis Panel

Shows:
- **Current protection state:** `BASELINE_PROTECTION` (hard gates only) or `AI_ENHANCED_PROTECTION` (adds MLP + YARA scoring)
- **Top threat actors:** most-blocked domains/IPs in the current demo session
- **Detection breakdown:** which scoring layers are firing most frequently

---

## Threat Scenarios

The demo injector (`docker/demo-injector-education/inject.py`) loops continuously. Each loop injects 7 events plus a burst sequence, repeating every ~33 seconds.

### Per-Loop Scenario Summary

| # | Domain | Client IP | Segment | Expected Decision | Why |
|---|--------|-----------|---------|------------------|-----|
| 1 | `khanacademy.org` | 10.10.0.10 | student | ALLOW | Legitimate study resource |
| 2 | `bbc.co.uk` | 10.10.0.11 | student | ALLOW | News/educational content |
| 3 | `wikipedia.org` | 10.10.0.12 | student | ALLOW | Reference research |
| 4 | `instagram.com` | 10.10.0.20 | student | MONITOR (score≈40) | Social media on student network |
| 5 | `nordvpn.com` | 10.10.0.50 | student | MONITOR | VPN service domain |
| 6 | `nordvpn-bypass.proxy.io` | 10.10.0.50 | student | **BLOCK** (score=75) | YARA VPN proxy match, exceeds student block threshold |
| 7 | `filter-bypass.student.io` | 192.168.100.10 | guest | **BLOCK** (score=75) | YARA content filter bypass, exceeds guest block threshold (60) |
| 8 | `bet365.com` | 10.10.0.100 | student | MONITOR (score≈40) | Gambling site on student network |
| Burst | `nordvpn-bypass.proxy.io` | 10.10.0.200 | student | **BLOCK cascade** | 200 rapid queries trigger burst detection, score escalates |

### Scenario Detail

**1–3 Normal traffic (ALLOW)**
Legitimate student study requests to Khan Academy, BBC, and Wikipedia. These demonstrate that the firewall is not over-blocking educational content.

**4 Social media (MONITOR)**
`instagram.com` from the student subnet (10.10.0.20). Score ~40 — crosses the student MONITOR threshold (35) but not BLOCK (70). The school has elected to log social media attempts rather than hard-block them.

**5–6 VPN bypass progression (MONITOR → BLOCK)**
First query: `nordvpn.com` — a VPN service domain. Score ~40, MONITOR only (student threshold 70 not reached). Second query: `nordvpn-bypass.proxy.io` — a domain matching the YARA VPN proxy rule (+35). Combined score 75 > student block threshold 70. **BLOCK fires.**

**7 Content filter bypass from guest (BLOCK)**
`filter-bypass.student.io` from a guest IP (192.168.100.10). YARA match pushes score to 75, which exceeds the guest block threshold of 60. **BLOCK fires.** Note: the same score would only MONITOR on the staff network (block threshold 80).

**8 Gambling site (MONITOR)**
`bet365.com` from student subnet. Score ~40 — above student MONITOR threshold (35) but below BLOCK (70). Flagged and logged.

**Burst sequence (BLOCK cascade)**
200 rapid queries to `nordvpn-bypass.proxy.io` from 10.10.0.200. The burst tracker fires within the first ~50 queries (+10 to score). Combined with YARA match (+35), score far exceeds block threshold. Multiple BLOCK entries appear rapidly in the event feed.

---

## Configuration

### policy.json

`config/modes/minifw_school/policy.json` controls thresholds and score weights.

Key fields (excerpt — simplified for clarity):

```json
{
  "segments": {
    "student": { "block_threshold": 70, "monitor_threshold": 35 },
    "guest":   { "block_threshold": 60, "monitor_threshold": 30 }
  },
  "features": {
    "dns_weight": 40, "sni_weight": 35, "asn_weight": 15,
    "burst_weight": 10, "mlp_weight": 30, "yara_weight": 35
  }
}
```

To make the demo more aggressive (block social media): lower `student.block_threshold` to 40. To relax monitoring: raise `student.monitor_threshold` to 50.

### config/feeds/

| File | Content |
|------|---------|
| `deny_domains.txt` | Known VPN services, proxy relays, content filter evasion domains |
| `tor_exit_nodes.txt` | Tor exit nodes (blocked on all segments) |
| `deny_ips.txt` | IP block list |

### Demo injector

`docker/demo-injector-education/inject.py` controls which domains are injected and their timing. Edit `NORMAL_TRAFFIC` patterns or add entries to simulate different scenarios. Rebuild the Docker image after editing:
```bash
docker compose -f docker/docker-compose.usb-education.yml build
bash demo.sh
```

---

## Admin Reference

| Item | Location / Command |
|------|--------------------|
| Stop demo | `Ctrl+C` in terminal |
| Force stop containers | `docker compose -f docker/docker-compose.usb-education.yml down` |
| Fast reset (restart containers) | `bash fast_reset.sh` |
| View engine logs | `docker compose -f docker/docker-compose.usb-education.yml logs minifw-engine` |
| View web logs | `docker compose -f docker/docker-compose.usb-education.yml logs minifw-web` |
| View injector output | `docker compose -f docker/docker-compose.usb-education.yml logs minifw-injector` |
| YARA rules | `yara_rules/education_rules.yar` |
| Feeds | `config/feeds/` |
| Pre-demo checklist | `PRE_DEMO_CHECKLIST.md` |
| Presenter talking points | `PRESENTER_CARD.md` |
| Full demo script | `DEMO_SCRIPT.md` |

---

## Troubleshooting

**Port 8447 already in use:**
```bash
docker compose -f docker/docker-compose.usb-education.yml down
bash demo.sh
```

**Docker not found:**
- Windows: Open Docker Desktop, ensure WSL integration is enabled, then re-open your terminal
- Linux: `sudo systemctl start docker`
- macOS: Open Docker Desktop from Applications

**`docker compose version` shows v1 (`docker-compose` not `docker compose`):**
Upgrade to Docker Engine 20.10+ which includes Compose v2 built-in. Or install the Compose v2 plugin:
```bash
sudo apt-get install docker-compose-plugin
```

**No events appearing after 33 seconds:**
```bash
docker compose -f docker/docker-compose.usb-education.yml logs minifw-injector
```
If injector is not running, restart the demo.

**Images failed to load (first run):**
```bash
docker load -i images/minifw-education.tar
bash demo.sh
```

**Browser shows certificate warning:**
This is expected — the demo uses a self-signed TLS certificate. Click "Advanced" → "Proceed to localhost" (Chrome) or "Accept the Risk and Continue" (Firefox).

**Dashboard loads but shows no data after 2 loops:**
The engine may not be receiving DNS events. Check:
```bash
docker compose -f docker/docker-compose.usb-education.yml logs minifw-engine | tail -20
```

---

## Production Deployment

This kit is for offline demos only. For production deployment on school gateway hardware:

**One-line installer** (Debian/Ubuntu, requires root):
```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

Select `education` when prompted for sector selection. The installer downloads the education `.deb`, verifies GPG signature, and starts both services.

**Manual .deb install:**
```bash
sudo dpkg -i minifw-ai_2.2.0-education_amd64.deb
sudo systemctl status minifw-ai minifw-ai-web
```

- Config: `/opt/minifw_ai/config/modes/minifw_school/policy.json`
- Logs: `/opt/minifw_ai/logs/`
- Dashboard: **https://localhost:8443** (TLS, self-signed cert generated on install)
- Credentials: `/etc/minifw/minifw.env` (auto-generated on first install)
```

- [ ] **Step 2: Verify all 9 sections present**

```bash
for section in "Overview" "Prerequisites" "Quick Start" "Dashboard Walkthrough" \
               "Threat Scenarios" "Configuration" "Admin Reference" \
               "Troubleshooting" "Production Deployment"; do
    grep -q "## ${section}" dist/minifw-usb-education-v2.2.0/GUIDE.md \
        && echo "OK: ${section}" || echo "MISSING: ${section}"
done
```

Expected: 9 lines all starting with `OK:`

- [ ] **Step 3: Commit**

```bash
git add -f dist/minifw-usb-education-v2.2.0/GUIDE.md
git commit -m "docs(education): add full product GUIDE.md — VPN bypass, SafeSearch, student/guest segments"
```

---

## Task 2: Stub README.txt + Final Verification

**Files:**
- Modify: `dist/minifw-usb-education-v2.2.0/README.txt`

- [ ] **Step 1: Replace README.txt**

Replace the full content of `dist/minifw-usb-education-v2.2.0/README.txt` with:

```
MiniFW-AI Schools Demo — v2.2.0
================================

See GUIDE.md for the full user guide:
  Docker setup, dashboard walkthrough, VPN/SafeSearch threat scenarios,
  configuration, admin reference, and troubleshooting.

Quick start:
  bash demo.sh
  open https://localhost:8447
  login: admin / Education1!
  (accept the self-signed certificate warning)
  wait ~33 seconds for first events to appear
```

- [ ] **Step 2: Commit README.txt**

```bash
git add -f dist/minifw-usb-education-v2.2.0/README.txt
git commit -m "docs(education): update README.txt stub to point to GUIDE.md"
```

- [ ] **Step 3: Final verification**

```bash
echo "=== STATIC ===" && \
    ls dist/minifw-usb-education-v2.2.0/static/index.html && echo "OK"

echo "=== LIVE ===" && \
    ls dist/minifw-usb-education-v2.2.0/demo.sh && \
    ls dist/minifw-usb-education-v2.2.0/docker/docker-compose.usb-education.yml && \
    ls dist/minifw-usb-education-v2.2.0/images/minifw-education.tar && echo "OK"

echo "=== TUTORIAL ===" && \
    ls dist/minifw-usb-education-v2.2.0/GUIDE.md && \
    wc -l dist/minifw-usb-education-v2.2.0/GUIDE.md && echo "OK"

echo "=== INSTALL (one-liner) ===" && \
    ls install.sh && echo "OK"

echo "=== INSTALL (.deb builder) ===" && \
    bash build_deb.sh education 2>&1 | head -4 | grep -q "education" && echo "OK" || echo "FAIL"
```

Expected: all 5 checks print `OK`.

- [ ] **Step 4: Test suite**

```bash
PYTHONPATH=. pytest testing/ -m "not integration" -q 2>&1 | tail -3
```

Expected: 0 failed.
