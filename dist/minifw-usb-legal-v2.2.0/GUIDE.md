# MiniFW-AI Legal — User Guide

**Version:** 2.2.0 | **Sector:** Legal | **Mode:** Docker Demo

---

## Overview

MiniFW-AI Legal is an AI-powered behavioral firewall for law firm gateway hardware. It enforces attorney-client privilege protections and defends against:

- **Ransomware C2 callbacks** — known command-and-control domains blocked before encryption keys can be received
- **Privilege breach exfiltration** — domains used to harvest opposing counsel data or leak privileged communications
- **Unauthorized cloud upload** — file-sharing services used to exfiltrate documents outside firm-approved channels
- **Tor exit relay access** — anonymization infrastructure blocked on all segments, especially client meeting rooms
- **Burst/DDoS-style C2** — high-frequency DNS queries to a single ransomware domain trigger burst detection

The demo loops continuously — events replay every ~27 seconds, so every dashboard visit shows live activity.

**Access:** HTTPS on port 8448. Accept the browser's self-signed certificate warning.

---

## Prerequisites

| Requirement | Check Command | Notes |
|-------------|---------------|-------|
| Docker Engine | `docker --version` | Docker Desktop on Windows/macOS |
| Docker Compose v2 | `docker compose version` | Must print v2.x, not v1 |
| Port 8448 free | `ss -tlnp \| grep 8448` | — |
| WSL2 (Windows only) | Docker Desktop settings | Required for Windows users |

**Windows:** Install Docker Desktop with WSL2 integration enabled.
**Linux:** `sudo systemctl start docker` if daemon is not running.
**macOS:** Open Docker Desktop before running `demo.sh`.

---

## Quick Start

```bash
bash demo.sh
```

**First run on a new machine** loads Docker images from `images/minifw-legal.tar` (~2–3 minutes, one-time). Subsequent runs start immediately.

Open **https://localhost:8448** and login with `admin` / `Legal1!`

Accept the self-signed certificate warning in your browser.

**Expected terminal output:**
```
  ● MiniFW-AI Demo — Legal
  ─────────────────────────────────────────────────────
  Dashboard : https://localhost:8448
  Login     : admin / Legal1!
  Sector    : Legal / Attorney-Client Privilege

  Ctrl+C to stop.
```

**Wait ~27 seconds** for the first injector loop to populate events in the dashboard. The injector starts after an 8-second warm-up delay and completes one full loop (7 scenario events + burst) before the 10-second inter-loop sleep.

**Stop the demo:**
```bash
Ctrl+C
```
The script prints the cleanup command. To force-stop manually:
```bash
docker compose -f docker/docker-compose.usb-legal.yml down
```

---

## Dashboard Walkthrough

### Event Feed

| Column | Meaning |
|--------|---------|
| **Time** | Timestamp of the DNS query |
| **Domain** | Queried hostname |
| **Client IP** | Source device (partner, associate, paralegal, client, or guest subnet) |
| **Score** | Threat score 0–100 |
| **Decision** | ALLOW / MONITOR / BLOCK |
| **Reason** | Primary detection layer that fired |
| **Segment** | Network zone the client IP maps to |

**Score composition** (configurable in `config/modes/minifw_legal/policy.json`):

| Layer | Max contribution |
|-------|-----------------|
| DNS feed match (deny list) | +40 |
| TLS/SNI anomaly | +35 |
| ASN block list | +15 |
| IP deny list | +15 |
| DNS burst / qpm spike | +10 |
| MLP classifier | 0–30 |
| YARA payload match | 0–35 |

### Decision Thresholds (Legal sector)

| Segment | MONITOR at | BLOCK at | Subnets |
|---------|-----------|---------|---------|
| partner | 55 | 85 | 10.20.0.0/24 |
| associate | 45 | 72 | 10.20.1.0/24 |
| paralegal | 38 | 70 | 10.20.2.0/24 |
| client | 30 | 62 | 192.168.200.0/24 |
| guest | 28 | 60 | 192.168.100.0/24 |
| default | 50 | 80 | (catch-all) |

Partners have the most relaxed thresholds (senior counsel). Client meeting rooms and guest WiFi have the tightest thresholds — unknown devices are treated with maximum suspicion.

### AI Threat Synthesis Panel

Shows:
- **Current protection state:** `BASELINE_PROTECTION` (hard gates only) or `AI_ENHANCED_PROTECTION` (adds MLP + YARA scoring)
- **Top threat actors:** most-blocked domains/IPs in the current demo session
- **Detection breakdown:** which scoring layers are firing most frequently

---

## Threat Scenarios

The demo injector (`docker/demo-injector-legal/inject.py`) loops continuously. Each loop injects 7 events plus a burst sequence, repeating every ~27 seconds.

### Per-Loop Scenario Summary

| # | Domain | Client IP | Segment | Expected Decision | Why |
|---|--------|-----------|---------|------------------|-----|
| 1 | `westlaw.com` | 10.20.0.10 | partner | ALLOW | Legitimate legal research (partner) |
| 2 | `lexisnexis.com` | 10.20.0.11 | partner | ALLOW | Legitimate legal research (partner) |
| 3 | `courts.gov` | 10.20.1.10 | associate | ALLOW | Federal court docket (associate) |
| 4 | `wetransfer-legal.io` | 10.20.2.10 | paralegal | MONITOR (score=40) | Unauthorized cloud upload; feed+40 > paralegal MONITOR=38 |
| 5 | `tor-exit-relay.onion-gw.net` | 192.168.200.5 | client | **BLOCK** (score=75) | Tor exit relay; YARA match pushes past client BLOCK=62 |
| 6 | `clio-encrypt.c2-server.ru` | 10.20.1.20 | associate | **BLOCK** (score=75) | Ransomware C2 beacon; feed+YARA > associate BLOCK=72 |
| 7 | `opposing-counsel.harvest.io` | 10.20.2.50 | paralegal | **BLOCK** (score=75) | Privilege violation; feed+YARA > paralegal BLOCK=70 |
| Burst | `clio-encrypt.c2-server.ru` | 10.20.1.99 | associate | **BLOCK cascade** | 200 rapid queries trigger burst detection, score escalates |

### Scenario Detail

**1–3 Normal traffic (ALLOW)**
Legitimate legal research to Westlaw and LexisNexis (partner subnet), and federal court docket access (associate subnet). These demonstrate that approved legal tools are not blocked.

**4 Unauthorized cloud upload (MONITOR)**
`wetransfer-legal.io` from paralegal subnet (10.20.2.10). DNS feed match adds +40, putting score at 40 — just above the paralegal MONITOR threshold (38) but below BLOCK (70). The firm logs the attempt for compliance review rather than hard-blocking.

**5 Tor exit relay from client meeting room (BLOCK)**
`tor-exit-relay.onion-gw.net` from a client meeting room IP (192.168.200.5). YARA rule matches the `.onion-gw` pattern (+35). Combined with feed score (+40), total is 75 — well above the client BLOCK threshold of 62. **BLOCK fires.** The same score would only MONITOR on the partner network (BLOCK=85).

**6 Ransomware C2 beacon (BLOCK)**
`clio-encrypt.c2-server.ru` from associate subnet (10.20.1.20). The domain matches both the deny feed (+40) and a YARA ransomware C2 rule (+35). Score = 75 exceeds the associate BLOCK threshold of 72. **BLOCK fires.**

**7 Privilege breach / opposing counsel harvest (BLOCK)**
`opposing-counsel.harvest.io` from paralegal subnet (10.20.2.50). YARA privilege-violation rule fires (+35). Score = 75 exceeds paralegal BLOCK threshold of 70. **BLOCK fires.** This scenario represents an insider threat or compromised paralegal workstation attempting to leak case data.

**Burst sequence (BLOCK cascade)**
200 rapid queries to `clio-encrypt.c2-server.ru` from 10.20.1.99. The burst tracker fires within the first ~50 queries (+10 to score). Combined with YARA match (+35) and feed (+40), score far exceeds any segment's block threshold. Multiple BLOCK entries appear rapidly in the event feed.

---

## Configuration

### policy.json

`config/modes/minifw_legal/policy.json` controls thresholds and score weights.

Key fields (excerpt — simplified for clarity):

```json
{
  "segments": {
    "partner":   { "block_threshold": 85, "monitor_threshold": 55 },
    "associate": { "block_threshold": 72, "monitor_threshold": 45 },
    "paralegal": { "block_threshold": 70, "monitor_threshold": 38 },
    "client":    { "block_threshold": 62, "monitor_threshold": 30 },
    "guest":     { "block_threshold": 60, "monitor_threshold": 28 }
  },
  "features": {
    "dns_weight": 40, "sni_weight": 35, "asn_weight": 15,
    "burst_weight": 10, "mlp_weight": 30, "yara_weight": 35
  }
}
```

To make the demo more aggressive (block cloud uploads on paralegal): lower `paralegal.block_threshold` to 42. To relax partner monitoring: raise `partner.monitor_threshold` to 70.

### config/feeds/

| File | Content |
|------|---------|
| `deny_domains.txt` | Known ransomware C2 domains, data exfiltration endpoints, privilege-breach harvesting domains |
| `tor_exit_nodes.txt` | Tor exit nodes (blocked on all segments) |
| `deny_ips.txt` | IP block list |

### Demo injector

`docker/demo-injector-legal/inject.py` controls which domains are injected and their timing. Edit the emit calls to simulate different scenarios. Rebuild the Docker image after editing:
```bash
docker compose -f docker/docker-compose.usb-legal.yml build
bash demo.sh
```

---

## Admin Reference

| Item | Location / Command |
|------|--------------------|
| Stop demo | `Ctrl+C` in terminal |
| Force stop containers | `docker compose -f docker/docker-compose.usb-legal.yml down` |
| Fast reset (restart containers) | `bash fast_reset.sh` |
| View engine logs | `docker compose -f docker/docker-compose.usb-legal.yml logs minifw-engine` |
| View web logs | `docker compose -f docker/docker-compose.usb-legal.yml logs minifw-web` |
| View injector output | `docker compose -f docker/docker-compose.usb-legal.yml logs minifw-injector` |
| YARA rules | `yara_rules/` |
| Feeds | `config/feeds/` |
| Pre-demo checklist | `PRE_DEMO_CHECKLIST.md` |
| Presenter talking points | `PRESENTER_CARD.md` |
| Full demo script | `DEMO_SCRIPT.md` |

---

## Troubleshooting

**Port 8448 already in use:**
```bash
docker compose -f docker/docker-compose.usb-legal.yml down
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

**No events appearing after 30 seconds:**
```bash
docker compose -f docker/docker-compose.usb-legal.yml logs minifw-injector
```
If injector is not running, restart the demo.

**Images failed to load (first run):**
```bash
docker load -i images/minifw-legal.tar
bash demo.sh
```

**Browser shows certificate warning:**
This is expected — the demo uses a self-signed TLS certificate. Click "Advanced" → "Proceed to localhost" (Chrome) or "Accept the Risk and Continue" (Firefox).

**Dashboard loads but shows no data after 2 loops:**
The engine may not be receiving DNS events. Check:
```bash
docker compose -f docker/docker-compose.usb-legal.yml logs minifw-engine | tail -20
```

---

## Production Deployment

This kit is for offline demos only. For production deployment on law firm gateway hardware:

**One-line installer** (Debian/Ubuntu, requires root):
```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

Select `legal` when prompted for sector selection. The installer downloads the legal `.deb`, verifies GPG signature, and starts both services.

**Manual .deb install:**
```bash
sudo dpkg -i minifw-ai_2.2.0-legal_amd64.deb
sudo systemctl status minifw-ai minifw-ai-web
```

- Config: `/opt/minifw_ai/config/modes/minifw_legal/policy.json`
- Logs: `/opt/minifw_ai/logs/`
- Dashboard: **https://localhost:8443** (TLS, self-signed cert generated on install)
- Credentials: `/etc/minifw/minifw.env` (auto-generated on first install)
