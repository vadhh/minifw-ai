# MiniFW-AI Education Sector — Tutorial

This tutorial walks through both **demo mode** (Docker, for presentations) and **production mode** (installed on a real Linux gateway).

---

## Part 1: Demo Mode (Docker)

### 1.1 Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 4 GB free disk space (image is ~910 MB)
- Port 8447 available on your machine

### 1.2 Start the Demo

    cd /path/to/minifw-ai
    docker compose -f docker/docker-compose.education.yml up

Wait ~20 seconds for the engine healthcheck to pass, then open `https://localhost:8447`. Accept the self-signed TLS certificate and log in:

- **Username:** `admin`
- **Password:** `Education1!`

### 1.3 Understanding the Dashboard

**Top bar:** Shows the current sector (`School — SafeSearch · Content Filtering`) and protection state.

**AI Threat Synthesis panel:**
- **THREAT BLOCKED** — headline for the most recent block event
- **Risk %** — colour-coded score badge (red >=85%, amber >=65%)
- **BLOCKED** pill — confirms enforcement action
- **AI REASON** — what detection method triggered (YARA, DNS feed, MLP)
- **DECISION OWNER** — which layer made the call (Hard Gate, AI Engine, Policy Engine)
- **TRACE ID** — 8-character ID for the audit trail

**Events page:** Full log of all allow/monitor/block decisions.

**Policy page:** Edit segment thresholds live (changes take effect within 5 seconds).

### 1.4 Watch the Demo Cycle

The injector sends threats in this order every ~2 minutes:

| Time | Event | Expected outcome |
|------|-------|-----------------|
| 0-8s | khanacademy.org, bbc.co.uk, wikipedia.org | ALLOW |
| 10s | instagram.com from 10.10.0.20 | MONITOR (score 40) |
| 12s | nordvpn.com from 10.10.0.50 | MONITOR (score 40) |
| 14s | nordvpn-bypass.proxy.io from 10.10.0.50 | BLOCK (YARA +35, score 75) |
| 16s | filter-bypass.student.io from 192.168.100.10 | BLOCK (YARA match) |
| 18s | bet365.com from 10.10.0.100 | MONITOR (score 40) |
| 20s+ | 200x nordvpn-bypass.proxy.io burst | BLOCK CASCADE |

### 1.5 Modify Policy Live

1. Go to **Policy -> Segments**
2. Lower the `student` block threshold from 70 to 40
3. Reload the Events page — the next `instagram.com` event will change from MONITOR to BLOCK

### 1.6 Stop and Reset

    docker compose -f docker/docker-compose.education.yml down -v

---

## Part 2: Production Mode (.deb on Linux Gateway)

### 2.1 Prerequisites

- Ubuntu 22.04 LTS or Debian 12 (amd64)
- Root access
- nftables: `sudo apt install nftables`
- dnsmasq configured for log output (see Installation Guide)

### 2.2 Install the Package

    sudo apt install ./minifw-ai_2.2.0-education_amd64.deb

### 2.3 Configure Secrets

    sudo mkdir -p /etc/minifw-ai
    sudo tee /etc/minifw-ai/env <<EOF
    MINIFW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    MINIFW_ADMIN_PASSWORD=YourSecurePassword1!
    MINIFW_DNS_LOG=/var/log/dnsmasq.log
    EOF
    sudo chmod 600 /etc/minifw-ai/env

### 2.4 Start Services

    sudo systemctl enable --now minifw-ai.service
    sudo systemctl enable --now minifw-ai-web.service

### 2.5 Verify Operation

    sudo journalctl -u minifw-ai.service -f
    sudo journalctl -u minifw-ai-web.service -f
    sudo tail -f /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool

### 2.6 Add Custom School Blacklist Entries

Edit `/opt/minifw_ai/config/feeds/school_blacklist.txt`:

    # Custom entries
    *.discord.com
    *.twitch.tv
    roblox.com

To force an immediate reload:

    sudo systemctl restart minifw-ai.service

### 2.7 Tune Per-Segment Thresholds

Log in to `https://<gateway-ip>:8443` -> **Policy -> Segments**.

Recommended starting values:

| Segment | Block | Monitor | Rationale |
|---------|-------|---------|-----------|
| student | 70 | 35 | Stricter — SafeSearch enforced |
| staff | 80 | 50 | Standard — trusted users |
| guest | 60 | 30 | Tightest — unknown devices |
| admin | 85 | 55 | Relaxed — IT personnel |

### 2.8 Export Audit Reports

**Dashboard -> Reports -> Export Events** — download CSV or PDF of all block events for safeguarding records and school board reporting.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No events appearing | dnsmasq not logging | Check `log-queries` in `/etc/dnsmasq.conf` |
| Dashboard unreachable | Service not started | `sudo systemctl start minifw-ai-web.service` |
| All traffic blocked | Block threshold too low | Raise threshold in Policy -> Segments |
| YARA not matching | Rules path wrong | Check `MINIFW_YARA_RULES` env var |
| Secret key error | Env var missing | Ensure `MINIFW_SECRET_KEY` is set in `/etc/minifw-ai/env` |
