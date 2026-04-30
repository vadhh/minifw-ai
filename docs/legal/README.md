# MiniFW-AI Legal Sector — Tutorial

This tutorial walks through both **demo mode** (Docker, for presentations) and **production mode** (installed on a real Linux gateway).

---

## Part 1: Demo Mode (Docker)

### 1.1 Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 4 GB free disk space (image is ~910 MB)
- Port 8448 available on your machine

### 1.2 Start the Demo

    cd /path/to/minifw-ai
    docker compose -f docker/docker-compose.legal.yml up

Wait ~20 seconds for the engine healthcheck to pass, then open `https://localhost:8448`. Accept the self-signed TLS certificate and log in:

- **Username:** `admin`
- **Password:** `Legal1!`

### 1.3 Understanding the Dashboard

**Top bar:** Shows the current sector (`Legal — Attorney-Client Privilege · Data Exfiltration · Ransomware`) and protection state.

**AI Threat Synthesis panel:**
- **THREAT BLOCKED** — headline for the most recent block event
- **Risk %** — colour-coded score badge (red ≥85%, amber ≥65%)
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
| 0-8s | westlaw.com, lexisnexis.com, courts.gov | ALLOW |
| 10s | wetransfer-legal.io from 10.20.2.10 | MONITOR (score 40) |
| 12s | tor-exit-relay.onion-gw.net from 192.168.200.5 | BLOCK (feed+YARA, score 75) |
| 14s | clio-encrypt.c2-server.ru from 10.20.1.20 | BLOCK (YARA ransomware, score 75) |
| 16s | opposing-counsel.harvest.io from 10.20.2.50 | BLOCK (YARA privilege, score 75) |
| 20s+ | 200× clio-encrypt.c2-server.ru burst | BLOCK CASCADE |

### 1.5 Modify Policy Live

1. Go to **Policy → Segments**
2. Lower the `paralegal` block threshold from 70 to 40
3. Reload the Events page — the next `wetransfer-legal.io` event will change from MONITOR to BLOCK

### 1.6 Stop and Reset

    docker compose -f docker/docker-compose.legal.yml down -v

---

## Part 2: Production Mode (.deb on Linux Gateway)

### 2.1 Prerequisites

- Ubuntu 22.04 LTS or Debian 12 (amd64)
- Root access
- nftables: `sudo apt install nftables`
- dnsmasq configured for log output (see INSTALL.md)

### 2.2 Install the Package

    sudo apt install ./minifw-ai_2.2.0-legal_amd64.deb

### 2.3 Configure Secrets

    sudo mkdir -p /etc/minifw-ai
    sudo tee /etc/minifw-ai/minifw-ai.conf <<EOF
    MINIFW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    MINIFW_ADMIN_PASSWORD=YourSecurePassword1!
    MINIFW_DNS_LOG=/var/log/dnsmasq.log
    MINIFW_DNS_SOURCE=file
    EOF
    sudo chmod 600 /etc/minifw-ai/minifw-ai.conf

### 2.4 Start Services

    sudo systemctl enable --now minifw-engine.service
    sudo systemctl enable --now minifw-web.service

### 2.5 Verify Operation

    sudo journalctl -u minifw-engine -f
    sudo journalctl -u minifw-web -f
    sudo tail -f /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool

### 2.6 Add Custom Deny Domains

Edit `/opt/minifw_ai/config/feeds/deny_domains.txt`:

    # Firm-specific additions
    *.dropbox.com
    *.googledrive.com
    pastebin.com

To force an immediate reload:

    sudo systemctl restart minifw-engine

### 2.7 Tune Per-Segment Thresholds

Log in to `https://<gateway-ip>:8443` → **Policy → Segments**.

Recommended starting values:

| Segment | Block | Monitor | Rationale |
|---------|-------|---------|-----------|
| partner | 85 | 55 | Senior counsel — relaxed |
| associate | 72 | 45 | Standard lawyer threshold |
| paralegal | 70 | 38 | Stricter — limited access |
| client | 62 | 30 | Client rooms — tight |
| guest | 60 | 28 | Visitor WiFi — tightest |

### 2.8 Export Audit Reports

**Dashboard → Reports → Export Events** — download CSV or PDF of all block events for compliance records, regulatory submissions, and incident response documentation.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No events appearing | dnsmasq not logging | Check `log-queries` in `/etc/dnsmasq.conf` |
| Dashboard unreachable | Service not started | `sudo systemctl start minifw-web.service` |
| All traffic blocked | Block threshold too low | Raise threshold in Policy → Segments |
| YARA not matching | Rules path wrong | Check `MINIFW_YARA_RULES` env var |
| Secret key error | Env var missing | Ensure `MINIFW_SECRET_KEY` is set in `/etc/minifw-ai/minifw-ai.conf` |
| Wrong sector shown | PRODUCT_MODE mismatch | Verify `PRODUCT_MODE=minifw_legal` in conf file |
