# MiniFW-AI Education Sector — Installation Guide

**Package:** `minifw-ai_2.2.0-education_amd64.deb`
**Target OS:** Ubuntu 22.04 LTS / Debian 12 (amd64)
**Requires:** Root access, nftables, Python 3.10+

---

## Build the .deb Package

On the development machine:

    bash scripts/build_deb.sh education
    # Output: build/minifw-ai_2.2.0-education_amd64.deb

## Install on the Gateway

    scp build/minifw-ai_2.2.0-education_amd64.deb admin@gateway:/tmp/
    ssh admin@gateway
    sudo apt install /tmp/minifw-ai_2.2.0-education_amd64.deb

The installer:
- Installs the app to `/opt/minifw_ai/`
- Installs two systemd services: `minifw-ai.service` (engine) and `minifw-ai-web.service` (dashboard)
- Pre-bakes `MINIFW_SECTOR=education` and `PRODUCT_MODE=minifw_school` into the service units
- Points `MINIFW_POLICY` at `/opt/minifw_ai/config/modes/minifw_school/policy.json`

## First-Run Configuration

    # Set mandatory secrets
    sudo nano /etc/minifw-ai/env
    # Add:
    #   MINIFW_SECRET_KEY=<random 32+ char string>
    #   MINIFW_ADMIN_PASSWORD=<secure password>

    # Enable and start both services
    sudo systemctl enable --now minifw-ai.service
    sudo systemctl enable --now minifw-ai-web.service

    # Check status
    sudo systemctl status minifw-ai.service
    sudo systemctl status minifw-ai-web.service

## Access the Dashboard

    https://<gateway-ip>:8443

Log in with `admin` and the password set in `MINIFW_ADMIN_PASSWORD`.

## DNS Source Configuration

By default the engine reads dnsmasq logs (`MINIFW_DNS_SOURCE=file`). Ensure dnsmasq is running and its log path is set:

    # /etc/dnsmasq.conf
    log-queries
    log-facility=/var/log/dnsmasq.log

Set `MINIFW_DNS_LOG=/var/log/dnsmasq.log` in `/etc/minifw-ai/env`.

## Verify Detection

    # Trigger a test block (VPN domain)
    dig nordvpn.com @127.0.0.1

    # Check events log
    sudo tail -f /opt/minifw_ai/logs/events.jsonl

You should see a `"action": "monitor"` or `"action": "block"` event within seconds.

## Uninstall

    sudo systemctl stop minifw-ai.service minifw-ai-web.service
    sudo apt remove minifw-ai
    sudo rm -rf /opt/minifw_ai /etc/minifw-ai
