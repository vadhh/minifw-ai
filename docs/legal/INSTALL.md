# Installation Guide — MiniFW-AI Legal Sector v2.2.0

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Debian 12 / Ubuntu 22.04+ | amd64 only |
| Python 3.10+ | `python3 --version` |
| python3-venv | `sudo apt install python3-venv` |
| nftables | `sudo apt install nftables` |
| conntrack | `sudo apt install conntrack` |
| openssl | For TLS certificate generation |
| Root / sudo | Required for install and daemon startup |

Optional (for enhanced detection):
- `dnsmasq` — DNS event collection (recommended for all deployments)
- `zeek` — TLS SNI enrichment via ssl.log

---

## Step 1 — Verify the Package

```bash
sha256sum -c minifw-ai_2.2.0-legal_amd64.deb.sha256
# Expected: minifw-ai_2.2.0-legal_amd64.deb: OK
```

---

## Step 2 — Set Environment Variables

```bash
export MINIFW_SECRET_KEY="$(openssl rand -hex 32)"
export MINIFW_ADMIN_PASSWORD="YourSecurePassword1!"
```

The `postinst` script reads these to provision the admin user and bake the secret key.
If not set, installation will abort with an error.

---

## Step 3 — Install

```bash
sudo -E dpkg -i minifw-ai_2.2.0-legal_amd64.deb
```

**What `postinst` does automatically:**
1. Creates `/opt/minifw_ai/` directory tree
2. Creates a Python virtual environment at `/opt/minifw_ai/venv/`
3. Installs Python dependencies into the venv
4. Generates a self-signed TLS certificate (valid 3650 days)
5. Provisions the `admin` user with the password you set
6. Writes `/etc/minifw-ai/minifw-ai.conf` with `MINIFW_SECTOR=legal` and `PRODUCT_MODE=minifw_legal`
7. Enables and starts `minifw-engine.service` and `minifw-web.service`

If any dependency is missing, resolve it with:
```bash
sudo apt-get install -f
sudo -E dpkg -i minifw-ai_2.2.0-legal_amd64.deb
```

---

## Step 4 — Verify Services

```bash
systemctl status minifw-engine
systemctl status minifw-web
```

Both should show `active (running)`.

```bash
journalctl -u minifw-engine -n 50
```

Expected output includes:
```
[minifw] Sector: legal | Mode: BASELINE_PROTECTION
[minifw] Web dashboard: https://0.0.0.0:8443
```

---

## Step 5 — Open the Dashboard

Navigate to `https://<gateway-ip>:8443`.

- Accept the self-signed TLS certificate warning
- Login: `admin` / `<password you set in Step 2>`
- Dashboard header should show **Legal Sector** with the amber-brown accent

---

## Step 6 — Configure DNS Source (Recommended)

Edit `/etc/minifw-ai/minifw-ai.conf`:

```bash
MINIFW_DNS_SOURCE=file
MINIFW_DNS_LOG=/var/log/dnsmasq.log
```

Ensure dnsmasq is logging queries:

```bash
# /etc/dnsmasq.conf
log-queries
log-facility=/var/log/dnsmasq.log
```

```bash
sudo systemctl restart minifw-engine
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/minifw-ai/minifw-ai.conf` | Environment variables for both services |
| `/opt/minifw_ai/config/modes/minifw_legal/policy.json` | Legal policy (per-segment thresholds, score weights) |
| `/opt/minifw_ai/config/feeds/` | Domain/IP/ASN deny and allow feeds |
| `/opt/minifw_ai/yara_rules/legal_rules.yar` | Ransomware C2, data exfiltration, privilege violation, Tor exit rules |

---

## Per-Segment Thresholds

Default thresholds baked into `minifw_legal/policy.json`. Adjust via Dashboard → Policy → Segments.

| Segment | Block | Monitor | Rationale |
|---------|-------|---------|-----------|
| `partner` | 85 | 55 | Senior counsel — most trusted |
| `associate` | 72 | 45 | Standard lawyer threshold |
| `paralegal` | 70 | 38 | Stricter — limited data access |
| `client` | 62 | 30 | Client meeting rooms — tight |
| `guest` | 60 | 28 | Visitor WiFi — tightest |

---

## Troubleshooting

**Services not starting:**
```bash
journalctl -u minifw-engine --no-pager -n 100
```
Common cause: `MINIFW_SECRET_KEY` not set. Add it to `/etc/minifw-ai/minifw-ai.conf` and restart.

**nftables enforcement not working:**
```bash
sudo nft list ruleset
sudo systemctl status nftables
```

**Port 8443 in use:**
```bash
ss -tlnp | grep 8443
sudo systemctl restart minifw-web
```

**No events appearing on dashboard:**
```bash
sudo systemctl status dnsmasq
tail -f /var/log/dnsmasq.log
```

---

## Uninstall

```bash
sudo systemctl stop minifw-engine minifw-web
sudo dpkg -r minifw-ai
```

To purge completely:
```bash
sudo dpkg --purge minifw-ai
sudo rm -rf /opt/minifw_ai /etc/minifw-ai
```
