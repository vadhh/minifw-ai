# MiniFW-AI Legal Sector — Design Spec

**Date:** 2026-04-30  
**Status:** Approved  
**Approach:** Option A — Full dedicated `minifw_legal` mode

---

## Overview

Implement the legal sector as a first-class `PRODUCT_MODE` (`minifw_legal`), following the same pattern as `minifw_school` (education). Legal is currently recognized in `VALID_SECTORS` but falls back to `minifw_establishment` — this spec makes it fully independent.

Target audience for demos: managing partners, IT directors, compliance officers at law firms.

---

## Section 1: Core Configuration

### `config/modes/minifw_legal/policy.json`

New policy with 5 segments reflecting law firm network structure.

**Segments and thresholds:**

| Segment | Subnet | Block | Monitor | Rationale |
|---------|--------|-------|---------|-----------|
| `partner` | 10.20.0.0/24 | 85 | 55 | Senior counsel — most trusted |
| `associate` | 10.20.1.0/24 | 78 | 45 | Standard lawyer threshold |
| `paralegal` | 10.20.2.0/24 | 70 | 38 | Limited data access — stricter |
| `client` | 192.168.200.0/24 | 62 | 30 | Client meeting rooms — tight |
| `guest` | 192.168.100.0/24 | 60 | 28 | Visitor WiFi — tightest |

Score weights: dns +40, sni +35, asn +15, ip_denied +15, burst +10, mlp +30, yara +35 (same as education).

### `app/minifw_ai/mode_context.py`

Add `minifw_legal` entry to `_MODE_UI`:
- `label`: `"Legal"`
- `sublabel`: `"Attorney-Client Privilege · Data Exfiltration · Ransomware"`
- `color`: `#b45309` (amber-brown — professional, distinct from all existing modes)
- `bg`: `rgba(180,83,9,0.10)`
- `css_class`: `mode-legal`
- `icon`: `bi-briefcase`
- `sector`: `"legal"`

Update `_SECTOR_TO_MODE`: `"legal" → "minifw_legal"` (removes the fallback to `minifw_establishment`).

---

## Section 2: YARA Rules & Demo Injector

### `yara_rules/legal_rules.yar`

Three rules covering the legal sector threat landscape:

- **`LegalRansomwareC2`** — ransomware C2 beacons targeting legal document management systems. Strings: `lexisnexis-ransom`, `clio-encrypt`, `case-mgmt-c2`, `ransomware-legal`.
- **`LegalDataExfiltration`** — unauthorized cloud upload/exfiltration of case files. Strings: `dropbox-casefile`, `wetransfer-legal`, `gdrive-exfil`, `onedrive-leak`, `case-upload.io`.
- **`LegalPrivilegeViolation`** — attorney-client privilege breach patterns. Strings: `opposing-counsel.harvest`, `case-data.darkweb`, `privilege-breach`, `client-data.dump`.

### `docker/demo-injector-legal/inject.py`

6-phase loop, ~2-minute cycle:

| Phase | Domain | Source IP | Expected outcome |
|-------|--------|-----------|-----------------|
| 1 — Normal legal research | westlaw.com, lexisnexis.com, courts.gov | 10.20.0.x | ALLOW |
| 2 — Unauthorized cloud upload | wetransfer-legal.io | 10.20.2.10 (paralegal) | MONITOR (score 40) |
| 3 — Tor exit node | tor-exit-relay.onion-gw.net | 192.168.200.5 (client room) | BLOCK (ASN +15, feed +40) |
| 4 — Ransomware C2 | clio-encrypt.c2-server.ru | 10.20.1.20 (associate) | BLOCK (YARA +35, score 75) |
| 5 — Privilege breach | opposing-counsel.harvest.io | 10.20.2.50 (paralegal) | BLOCK (YARA +35) |
| 6 — Burst attack | 200× clio-encrypt.c2-server.ru | 10.20.1.99 | BLOCK CASCADE |

### `docker/demo-injector-legal/Dockerfile`

Minimal Python image, copies `inject.py`, runs it as entrypoint.

---

## Section 3: Docker Compose & Build Scripts

### `docker/docker-compose.legal.yml` (source build)

- 3 services: `engine`, `web`, `injector`
- `PRODUCT_MODE: minifw_legal`, `MINIFW_SECTOR: legal`
- `MINIFW_ADMIN_PASSWORD: "Legal1!"`
- Port `8448:8443`
- Injector built from `docker/demo-injector-legal/`

### `docker/docker-compose.usb-legal.yml` (USB variant)

- Same structure but uses pre-loaded images instead of build context
- Image names: `minifw-ai-demo/legal:latest`, `minifw-ai-demo/legal-injector:latest`
- Image tar: `minifw-legal.tar`

### `build_usb.sh` — add `legal)` case

| Key | Value |
|-----|-------|
| `SOURCE_COMPOSE` | `docker/docker-compose.legal.yml` |
| `USB_COMPOSE` | `docker/docker-compose.usb-legal.yml` |
| `INJECTOR_DIR` | `docker/demo-injector-legal` |
| `IMAGE_TAG` | `minifw-ai-demo/legal:latest` |
| `INJECTOR_TAG` | `minifw-ai-demo/legal-injector:latest` |
| `IMAGE_TAR_NAME` | `minifw-legal.tar` |
| `CONFIG_MODE` | `minifw_legal` |
| `DASHBOARD_PORT` | `8448` |
| `ADMIN_PASS` | `Legal1!` |

### `scripts/build_deb.sh` — add `legal)` case

- `PRODUCT_MODE=minifw_legal`, `MINIFW_SECTOR=legal`
- Package: `minifw-ai_2.2.0-legal_amd64.deb`
- Policy: `config/modes/minifw_legal/policy.json`

---

## Section 4: Documentation

Three files under `docs/legal/`:

### `docs/legal/demo-guide.md`
- Audience: sales engineers presenting to managing partners, IT directors, compliance officers
- Port `8448`, password `Legal1!`, mode `minifw_legal`
- 4-phase walkthrough matching injector (normal → cloud upload monitor → ransomware C2 block → burst cascade)
- Talking points by audience:

| Audience | Focus |
|----------|-------|
| Managing Partner | Trace ID + audit trail for privilege protection |
| IT Director | Per-segment thresholds (partner vs paralegal vs client room) |
| Compliance Officer | YARA catches unknown C2 variants not yet on blocklists |
| Associate | Decision Owner + Trace ID for incident response |

### `docs/legal/INSTALL.md`
- Package verification (sha256), env var setup, `sudo -E dpkg -i`, service verification, dashboard access, DNS source config, per-segment threshold table, config file locations, troubleshooting, uninstall.

### `docs/legal/README.md`
- Part 1: Demo mode (Docker) — prerequisites, start, dashboard walkthrough, cycle timing table, live policy modification, stop/reset
- Part 2: Production mode (.deb) — install, configure secrets, start services, verify, add custom deny domains, tune segments, export audit reports
- Troubleshooting table

---

## Deliverables Checklist

- [ ] `config/modes/minifw_legal/policy.json`
- [ ] `app/minifw_ai/mode_context.py` — `minifw_legal` entry + sector map update
- [ ] `yara_rules/legal_rules.yar`
- [ ] `docker/demo-injector-legal/Dockerfile`
- [ ] `docker/demo-injector-legal/inject.py`
- [ ] `docker/docker-compose.legal.yml`
- [ ] `docker/docker-compose.usb-legal.yml`
- [ ] `build_usb.sh` — legal case
- [ ] `scripts/build_deb.sh` — legal case
- [ ] `docs/legal/demo-guide.md`
- [ ] `docs/legal/INSTALL.md`
- [ ] `docs/legal/README.md`
