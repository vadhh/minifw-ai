# MiniFW-AI — Distribution Packages Index

> Last updated: 2026-05-26

---

## Current Packages — v2.2.0

### Hospital Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-hospital-v2.2.0/` | Docker USB Kit | https://localhost:8443 | Requires Docker. For technical buyers. |
| `minifw-usb-hospital-standalone-v2.2.0/` | Standalone (Python) | http://localhost:8000 | No Docker. Best for executive demos. |

**Credentials:** `admin / Hospital1!`  
**Quick start:** `bash demo.sh` (Docker kit) or `bash run_demo.sh` (standalone)  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

---

### Education Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-education-v2.2.0/` | Docker USB Kit | https://localhost:8447 | Requires Docker. SafeSearch + content policy demo. |

**Credentials:** `admin / Education1!`  
**Quick start:** `bash demo.sh`  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

---

### Government Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-government-v2.2.0/` | Docker USB Kit | https://localhost:8449 | Requires Docker. APT28 C2 + data sovereignty demo. |

**Credentials:** `admin / Government1!`  
**Quick start:** `bash demo.sh`  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

---

### Legal Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-legal-v2.2.0/` | Docker USB Kit | https://localhost:8448 | Requires Docker. Attorney–client privilege + ransomware demo. |

**Credentials:** `admin / Legal1!`  
**Quick start:** `bash demo.sh`  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

---

### Establishment Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-establishment-v2.2.0/` | Docker USB Kit | https://localhost:8444 | Requires Docker. Dual-threshold (office vs guest WiFi) demo. |

**Credentials:** `admin / SME_Demo1!`  
**Quick start:** `bash demo.sh`  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

---

### Finance Sector

| Package | Type | Dashboard | Notes |
|---------|------|-----------|-------|
| `minifw-usb-financial-standalone-v2.2.0/` | Standalone (Python) | https://localhost:8443 | No Docker. PCI-DSS compliance demo for executive buyers. |

**Credentials:** `admin / Finance1!`  
**Quick start:** `bash setup_tls.sh && bash run_demo.sh`  
**Fast reset:** `bash fast_reset.sh` (target: 45 seconds)  
**Presenter docs:** `DEMO_SCRIPT.md` · `PRESENTER_CARD.md`

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

| Sector | Port | Package | Type |
|--------|------|---------|------|
| Hospital (Docker) | 8443 | minifw-usb-hospital-v2.2.0 | Docker |
| Hospital (Standalone) | 8000 | minifw-usb-hospital-standalone-v2.2.0 | Python |
| Education | 8447 | minifw-usb-education-v2.2.0 | Docker |
| Gambling | 8446 | minifw-usb-gambling-v2.2.0 | Docker |
| Finance | 8443 (HTTPS) | minifw-usb-financial-standalone-v2.2.0 | Python |
| Government | 8449 | minifw-usb-government-v2.2.0 | Docker |
| Legal | 8448 | minifw-usb-legal-v2.2.0 | Docker |
| Establishment | 8444 | minifw-usb-establishment-v2.2.0 | Docker |

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
bash build_deb.sh government
bash build_deb.sh legal
bash build_deb.sh establishment
```

See `build_usb.sh` and `scripts/build_deb.sh` for full options.
