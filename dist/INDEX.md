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
