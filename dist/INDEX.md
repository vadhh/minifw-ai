# MiniFW-AI — Distribution Packages Index

> Last updated: 2026-07-29

---

## Current Packages — v2.2.0

All six sector packages are Docker USB kits (`docker compose -f docker/docker-compose.usb-<sector>.yml up`, or `bash demo.sh`).

| Sector | Package | Dashboard | Credentials | Notes |
|--------|---------|-----------|-------------|-------|
| Hospital | `minifw-usb-hospital-v2.2.0/` | https://localhost:8443 | `admin / Hospital1!` | HIPAA + IoMT demo |
| Education | `minifw-usb-education-v2.2.0/` | https://localhost:8447 | `admin / Education1!` | SafeSearch + content policy demo |
| Establishment | `minifw-usb-establishment-v2.2.0/` | https://localhost:8444 | `admin / SME_Demo1!` | Dual-threshold (office vs guest WiFi) demo |
| Finance | `minifw-usb-financial-v2.2.0/` | https://localhost:8445 | `admin / Finance1!` | PCI-DSS + Tor blocking demo |
| Government | `minifw-usb-government-v2.2.0/` | https://localhost:8449 | `admin / Government1!` | APT/C2 + data sovereignty demo |
| Legal | `minifw-usb-legal-v2.2.0/` | https://localhost:8448 | `admin / Legal1!` | Attorney-client privilege + ransomware demo |

Each package includes its own `demo.sh` (start), `fast_reset.sh` (reset, where present), and Docker Compose file under `docker/`.

---

## Legacy / Archived

The standalone (no-Docker) Python demo packages for hospital and financial, and the gambling-sector package, have been removed — see git history if needed. All sectors are now served by the Docker USB kits above.

---

## Build Commands

```bash
# Rebuild a USB kit from source
bash build_usb.sh hospital        # → dist/minifw-usb-hospital-v2.2.0/
bash build_usb.sh education        # → dist/minifw-usb-education-v2.2.0/
bash build_usb.sh establishment     # → dist/minifw-usb-establishment-v2.2.0/
bash build_usb.sh financial          # → dist/minifw-usb-financial-v2.2.0/
bash build_usb.sh government          # → dist/minifw-usb-government-v2.2.0/
bash build_usb.sh legal                # → dist/minifw-usb-legal-v2.2.0/

# Build .deb installer
bash build_deb.sh <sector> [version]
```

See `build_usb.sh` and `scripts/build_deb.sh` for full options.
