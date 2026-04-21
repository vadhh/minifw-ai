# USB Demo Kit — Design Spec
**Date:** 2026-04-20  
**Sector:** establishment (extensible to all sectors)  
**Status:** approved

---

## Goal

Package the MiniFW-AI establishment demo into a single 8GB USB key that a sales person can plug into any Windows (WSL2) or Linux laptop and run with one command — no internet required.

---

## Approach

Single smart launcher (`demo.sh` on USB root). On first run it loads Docker images from the USB onto the host; subsequent runs on the same machine detect the images are already loaded and skip straight to starting the demo. One command always: `bash /media/usb/demo.sh`.

---

## USB Layout

```
USB root/
├── demo.sh                          ← smart launcher (load-if-needed + start)
├── README.txt                       ← quickstart for sales team
├── images/
│   └── minifw-establishment.tar     ← docker save of all required images (~2–3 GB)
└── docker/
    ├── docker-compose.sme.yml
    ├── demo-policy-sme.json
    ├── demo-injector-sme
    ├── entrypoint-engine.sh
    ├── entrypoint-web.sh
    └── Dockerfile
```

---

## demo.sh Logic

```
1. Detect USB mount path (resolve path of $0)
2. Check if image "minifw_establishment" exists in local Docker
3. If not → docker load -i images/minifw-establishment.tar  (one-time, ~2–3 min)
4. Set COMPOSE_FILE to docker/docker-compose.sme.yml (relative to USB)
5. Run: docker compose up --build  (fast — image already loaded)
6. Print dashboard URL + credentials to terminal
```

---

## Build Script

A new `build_usb.sh` (or extend `build_demo_zip.sh`) that:

1. Builds the establishment Docker images if not already built
2. Runs `docker save minifw_establishment ... > images/minifw-establishment.tar`
3. Copies `docker/` subset (sme files only) to staging dir
4. Writes `demo.sh` and `README.txt`
5. Outputs a staging directory ready to `dd` or drag-and-drop onto a formatted USB

---

## Constraints

- Target: Windows WSL2 or native Linux with Docker installed
- Offline: no image pulls during demo
- Manual launch: sales person runs `bash demo.sh` from USB mount
- Not handed directly to clients
- Sector-specific: one USB per sector; this spec covers `establishment`; the same `build_usb.sh` should accept a sector argument for future sectors

---

## Out of Scope

- Autorun / autoplay
- USB formatting / OS installation
- macOS support
- Client-facing handoff packaging
