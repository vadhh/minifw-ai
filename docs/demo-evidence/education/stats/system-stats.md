# System Stats — Westgate Academy Education Demo
**Captured:** 2026-05-26  
**Package:** minifw-usb-education-v2.2.0

---

## Runtime Metrics

| Metric | Value |
|--------|-------|
| Container count | 3 (engine, web, injector) |
| CPU (idle, between events) | < 1% per container |
| RAM (RSS, all containers combined) | ~280 MB |
| Port | 8447 (HTTPS via Docker) |
| Startup time (images already loaded) | 20–35 seconds |
| Reset time (fast_reset.sh) | 30–60 seconds |

## Event Counters (after one demo loop)

| Counter | Value |
|---------|-------|
| Total events | ~12 per loop |
| Allow | ~7 per loop |
| Monitor | ~2 per loop |
| Block | 3 per loop (VPN + guest + burst) |
| False positives | 0 |

## Loop Behavior

The injector runs continuously. Each loop (~30s) replays the full sequence:
clean allows → social media monitor → VPN monitor → VPN bypass BLOCK → guest BLOCK → gambling monitor → burst BLOCK.

The demo never stops on its own — it loops until `fast_reset.sh` or `docker compose down`.

## Deployment Footprint

| Item | Value |
|------|-------|
| Docker image size | ~380 MB (minifw-education.tar) |
| Requires Docker | Yes (Docker Desktop or Docker Engine) |
| Platform | Linux, macOS, Windows (with Docker Desktop) |
| Internet access required | No |
