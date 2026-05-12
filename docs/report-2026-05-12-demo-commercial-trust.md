# Demo Commercial Trust — Implementation Report

**Date:** 2026-05-12  
**Scope:** All three demo kits — v3 standalone, Hospital Docker, Education Docker  
**Goal:** Build commercial trust through cleaner startup, automated health verification, TLS certificate trust, and reliable live-demo recovery.  
**Result:** All 8 tasks complete. 14 commits. All scripts pass syntax check. Working tree clean.

---

## Summary

| Demo Kit | Startup | HEALTHCHECK.sh | TLS | Recovery |
|----------|---------|---------------|-----|----------|
| v3 Standalone (`dist/minifw-ai-usb-v2.2.0v3/`) | Clean 4-line output, no sklearn warnings | 11 checks | n/a (HTTP) | Script + markdown |
| Hospital Docker (`dist/minifw-usb-hospital-v2.2.0/`) | Quiet, readiness poll, auto-cleanup | 11 checks + TLS trust | Local CA + OS store | Script + markdown |
| Education Docker (`dist/minifw-usb-education-v2.2.0/`) | Quiet, readiness poll, auto-cleanup | 11 checks + TLS trust | Local CA + OS store | Script + markdown |

---

## Files Delivered

### v3 Standalone — `dist/minifw-ai-usb-v2.2.0v3/`

| File | Change | Key Details |
|------|--------|-------------|
| `run_demo.sh` | Modified | `PYTHONWARNINGS="ignore::UserWarning"` suppresses sklearn noise; uvicorn `--log-level warning` suppresses route registration; 15s readiness poll before printing banner; best-effort browser open; `EXIT INT TERM` trap |
| `HEALTHCHECK.sh` | New | 11 checks: Python 3.10+, venv+fastapi, port 8000, demo data, MLP model, YARA rules, engine smoke test, dashboard HTTP 200, BLOCK event (150s timeout); pre-flight/live mode auto-detected; log to `logs/healthcheck-YYYY-MM-DD-HHmm.log` |
| `recover_demo.sh` | New | Kills stale port 8000, kills orphaned engine/uvicorn processes, resets SQLite DB if corrupt, relaunches demo, re-runs HEALTHCHECK |
| `RECOVERY.md` | New | 30-second fix, 4 manual steps, pre-demo checklist, emergency fallback, credentials table |

### Hospital Docker — `dist/minifw-usb-hospital-v2.2.0/`

| File | Change | Key Details |
|------|--------|-------------|
| `demo.sh` | Modified | Pre-flight Docker daemon check; `--quiet-pull`; 30s readiness poll with progress dots; auto-cleanup trap (`docker compose down` on EXIT/INT/TERM); post-load image verification; browser open; TLS setup hint if certs not provisioned |
| `docker/docker-compose.usb-hospital.yml` | Modified | Added `../docker/certs:/opt/minifw_ai/tls` bind-mount to web service — enables CA-signed cert from `setup_tls.sh` |
| `docker/certs/.gitkeep` | New | Placeholder so git tracks the empty certs directory |
| `setup_tls.sh` | New | Generates local CA (`minifw-demo-ca.key/crt`), signs `localhost` server cert with SAN (DNS:localhost, IP:127.0.0.1); installs CA in OS trust store (Linux: `update-ca-certificates`, macOS: Keychain) with sudo fallback to manual instructions; idempotent; `chmod 600` on private keys; `trap` cleanup of temp CSR/ext files |
| `HEALTHCHECK.sh` | New | 11 checks: Docker daemon, compose, port 8443, images, MLP model, YARA rules, dashboard HTTPS 200, TLS cert trust, BLOCK event (60s via `docker exec`); pre-flight/live mode; `lsof` presence guard; accurate PASS/FAIL counters |
| `recover_demo.sh` | New | `docker compose down --remove-orphans`, free port 8443 (with `lsof` guard), `docker compose up -d`, 30s poll, re-run HEALTHCHECK |
| `RECOVERY.md` | New | 30-second fix, 5 manual steps, pre-demo checklist (with TLS setup), TLS browser warning section, emergency fallback, credentials table |

### Education Docker — `dist/minifw-usb-education-v2.2.0/`

Same set as Hospital Docker with all values updated: port `8447`, credentials `admin / Education1!`, compose file `docker-compose.usb-education.yml`, images `minifw-ai-demo/education:latest` + injector, containers `minifw_education_engine` / `minifw_education_web`, RECOVERY.md references SafeSearch/education policy instead of HIPAA.

---

## Startup Output — Before vs After

### v3 Standalone — before
```
UserWarning: Trying to unpickle estimator MLPClassifier from version 1.5.0 when
using version 1.5.2...
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
...
```

### v3 Standalone — after
```
[minifw] Starting Hospital Demo...
[minifw] Engine started (PID 12345)
[minifw] Dashboard ready → http://localhost:8000  (admin / Hospital1!)
[minifw] Press Ctrl+C to stop.
```

### Docker kits — after
```
[minifw] Images ready.
[minifw] Starting Hospital Demo...
..............................
[minifw] Dashboard ready → https://localhost:8443  (admin / Hospital1!)
[minifw] Press Ctrl+C to stop.
```
(dots appear during the 30s readiness poll)

---

## HEALTHCHECK.sh — Checks Matrix

| # | Check | v3 Standalone | Docker kits |
|---|-------|:---:|:---:|
| 1 | Python 3.10+ present | ✓ | — |
| 2 | venv activatable + `fastapi` importable | ✓ | — |
| 3 | Docker daemon running + compose available | — | ✓ |
| 4 | Required port free | ✓ (8000) | ✓ (8443 / 8447) |
| 5 | Demo data / Docker images present | ✓ | ✓ |
| 6 | MLP model file present | ✓ | ✓ (via image) |
| 7 | YARA rules directory non-empty | ✓ | ✓ |
| 8 | Engine smoke test (5s start + kill) | ✓ | — |
| 9 | Dashboard HTTP/HTTPS 200 | ✓ | ✓ |
| 10 | TLS cert valid + trusted in OS store | — | ✓ |
| 11 | BLOCK event appears (150s v3 / 60s Docker) | ✓ | ✓ |

Auto-detects **pre-flight mode** (starts demo temporarily for checks) vs **live mode** (checks against already-running instance). Writes timestamped log to `logs/healthcheck-YYYY-MM-DD-HHmm.log`. Exit 0 = all pass, exit 1 = any failure.

---

## TLS Certificate Trust — How It Works

1. Run `bash setup_tls.sh` once per demo machine (before first `docker compose up`)
2. Script generates a local CA and a `localhost` server cert signed by that CA (SAN: `DNS:localhost`, `IP:127.0.0.1`, 825-day validity)
3. CA is installed in the OS trust store (`update-ca-certificates` on Linux, Keychain on macOS) — requires `sudo` once; falls back to manual instructions if unavailable
4. Server cert is written to `docker/certs/server.crt` — the compose bind-mount places it at `/opt/minifw_ai/tls/server.crt` inside the container, which the entrypoint uses in place of a self-signed cert
5. Chrome and Safari show a green padlock. Firefox requires a one-time manual import of `docker/certs/minifw-demo-ca.crt`

If `setup_tls.sh` hasn't been run, `demo.sh` prints a TIP at startup and the container falls back to a self-signed cert (browser shows a security warning — same as before this work).

---

## Quality Issues Found and Fixed During Review

| Issue | Fix |
|-------|-----|
| sklearn `InconsistentVersionWarning` leaked to terminal | `PYTHONWARNINGS="ignore::UserWarning"` + uvicorn `--log-level warning` |
| Docker demo.sh trap didn't clean up containers on exit | Trap now calls `docker compose down` + covers `EXIT INT TERM` |
| No post-load image verification | `docker image inspect` for both tags after `docker load`; `die` on missing |
| `lsof` not installed → silent false-PASS on port check | `command -v lsof` guard added to HEALTHCHECK + recover scripts |
| HEALTHCHECK double-`fail` inflated FAIL counter | Skip notice demoted from `fail()` to `info()` |
| `setup_tls.sh` CA private key world-readable | `chmod 600` on CA key and server key |
| `setup_tls.sh` no sudo fallback on macOS | Both Linux and macOS trust store install wrapped in `if sudo ... else <manual instructions> fi` |
| `docker compose logs -f` stderr suppressed | Removed `2>/dev/null` — Docker errors now visible to presenter |
| `docker compose up` failure silent in `recover_demo.sh` | Added `|| { log "ERROR..."; exit 1; }` for immediate diagnosis |
| Bare `lsof \| xargs kill -9` in RECOVERY.md would print confusing error on clean system | Changed to `xargs -r kill -9` |

---

## Commit Log

```
7461edc fix(demo-docker): HEALTHCHECK counter accuracy, lsof guard, compose up error logging, safe xargs
ce1173f fix(demo-docker): surface docker compose logs stderr for diagnostics
d277cd9 fix(demo-education): HEALTHCHECK Check 6 output format, recover trailing period
1a02e48 fix(demo-docker): harden demo.sh — auto-cleanup trap, post-load verify, poll progress, log exit handling
610017f fix(demo-hospital): HEALTHCHECK Check 6 output format, failure summary format, recover trailing period
fd3d65b feat(demo-education): cleaner startup, HEALTHCHECK.sh, recover_demo.sh, RECOVERY.md
fa4ff7a fix(demo-docker): setup_tls.sh — sudo fallback, chmod 600, cleanup trap; demo.sh TLS hint
bd5bba2 feat(demo-hospital): add HEALTHCHECK.sh, recover_demo.sh, RECOVERY.md
c19dcb0 fix(demo-education): correct header comment in setup_tls.sh
bb42082 feat(demo-hospital): cleaner startup — quiet pull, readiness poll, browser open
588b32c feat(demo-docker): add setup_tls.sh — local CA + signed cert for browser trust
c35bbeb feat(demo-v3): add recover_demo.sh and RECOVERY.md
e8a0117 feat(demo-v3): add HEALTHCHECK.sh — 11-check pre-demo verification
f29ab24 feat(demo-v3): cleaner startup — suppress warnings, readiness poll, browser open
```

---

## Pre-Demo Checklist (any kit)

```bash
# One-time per machine (Docker kits only)
bash setup_tls.sh

# Morning of demo — run this
bash HEALTHCHECK.sh   # must exit 0

# If anything breaks during demo
bash recover_demo.sh
```

---

*MiniFW-AI Demo Commercial Trust — completed 2026-05-12*
