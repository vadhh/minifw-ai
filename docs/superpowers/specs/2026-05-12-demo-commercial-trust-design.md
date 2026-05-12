# Demo Commercial Trust — Design Spec

**Date:** 2026-05-12
**Scope:** Both USB kit types — v3 standalone (`dist/minifw-ai-usb-v2.2.0v3/`) and Docker kits (`dist/minifw-usb-hospital-v2.2.0/`, `dist/minifw-usb-education-v2.2.0/`)
**Goal:** Build commercial trust through a cleaner startup experience, automated health verification, TLS certificate trust, and a reliable live-demo recovery path.

---

## 1. Approach

Per-kit, self-contained scripts. Each kit folder contains everything a presenter needs with no external dependencies. No shared layer — Docker and standalone kits differ enough in their process model that shared logic would require conditional branching with little benefit. USB portability is preserved.

---

## 2. Startup Improvements

### v3 Standalone (`run_demo.sh`)

- Add `export PYTHONWARNINGS="ignore::UserWarning"` before engine launch to suppress sklearn `InconsistentVersionWarning` (model built on 1.5.0, running 1.5.2 — harmless but alarming to observers).
- Poll `curl -s http://localhost:8000/health` for up to 15s after uvicorn starts; print the ready banner only when the dashboard responds 200.
- Best-effort browser auto-open: `xdg-open` on Linux, `open` on macOS, after ready check.
- Clean 4-line startup output:

```
[minifw] Starting Hospital Demo...
[minifw] Engine started (PID 12345)
[minifw] Dashboard ready → http://localhost:8000  (admin / Hospital1!)
[minifw] Press Ctrl+C to stop.
```

### Docker kits (`demo.sh`)

- Pre-flight check at top of script: if Docker daemon is not running, print a clear error and `exit 1` before any compose commands.
- Use `--quiet-pull` on `docker compose up` to suppress layer pull noise in the terminal.
- Poll `curl -sk https://localhost:<port>/health` for up to 30s after `docker compose up -d`; print ready banner when dashboard responds.
- Best-effort browser auto-open after ready check.

---

## 3. `HEALTHCHECK.sh`

One script per kit, placed in the kit root. Runnable anytime — morning of demo, after setup, or when troubleshooting.

### Checks

| # | Check | v3 Standalone | Docker kit |
|---|-------|:---:|:---:|
| 1 | Python 3.10+ present | ✓ | — |
| 2 | venv activatable + `fastapi` importable | ✓ | — |
| 3 | Docker daemon running + compose available | — | ✓ |
| 4 | Required port free (8000 / 8443 / 8447) | ✓ | ✓ |
| 5 | Demo data files exist (`normal_traffic.json`, `attack_traffic.json`) | ✓ | ✓ |
| 6 | MLP model file present | ✓ | ✓ |
| 7 | YARA rules directory non-empty | ✓ | ✓ |
| 8 | Engine smoke test (5s start + kill) | ✓ | — |
| 9 | Dashboard HTTP/HTTPS 200 | ✓ | ✓ |
| 10 | TLS cert valid + trusted in OS store | — | ✓ |
| 11 | BLOCK event appears within 150s (v3) / 60s (Docker) | ✓ | ✓ |

### Runtime mode

HEALTHCHECK.sh runs in two modes depending on whether the demo is already up:

- **Pre-flight mode** (demo not running): script starts the demo internally, runs all checks, then stops it. Checks 9 and 11 use this temporary instance.
- **Live mode** (demo already running on expected port): script detects the running demo and skips the start/stop lifecycle — runs all checks against the live instance.

The script auto-detects which mode applies by checking if the port is occupied.

> Note: v3 standalone check #11 waits up to 150s because the DEMO_MODE simulator runs ~2 min of normal traffic before the attack phase fires BLOCK events. Docker injector fires from loop 1, so 60s is sufficient.

### Output

- Each check prints `[PASS]` or `[FAIL] <reason>` in real time to terminal.
- Final line: `HEALTHCHECK PASSED (11/11)` or `HEALTHCHECK FAILED (9/11) — see logs/healthcheck-2026-05-12-1430.log`
- Log file: `logs/healthcheck-YYYY-MM-DD-HHmm.log` — same lines + timestamps + stderr from failed checks.
- Exit codes: 0 = all pass, 1 = one or more failures.

---

## 4. `setup_tls.sh` (Docker kits only)

One-time per demo machine. Generates a local CA, signs a `localhost` server certificate, and installs the CA into the OS trust store so Chrome and Firefox show a green padlock.

### Steps

1. Generate local root CA (`minifw-demo-ca.key` + `minifw-demo-ca.crt`) via `openssl req`.
2. Generate server keypair + CSR for `localhost` / `127.0.0.1`.
3. Sign server cert with the CA (SAN extension: `DNS:localhost`, `IP:127.0.0.1`).
4. Install CA into OS trust store:
   - Linux: copy to `/usr/local/share/ca-certificates/minifw-demo-ca.crt` + `sudo update-ca-certificates`
   - macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain minifw-demo-ca.crt`
5. Write server cert + key to `docker/certs/` (nginx TLS config path).
6. Print: `TLS ready. Run HEALTHCHECK.sh to verify browser trust.`

### Safety

- Script detects existing CA and skips regeneration — re-running is idempotent.
- Requires `sudo` once. If unavailable, falls back to printing manual browser-override instructions.
- HEALTHCHECK check #10 verifies the cert is trusted after setup.

---

## 5. `recover_demo.sh` + `RECOVERY.md`

### `recover_demo.sh`

Automated repair sequence — run when something breaks live:

| Step | Action |
|------|--------|
| 1 | Kill stale process on demo port: `lsof -ti:<port> \| xargs kill -9` |
| 2 | Kill orphaned engine: `pgrep -f minifw_ai/main.py \| xargs kill` |
| 3 | Docker: `docker compose down --remove-orphans && docker compose up -d` |
| 4 | v3: reset DB if corrupted (`rm -f minifw.db`), relaunch engine + dashboard |
| 5 | Poll dashboard for readiness (same 15/30s timeout as startup) |
| 6 | Re-run `HEALTHCHECK.sh`, print result |

Exit: `Recovery successful — demo ready` or `Recovery failed — see RECOVERY.md Step <N>`.

### `RECOVERY.md`

Designed to be read under pressure. Structure:

```
# Demo Recovery Procedure

## 30-Second Fix (try this first)
  bash recover_demo.sh

## Manual Steps (if script fails)
  Step 1 — Kill port conflict
  Step 2 — Reset the database
  Step 3 — Rebuild Docker services
  Step 4 — Full wipe and restart

## Pre-Demo Checklist (run the morning of)
  □ Run HEALTHCHECK.sh — all checks pass
  □ Browser open to dashboard — no cert warning
  □ First BLOCK event visible
  □ Credentials confirmed: admin / Hospital1!

## Emergency Fallback
  If nothing works: screen-share a pre-recorded demo video
  Location: [to be filled in per deployment]
```

---

## 6. Files Created Per Kit

### v3 Standalone (`dist/minifw-ai-usb-v2.2.0v3/`)

| File | Change |
|------|--------|
| `run_demo.sh` | Modified — readiness poll, PYTHONWARNINGS, browser open, cleaner output |
| `HEALTHCHECK.sh` | New — 11-check verification, file log |
| `recover_demo.sh` | New — automated repair sequence |
| `RECOVERY.md` | New — human recovery narrative + pre-demo checklist |

### Docker kits (`dist/minifw-usb-hospital-v2.2.0/`, `dist/minifw-usb-education-v2.2.0/`)

| File | Change |
|------|--------|
| `demo.sh` | Modified — pre-flight Docker check, quiet pull, readiness poll, browser open |
| `HEALTHCHECK.sh` | New — 11-check verification including TLS trust, file log |
| `setup_tls.sh` | New — local CA generation + OS trust store install |
| `recover_demo.sh` | New — Docker-aware repair sequence |
| `RECOVERY.md` | New — human recovery narrative + pre-demo checklist |

---

## 7. Out of Scope

- Modifying the engine or web app source code (no changes to `app/`)
- Adding HTTPS to the v3 standalone (HTTP is intentional — no cert story needed for no-Docker demos)
- Automating Firefox trust store (Firefox uses its own store; manual instructions provided in `RECOVERY.md`)
- Production `.deb` packaging changes
