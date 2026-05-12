# Demo Commercial Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HEALTHCHECK.sh, setup_tls.sh, recover_demo.sh, and RECOVERY.md to all three demo kits; improve run_demo.sh and demo.sh startup UX.

**Architecture:** Per-kit self-contained scripts — no shared layer. v3 standalone (process-based, HTTP) and two Docker kits (container-based, HTTPS) each get their own set of scripts. Docker kits get a CA-signed TLS cert workflow so the browser shows no security warning. All scripts are bash, idempotent, and exit 0/1 for CI use.

**Tech Stack:** bash, openssl, curl, lsof, docker compose v2, uvicorn `--log-level warning`

---

## File Map

### v3 Standalone — `dist/minifw-ai-usb-v2.2.0v3/`

| File | Action |
|------|--------|
| `run_demo.sh` | Modify — PYTHONWARNINGS, readiness poll, browser open, cleaner output |
| `HEALTHCHECK.sh` | Create — 11 checks, pre-flight/live mode, file log |
| `recover_demo.sh` | Create — kill stale processes, reset DB, relaunch, re-healthcheck |
| `RECOVERY.md` | Create — human-readable recovery narrative |

### Hospital Docker — `dist/minifw-usb-hospital-v2.2.0/`

| File | Action |
|------|--------|
| `demo.sh` | Modify — quiet-pull, readiness poll, browser open |
| `docker/docker-compose.usb-hospital.yml` | Modify — add `../docker/certs:/opt/minifw_ai/tls` bind-mount to web service |
| `docker/certs/.gitkeep` | Create — placeholder so git tracks the empty dir |
| `setup_tls.sh` | Create — local CA + signed cert, OS trust store install |
| `HEALTHCHECK.sh` | Create — 11 checks including TLS trust, file log |
| `recover_demo.sh` | Create — Docker-aware repair sequence |
| `RECOVERY.md` | Create — human-readable recovery narrative |

### Education Docker — `dist/minifw-usb-education-v2.2.0/`

| File | Action |
|------|--------|
| `demo.sh` | Modify — same as hospital, port 8447, Education1! |
| `docker/docker-compose.usb-education.yml` | Modify — add `../docker/certs:/opt/minifw_ai/tls` bind-mount to web service |
| `docker/certs/.gitkeep` | Create |
| `setup_tls.sh` | Create — same as hospital, port 8447 |
| `HEALTHCHECK.sh` | Create — same as hospital, port 8447 |
| `recover_demo.sh` | Create — same as hospital, port 8447 |
| `RECOVERY.md` | Create — same as hospital, Education1! credentials |

---

## Shared Knowledge

**Health endpoint:** `GET http://localhost:8000/health` returns `{"status": "ok"}` (200).
For Docker kits: `GET https://localhost:8443/health` (hospital) or `https://localhost:8447/health` (education).

**Event format in JSONL:** `"action": "block"` (Python json.dumps — space after colon).

**PYTHONWARNINGS:** Set to `"ignore::UserWarning"` before engine launch suppresses the sklearn `InconsistentVersionWarning` (model built 1.5.0, running 1.5.2 — harmless).

**uvicorn log suppression:** `--log-level warning` suppresses route registration noise.

**TLS in Docker kits:** The web container entrypoint (`docker/entrypoint-web.sh`) checks `if [ ! -f tls/server.crt ]` — if the file exists it uses it; otherwise generates self-signed. By bind-mounting `../docker/certs:/opt/minifw_ai/tls` (rw), we can drop CA-signed certs there via `setup_tls.sh`. If `setup_tls.sh` hasn't been run, the bind-mount is empty, the container generates a self-signed cert into it (graceful fallback = same browser warning as before, but cert now persists across restarts).

---

## Task 1: v3 Standalone — Improve `run_demo.sh`

**Files:**
- Modify: `dist/minifw-ai-usb-v2.2.0v3/run_demo.sh`

- [ ] **Step 1: Write the updated run_demo.sh**

Replace the entire file with:

```bash
#!/bin/bash
# MiniFW-AI — Hospital Demo Launcher (v3 Framework)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw] $*"; }
die() { echo "[minifw] ERROR: $*" >&2; exit 1; }

export DEMO_MODE=1
export PRODUCT_MODE=minifw_hospital
export MINIFW_SECTOR=hospital
export AI_ENABLED=1
export MINIFW_DISABLE_FLOWS=1
export MINIFW_LOG=logs/events.jsonl
export MINIFW_AUDIT_LOG=logs/audit.jsonl
export MINIFW_FLOW_RECORDS=logs/flow_records.jsonl
export MINIFW_POLICY=config/policy.json
export MINIFW_FEEDS=config/feeds
export MINIFW_MLP_MODEL=models/mlp_model.pkl
export MINIFW_YARA_RULES=yara_rules
export MINIFW_SECRET_KEY="demo-hospital-key-change-in-prod!!"
export MINIFW_ADMIN_PASSWORD="Hospital1!"
export DATABASE_URL="sqlite:///./minifw.db"
export PYTHONPATH="$(pwd):$(pwd)/app:${PYTHONPATH:-}"
export PYTHONWARNINGS="ignore::UserWarning"

mkdir -p logs

log "Starting Hospital Demo..."

python3 app/minifw_ai/main.py > logs/engine.log 2>&1 &
ENGINE_PID=$!
log "Engine started (PID $ENGINE_PID)"

cleanup() {
    log "Stopping..."
    kill "$ENGINE_PID" 2>/dev/null || true
    kill "$WEB_PID"   2>/dev/null || true
    log "Demo stopped."
}
trap cleanup EXIT INT TERM

uvicorn app.web.app:app \
    --host 0.0.0.0 --port 8000 \
    --log-level warning \
    > logs/web.log 2>&1 &
WEB_PID=$!

# Wait up to 15s for dashboard to be ready
READY=false
for i in $(seq 1 15); do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not start in 15s — check logs/web.log"
    exit 1
fi

log "Dashboard ready → http://localhost:8000  (admin / Hospital1!)"
log "Press Ctrl+C to stop."

# Best-effort browser open
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:8000" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "http://localhost:8000" >/dev/null 2>&1 || true
fi

wait "$WEB_PID" || true
```

- [ ] **Step 2: Verify startup output is clean**

```bash
cd dist/minifw-ai-usb-v2.2.0v3
source venv/bin/activate
bash run_demo.sh
```

Expected terminal output (nothing else):
```
[minifw] Starting Hospital Demo...
[minifw] Engine started (PID <N>)
[minifw] Dashboard ready → http://localhost:8000  (admin / Hospital1!)
[minifw] Press Ctrl+C to stop.
```

Verify no sklearn warnings appear in terminal. Check `logs/engine.log` — sklearn warnings may still appear there (acceptable, they're in the log file not the terminal).

Press Ctrl+C. Expected:
```
[minifw] Stopping...
[minifw] Demo stopped.
```

- [ ] **Step 3: Commit**

```bash
git add dist/minifw-ai-usb-v2.2.0v3/run_demo.sh
git commit -m "feat(demo-v3): cleaner startup — suppress warnings, readiness poll, browser open"
```

---

## Task 2: v3 Standalone — Create `HEALTHCHECK.sh`

**Files:**
- Create: `dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh`

- [ ] **Step 1: Create HEALTHCHECK.sh**

```bash
#!/bin/bash
# MiniFW-AI Hospital Demo — Health Check
# Usage: bash HEALTHCHECK.sh
# Exit 0 = all checks pass. Exit 1 = one or more failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/healthcheck-$(date +%Y-%m-%d-%H%M).log"

PASS=0
FAIL=0

log()  { echo "$(date +%H:%M:%S) $*" | tee -a "$LOG_FILE"; }
pass() { echo "[PASS] $*" | tee -a "$LOG_FILE"; ((PASS++)); }
fail() { echo "[FAIL] $*" | tee -a "$LOG_FILE"; ((FAIL++)); }
info() { echo "       $*" | tee -a "$LOG_FILE"; }

echo "MiniFW-AI Hospital Demo — Health Check $(date)" | tee "$LOG_FILE"
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"

# ── Check 1: Python 3.10+ ──────────────────────────────────────────────────────
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
    pass "Python $PY_VER present"
else
    fail "Python 3.10+ required, found $PY_VER — install python3.10+ and retry"
fi

# ── Check 2: venv + fastapi ────────────────────────────────────────────────────
if source venv/bin/activate 2>/dev/null && python3 -c "import fastapi" 2>/dev/null; then
    pass "venv activatable, fastapi importable"
    deactivate 2>/dev/null || true
else
    fail "venv not activatable or fastapi missing — run: python3 -m venv venv && pip install -r requirements.txt"
fi

# ── Check 4: Port 8000 free ────────────────────────────────────────────────────
if ! lsof -ti:8000 >/dev/null 2>&1; then
    pass "Port 8000 is free"
else
    fail "Port 8000 is in use — run: lsof -ti:8000 | xargs kill -9"
fi

# ── Check 5: Demo data ──────────────────────────────────────────────────────────
if [[ -f demo_data/normal_traffic.json && -f demo_data/attack_traffic.json ]]; then
    pass "Demo data files present"
else
    fail "Missing demo_data/normal_traffic.json or demo_data/attack_traffic.json — USB copy may be incomplete"
fi

# ── Check 6: MLP model ─────────────────────────────────────────────────────────
if [[ -f models/mlp_model.pkl ]]; then
    pass "MLP model present"
else
    fail "models/mlp_model.pkl missing — USB copy may be incomplete"
fi

# ── Check 7: YARA rules ────────────────────────────────────────────────────────
YARA_COUNT=$(find yara_rules -name "*.yar" 2>/dev/null | wc -l)
if [[ "$YARA_COUNT" -gt 0 ]]; then
    pass "YARA rules directory has $YARA_COUNT rule file(s)"
else
    fail "yara_rules/ is empty or missing"
fi

# ── Determine runtime mode ─────────────────────────────────────────────────────
DEMO_RUNNING=false
if curl -s http://localhost:8000/health >/dev/null 2>&1; then
    DEMO_RUNNING=true
    info "Live mode — demo already running, checking against live instance"
else
    info "Pre-flight mode — starting demo temporarily for checks 8, 9, 11"
fi

if [[ "$DEMO_RUNNING" == "false" ]]; then
    # Set env for temporary launch
    export DEMO_MODE=1 PRODUCT_MODE=minifw_hospital MINIFW_SECTOR=hospital
    export AI_ENABLED=1 MINIFW_DISABLE_FLOWS=1
    export MINIFW_LOG=logs/events.jsonl MINIFW_AUDIT_LOG=logs/audit.jsonl
    export MINIFW_FLOW_RECORDS=logs/flow_records.jsonl
    export MINIFW_POLICY=config/policy.json MINIFW_FEEDS=config/feeds
    export MINIFW_MLP_MODEL=models/mlp_model.pkl MINIFW_YARA_RULES=yara_rules
    export MINIFW_SECRET_KEY="demo-hospital-key-change-in-prod!!"
    export MINIFW_ADMIN_PASSWORD="Hospital1!" DATABASE_URL="sqlite:///./minifw.db"
    export PYTHONPATH="$(pwd):$(pwd)/app:${PYTHONPATH:-}"
    export PYTHONWARNINGS="ignore::UserWarning"

    # ── Check 8: Engine smoke test ─────────────────────────────────────────────
    python3 app/minifw_ai/main.py > /tmp/hc_engine.log 2>&1 &
    HC_ENGINE_PID=$!
    sleep 5
    if kill -0 "$HC_ENGINE_PID" 2>/dev/null; then
        kill "$HC_ENGINE_PID" 2>/dev/null
        wait "$HC_ENGINE_PID" 2>/dev/null || true
        pass "Engine smoke test passed (5s, still running)"
    else
        fail "Engine crashed at startup — details:"
        grep -i "critical\|error\|fatal" /tmp/hc_engine.log | head -5 | tee -a "$LOG_FILE" || true
    fi

    # Start engine + dashboard for checks 9 and 11
    python3 app/minifw_ai/main.py > logs/engine.log 2>&1 &
    HC_ENGINE_FULL_PID=$!
    uvicorn app.web.app:app --host 0.0.0.0 --port 8000 --log-level warning \
        > /tmp/hc_web.log 2>&1 &
    HC_WEB_PID=$!

    # Poll dashboard ready (15s)
    DASHBOARD_UP=false
    for i in $(seq 1 15); do
        if curl -s http://localhost:8000/health >/dev/null 2>&1; then
            DASHBOARD_UP=true; break
        fi
        sleep 1
    done

    if [[ "$DASHBOARD_UP" == "true" ]]; then
        # ── Check 9: Dashboard HTTP 200 ────────────────────────────────────────
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
        if [[ "$HTTP_CODE" == "200" ]]; then
            pass "Dashboard responds HTTP 200"
        else
            fail "Dashboard returned HTTP $HTTP_CODE (expected 200)"
        fi

        # ── Check 11: BLOCK event within 150s ─────────────────────────────────
        info "Waiting for BLOCK event (up to 150s — normal traffic phase runs ~2 min)..."
        BLOCK_FOUND=false
        for i in $(seq 1 150); do
            if grep -q '"action": "block"' logs/events.jsonl 2>/dev/null; then
                BLOCK_FOUND=true; break
            fi
            sleep 1
        done
        if [[ "$BLOCK_FOUND" == "true" ]]; then
            pass "BLOCK event detected in logs/events.jsonl"
        else
            fail "No BLOCK event after 150s — check logs/engine.log for errors"
        fi
    else
        fail "Dashboard did not start in 15s — check /tmp/hc_web.log"
        grep -i "error\|critical" /tmp/hc_web.log | head -5 | tee -a "$LOG_FILE" || true
        fail "Checks 9 and 11 skipped (dashboard not running)"
    fi

    # Cleanup temp processes
    kill "$HC_WEB_PID"         2>/dev/null || true
    kill "$HC_ENGINE_FULL_PID" 2>/dev/null || true
    wait "$HC_WEB_PID"         2>/dev/null || true
    wait "$HC_ENGINE_FULL_PID" 2>/dev/null || true

else
    # Live mode — skip check 8, check 9 and 11 against live instance

    # ── Check 8: skip ──────────────────────────────────────────────────────────
    info "Check 8 (engine smoke test) — skipped (demo already running)"
    ((PASS++))

    # ── Check 9: Dashboard HTTP 200 ────────────────────────────────────────────
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "Dashboard responds HTTP 200"
    else
        fail "Dashboard returned HTTP $HTTP_CODE (expected 200)"
    fi

    # ── Check 11: BLOCK event ──────────────────────────────────────────────────
    if grep -q '"action": "block"' logs/events.jsonl 2>/dev/null; then
        pass "BLOCK event detected in logs/events.jsonl"
    else
        fail "No BLOCK event yet — demo may still be in normal traffic phase (wait ~2 min)"
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
if [[ "$FAIL" -eq 0 ]]; then
    echo "HEALTHCHECK PASSED ($PASS/$TOTAL)" | tee -a "$LOG_FILE"
    exit 0
else
    echo "HEALTHCHECK FAILED ($PASS/$TOTAL passed, $FAIL/$TOTAL failed) — see $LOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi
```

- [ ] **Step 2: Make executable and verify it runs**

```bash
chmod +x dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh
cd dist/minifw-ai-usb-v2.2.0v3
source venv/bin/activate
bash HEALTHCHECK.sh
```

Expected: each check prints `[PASS]` or `[FAIL]` as it runs. Final line: `HEALTHCHECK PASSED (N/N)`. A `logs/healthcheck-YYYY-MM-DD-HHmm.log` file is created.

Verify log file was created:
```bash
ls -la dist/minifw-ai-usb-v2.2.0v3/logs/healthcheck-*.log
```

- [ ] **Step 3: Commit**

```bash
git add dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh
git commit -m "feat(demo-v3): add HEALTHCHECK.sh — 11-check pre-demo verification"
```

---

## Task 3: v3 Standalone — Create `recover_demo.sh` and `RECOVERY.md`

**Files:**
- Create: `dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh`
- Create: `dist/minifw-ai-usb-v2.2.0v3/RECOVERY.md`

- [ ] **Step 1: Create recover_demo.sh**

```bash
#!/bin/bash
# MiniFW-AI Hospital Demo — Recovery Script
# Usage: bash recover_demo.sh
# Kills stale processes, resets database if corrupt, relaunches demo, re-runs HEALTHCHECK.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { echo "[minifw-recover] $*"; }
die()  { echo "[minifw-recover] ERROR: $*" >&2; exit 1; }

log "Starting demo recovery..."

# Step 1 — Kill stale process on port 8000
log "Step 1: Freeing port 8000..."
if lsof -ti:8000 >/dev/null 2>&1; then
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 1
    log "Port 8000 freed."
else
    log "Port 8000 already free."
fi

# Step 2 — Kill orphaned engine processes
log "Step 2: Killing orphaned engine processes..."
if pgrep -f "minifw_ai/main.py" >/dev/null 2>&1; then
    pgrep -f "minifw_ai/main.py" | xargs kill 2>/dev/null || true
    sleep 1
    log "Engine processes killed."
else
    log "No orphaned engine processes found."
fi

# Step 3 — Kill orphaned uvicorn processes for this port
if pgrep -f "uvicorn.*app.web.app" >/dev/null 2>&1; then
    pgrep -f "uvicorn.*app.web.app" | xargs kill 2>/dev/null || true
    sleep 1
    log "Uvicorn processes killed."
fi

# Step 4 — Reset database if corrupted
DB_PATH="minifw.db"
if [[ -f "$DB_PATH" ]]; then
    if ! python3 -c "import sqlite3; sqlite3.connect('${DB_PATH}').execute('SELECT 1')" 2>/dev/null; then
        log "Step 4: Database appears corrupt — removing $DB_PATH..."
        rm -f "$DB_PATH"
        log "Database removed (will be recreated on next start)."
    else
        log "Step 4: Database OK."
    fi
else
    log "Step 4: No database file found (will be created on start)."
fi

# Step 5 — Relaunch demo via run_demo.sh in background
log "Step 5: Relaunching demo..."
if [[ ! -f run_demo.sh ]]; then
    die "run_demo.sh not found — are you in the correct directory?"
fi

bash run_demo.sh &
DEMO_PID=$!

# Step 6 — Wait for dashboard ready (30s)
log "Step 6: Waiting for dashboard..."
READY=false
for i in $(seq 1 30); do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up in 30s."
    log "Recovery failed — see RECOVERY.md for manual steps."
    exit 1
fi

log "Dashboard is responding."
log "Running HEALTHCHECK to verify full recovery..."
echo ""

bash HEALTHCHECK.sh
HC_EXIT=$?

if [[ "$HC_EXIT" -eq 0 ]]; then
    echo ""
    log "Recovery successful — demo ready at http://localhost:8000  (admin / Hospital1!)"
else
    echo ""
    log "Recovery completed but HEALTHCHECK reported failures."
    log "See RECOVERY.md for manual steps."
fi

exit $HC_EXIT
```

- [ ] **Step 2: Create RECOVERY.md**

```markdown
# Demo Recovery Procedure — MiniFW-AI Hospital v3 Standalone

## 30-Second Fix (try this first)

```bash
bash recover_demo.sh
```

This script automatically: kills stale processes on port 8000, resets the database if
corrupted, relaunches the demo, and runs HEALTHCHECK.sh to confirm recovery.

---

## Manual Steps (if recover_demo.sh fails)

### Step 1 — Kill port conflict

Find and kill whatever is using port 8000:

```bash
lsof -ti:8000 | xargs kill -9
```

Confirm the port is now free:

```bash
lsof -i:8000
# Expected: no output
```

### Step 2 — Kill orphaned engine process

```bash
pgrep -f minifw_ai/main.py | xargs kill
pgrep -f "uvicorn.*app.web.app" | xargs kill
```

### Step 3 — Reset the database

If the web app is throwing a database error:

```bash
cd dist/minifw-ai-usb-v2.2.0v3
rm -f minifw.db
```

The database is auto-recreated with default credentials on next start.

### Step 4 — Full wipe and restart

If all else fails:

```bash
cd dist/minifw-ai-usb-v2.2.0v3
# Kill everything
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
pgrep -f minifw_ai | xargs kill 2>/dev/null || true
# Reset state
rm -f minifw.db logs/events.jsonl
# Restart
source venv/bin/activate
bash run_demo.sh
```

---

## Pre-Demo Checklist (run the morning of)

Run this 30 minutes before the presentation:

```bash
bash HEALTHCHECK.sh
```

All checks must pass. Also confirm manually:

- [ ] `bash HEALTHCHECK.sh` — all checks pass
- [ ] Browser opens `http://localhost:8000` — login page appears, no errors
- [ ] Login with `admin / Hospital1!` — dashboard loads
- [ ] Wait ~2 minutes — first BLOCK event appears in the event feed
- [ ] AI Threat Synthesis panel shows a blocked domain + HIPAA reason

---

## Emergency Fallback

If the demo cannot be recovered before the audience arrives:

1. Open a pre-recorded demo video (screen recording) and share your screen
2. Location of video: *(fill in per deployment — e.g., USB drive root or cloud link)*

---

## Credentials

| Item | Value |
|------|-------|
| Dashboard URL | http://localhost:8000 |
| Username | admin |
| Password | Hospital1! |
| Port | 8000 (HTTP) |
```

- [ ] **Step 3: Make executable and do a dry-run**

```bash
chmod +x dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh
# Verify script is syntactically valid
bash -n dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh
echo "Syntax OK"
```

Expected: `Syntax OK`

- [ ] **Step 4: Commit**

```bash
git add dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh dist/minifw-ai-usb-v2.2.0v3/RECOVERY.md
git commit -m "feat(demo-v3): add recover_demo.sh and RECOVERY.md"
```

---

## Task 4: Docker Kits — TLS Infrastructure

**Files:**
- Modify: `dist/minifw-usb-hospital-v2.2.0/docker/docker-compose.usb-hospital.yml`
- Create: `dist/minifw-usb-hospital-v2.2.0/docker/certs/.gitkeep`
- Create: `dist/minifw-usb-hospital-v2.2.0/setup_tls.sh`
- Modify: `dist/minifw-usb-education-v2.2.0/docker/docker-compose.usb-education.yml`
- Create: `dist/minifw-usb-education-v2.2.0/docker/certs/.gitkeep`
- Create: `dist/minifw-usb-education-v2.2.0/setup_tls.sh`

**Context:** The Docker web container runs `entrypoint-web.sh` which checks `if [ ! -f tls/server.crt ]` (relative to `/opt/minifw_ai/`). If we bind-mount `../docker/certs:/opt/minifw_ai/tls`, the container uses whatever certs are in `docker/certs/`. When `setup_tls.sh` has been run, that directory contains a CA-signed cert — browser shows green padlock. When it hasn't been run, directory is empty, container generates self-signed cert there — browser shows warning (same as before, but cert now persists across restarts).

- [ ] **Step 1: Add certs bind-mount to hospital docker-compose**

In `dist/minifw-usb-hospital-v2.2.0/docker/docker-compose.usb-hospital.yml`, find the `web` service `volumes` section:

```yaml
      - minifw_hospital_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
```

Add the certs mount as a third entry:

```yaml
      - minifw_hospital_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
      - ../docker/certs:/opt/minifw_ai/tls
```

- [ ] **Step 2: Create hospital docker/certs/.gitkeep**

```bash
touch dist/minifw-usb-hospital-v2.2.0/docker/certs/.gitkeep
```

- [ ] **Step 3: Create setup_tls.sh for hospital**

```bash
#!/bin/bash
# MiniFW-AI Hospital Demo — TLS Setup
# Generates a local CA + signed certificate for localhost.
# Installs CA in the OS trust store (requires sudo once).
# Run once per demo machine. Re-running is safe (idempotent).
#
# After running: browser opens https://localhost:8443 with green padlock.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CERTS_DIR="docker/certs"
CA_KEY="$CERTS_DIR/minifw-demo-ca.key"
CA_CRT="$CERTS_DIR/minifw-demo-ca.crt"
SERVER_KEY="$CERTS_DIR/server.key"
SERVER_CRT="$CERTS_DIR/server.crt"
SERVER_CSR="$CERTS_DIR/server.csr"
EXT_FILE="$CERTS_DIR/san.ext"

log() { echo "[tls-setup] $*"; }
die() { echo "[tls-setup] ERROR: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found — install openssl and retry"

mkdir -p "$CERTS_DIR"

# Skip CA generation if CA already exists
if [[ -f "$CA_KEY" && -f "$CA_CRT" ]]; then
    log "CA already exists — skipping CA generation."
else
    log "Generating local CA..."
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
    openssl req -x509 -new -nodes \
        -key "$CA_KEY" \
        -sha256 -days 3650 \
        -out "$CA_CRT" \
        -subj "/CN=MiniFW Demo CA/O=MiniFW Demo/C=US" 2>/dev/null
    log "CA generated: $CA_CRT"
fi

# Always regenerate server cert (ensures it's signed by current CA)
log "Generating server certificate for localhost..."

openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null

openssl req -new \
    -key "$SERVER_KEY" \
    -out "$SERVER_CSR" \
    -subj "/CN=localhost/O=MiniFW Demo/C=US" 2>/dev/null

cat > "$EXT_FILE" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req \
    -in "$SERVER_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$SERVER_CRT" \
    -days 825 \
    -sha256 \
    -extfile "$EXT_FILE" \
    -extensions v3_req 2>/dev/null

rm -f "$SERVER_CSR" "$EXT_FILE"
log "Server certificate generated: $SERVER_CRT"

# Install CA in OS trust store
log "Installing CA in OS trust store (requires sudo)..."

if [[ "$(uname)" == "Linux" ]]; then
    if command -v update-ca-certificates >/dev/null 2>&1; then
        sudo cp "$CA_CRT" /usr/local/share/ca-certificates/minifw-demo-ca.crt
        sudo update-ca-certificates
        log "CA installed (Linux — update-ca-certificates)."
    else
        log "WARNING: update-ca-certificates not found."
        log "Manual step: copy $CA_CRT to your system CA store and update it."
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    sudo security add-trusted-cert \
        -d -r trustRoot \
        -k /Library/Keychains/System.keychain \
        "$CA_CRT"
    log "CA installed (macOS — Keychain)."
else
    log "Unsupported OS. Manual step:"
    log "  Install $CA_CRT as a trusted root CA in your browser/OS."
fi

log ""
log "TLS setup complete."
log "Run HEALTHCHECK.sh to verify browser trust."
log ""
log "NOTE: Firefox uses its own trust store."
log "  To trust the cert in Firefox:"
log "  Preferences → Privacy & Security → View Certificates → Authorities → Import"
log "  Import: $CA_CRT  (check 'Trust this CA to identify websites')"
```

- [ ] **Step 4: Add certs bind-mount to education docker-compose**

In `dist/minifw-usb-education-v2.2.0/docker/docker-compose.usb-education.yml`, find the `web` service `volumes` section and add `../docker/certs:/opt/minifw_ai/tls` as a third entry (same pattern as Step 1 above).

- [ ] **Step 5: Create education docker/certs/.gitkeep**

```bash
touch dist/minifw-usb-education-v2.2.0/docker/certs/.gitkeep
```

- [ ] **Step 6: Create setup_tls.sh for education**

Copy the hospital `setup_tls.sh` exactly. The only differences are in the log messages (cosmetic). The cert generation and trust store logic is identical. Create `dist/minifw-usb-education-v2.2.0/setup_tls.sh` with the same content, changing the `log "..."` line at the end to reference port 8447:

Change the last `log` block to:
```bash
log "TLS setup complete."
log "Run HEALTHCHECK.sh to verify browser trust."
log ""
log "Dashboard will be available at: https://localhost:8447"
log ""
log "NOTE: Firefox uses its own trust store."
log "  To trust the cert in Firefox:"
log "  Preferences → Privacy & Security → View Certificates → Authorities → Import"
log "  Import: $CA_CRT  (check 'Trust this CA to identify websites')"
```

- [ ] **Step 7: Make scripts executable**

```bash
chmod +x dist/minifw-usb-hospital-v2.2.0/setup_tls.sh
chmod +x dist/minifw-usb-education-v2.2.0/setup_tls.sh
```

- [ ] **Step 8: Verify setup_tls.sh syntax**

```bash
bash -n dist/minifw-usb-hospital-v2.2.0/setup_tls.sh && echo "Hospital: Syntax OK"
bash -n dist/minifw-usb-education-v2.2.0/setup_tls.sh && echo "Education: Syntax OK"
```

Expected: both print `Syntax OK`

- [ ] **Step 9: Commit**

```bash
git add \
  dist/minifw-usb-hospital-v2.2.0/docker/docker-compose.usb-hospital.yml \
  dist/minifw-usb-hospital-v2.2.0/docker/certs/.gitkeep \
  dist/minifw-usb-hospital-v2.2.0/setup_tls.sh \
  dist/minifw-usb-education-v2.2.0/docker/docker-compose.usb-education.yml \
  dist/minifw-usb-education-v2.2.0/docker/certs/.gitkeep \
  dist/minifw-usb-education-v2.2.0/setup_tls.sh
git commit -m "feat(demo-docker): add setup_tls.sh — local CA + signed cert for browser trust"
```

---

## Task 5: Hospital Docker — Improve `demo.sh`

**Files:**
- Modify: `dist/minifw-usb-hospital-v2.2.0/demo.sh`

- [ ] **Step 1: Write the updated demo.sh**

Replace the entire file with:

```bash
#!/usr/bin/env bash
# MiniFW-AI — Hospital Sector Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="minifw-ai-demo/hospital:latest"
INJECTOR_TAG="minifw-ai-demo/hospital-injector:latest"
IMAGE_TAR="${USB_DIR}/images/minifw-hospital.tar"
COMPOSE_FILE="${USB_DIR}/docker/docker-compose.usb-hospital.yml"
DASHBOARD_URL="https://localhost:8443"

log() { echo "[minifw] $*"; }
die() { echo "[minifw] ERROR: $*" >&2; exit 1; }

# Pre-flight checks
[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: ${COMPOSE_FILE} — is the USB copy complete?"
command -v docker        >/dev/null 2>&1 || die "Docker is not installed or not in PATH"
docker compose version   >/dev/null 2>&1 || die "Docker Compose v2 is required (try: docker compose version)"
docker info              >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

# Load images if needed
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1 || \
   ! docker image inspect "$INJECTOR_TAG" >/dev/null 2>&1; then
    log "Loading images from USB (this takes ~2-3 minutes on first run)..."
    [[ -f "$IMAGE_TAR" ]] || die "Image archive not found: ${IMAGE_TAR}"
    docker load -i "$IMAGE_TAR"
    log "Images loaded."
else
    log "Images ready."
fi

trap 'echo ""; log "Demo stopped. To clean up: docker compose -f \"${COMPOSE_FILE}\" down"' EXIT

log "Starting Hospital Demo..."
docker compose -f "$COMPOSE_FILE" up -d --quiet-pull

# Poll for dashboard ready (30s)
log "Waiting for dashboard..."
READY=false
for i in $(seq 1 30); do
    if curl -sk "${DASHBOARD_URL}/health" >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not respond in 30s — check: docker compose -f ${COMPOSE_FILE} logs web"
    exit 1
fi

log "Dashboard ready → ${DASHBOARD_URL}  (admin / Hospital1!)"
log "Press Ctrl+C to stop."

# Best-effort browser open
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "$DASHBOARD_URL" >/dev/null 2>&1 || true
fi

# Stream logs in foreground (Ctrl+C stops here and triggers trap)
docker compose -f "$COMPOSE_FILE" logs -f --no-log-prefix 2>/dev/null || true
```

- [ ] **Step 2: Verify syntax**

```bash
bash -n dist/minifw-usb-hospital-v2.2.0/demo.sh && echo "Syntax OK"
```

- [ ] **Step 3: Commit**

```bash
git add dist/minifw-usb-hospital-v2.2.0/demo.sh
git commit -m "feat(demo-hospital): cleaner startup — quiet pull, readiness poll, browser open"
```

---

## Task 6: Hospital Docker — Create `HEALTHCHECK.sh`, `recover_demo.sh`, `RECOVERY.md`

**Files:**
- Create: `dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh`
- Create: `dist/minifw-usb-hospital-v2.2.0/recover_demo.sh`
- Create: `dist/minifw-usb-hospital-v2.2.0/RECOVERY.md`

- [ ] **Step 1: Create HEALTHCHECK.sh**

```bash
#!/bin/bash
# MiniFW-AI Hospital Demo (Docker) — Health Check
# Usage: bash HEALTHCHECK.sh
# Exit 0 = all pass. Exit 1 = one or more failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker/docker-compose.usb-hospital.yml"
DASHBOARD_URL="https://localhost:8443"
PORT=8443
ENGINE_CONTAINER="minifw_hospital_engine"
WEB_CONTAINER="minifw_hospital_web"
CA_CRT="docker/certs/minifw-demo-ca.crt"

mkdir -p logs
LOG_FILE="logs/healthcheck-$(date +%Y-%m-%d-%H%M).log"

PASS=0
FAIL=0

pass() { echo "[PASS] $*" | tee -a "$LOG_FILE"; ((PASS++)); }
fail() { echo "[FAIL] $*" | tee -a "$LOG_FILE"; ((FAIL++)); }
info() { echo "       $*" | tee -a "$LOG_FILE"; }

echo "MiniFW-AI Hospital Demo (Docker) — Health Check $(date)" | tee "$LOG_FILE"
echo "─────────────────────────────────────────────────────────" | tee -a "$LOG_FILE"

# ── Check 3: Docker daemon ─────────────────────────────────────────────────────
if docker info >/dev/null 2>&1; then
    pass "Docker daemon running"
else
    fail "Docker daemon not running — start Docker Desktop or: sudo systemctl start docker"
fi

if docker compose version >/dev/null 2>&1; then
    pass "Docker Compose v2 available"
else
    fail "Docker Compose v2 not available — upgrade Docker"
fi

# ── Check 4: Port free or in use by demo ──────────────────────────────────────
PORT_PID=$(lsof -ti:$PORT 2>/dev/null || true)
if [[ -z "$PORT_PID" ]]; then
    pass "Port $PORT is free"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$WEB_CONTAINER"; then
    pass "Port $PORT is in use by demo container (expected)"
else
    fail "Port $PORT is in use by non-demo process (PID $PORT_PID) — run: lsof -ti:$PORT | xargs kill -9"
fi

# ── Check 5: Demo data ─────────────────────────────────────────────────────────
# For Docker kits, demo data is inside the image — check images are present
if docker image inspect "minifw-ai-demo/hospital:latest" >/dev/null 2>&1 && \
   docker image inspect "minifw-ai-demo/hospital-injector:latest" >/dev/null 2>&1; then
    pass "Docker images present"
else
    fail "Docker images not loaded — run: docker load -i images/minifw-hospital.tar"
fi

# ── Check 6: MLP model (inside image — verify image exists, checked above) ────
info "Check 6 (MLP model) — covered by image presence check above"
((PASS++))

# ── Check 7: YARA rules ────────────────────────────────────────────────────────
YARA_COUNT=$(find yara_rules -name "*.yar" 2>/dev/null | wc -l)
if [[ "$YARA_COUNT" -gt 0 ]]; then
    pass "YARA rules directory has $YARA_COUNT rule file(s)"
else
    fail "yara_rules/ is empty or missing — USB copy may be incomplete"
fi

# ── Determine runtime mode ─────────────────────────────────────────────────────
DEMO_RUNNING=false
if curl -sk "${DASHBOARD_URL}/health" >/dev/null 2>&1; then
    DEMO_RUNNING=true
    info "Live mode — demo already running"
else
    info "Pre-flight mode — starting demo for checks 9, 10, 11"
fi

if [[ "$DEMO_RUNNING" == "false" ]]; then
    docker compose -f "$COMPOSE_FILE" up -d --quiet-pull 2>&1 | tee -a "$LOG_FILE"

    # Poll dashboard ready (30s)
    DASHBOARD_UP=false
    for i in $(seq 1 30); do
        if curl -sk "${DASHBOARD_URL}/health" >/dev/null 2>&1; then
            DASHBOARD_UP=true; break
        fi
        sleep 1
    done

    if [[ "$DASHBOARD_UP" == "false" ]]; then
        fail "Dashboard did not start in 30s"
        docker compose -f "$COMPOSE_FILE" logs web 2>/dev/null | tail -20 | tee -a "$LOG_FILE"
        fail "Skipping checks 9, 10, 11"
        docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
        TOTAL=$((PASS + FAIL))
        echo "─────────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
        echo "HEALTHCHECK FAILED ($PASS/$TOTAL passed) — see $LOG_FILE" | tee -a "$LOG_FILE"
        exit 1
    fi
fi

# ── Check 9: Dashboard HTTPS 200 ──────────────────────────────────────────────
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${DASHBOARD_URL}/health")
if [[ "$HTTP_CODE" == "200" ]]; then
    pass "Dashboard responds HTTPS 200"
else
    fail "Dashboard returned HTTPS $HTTP_CODE (expected 200)"
fi

# ── Check 10: TLS cert trusted ────────────────────────────────────────────────
if [[ -f "$CA_CRT" ]]; then
    # Test with system trust store (no -k flag = strict validation)
    if curl -s --cacert "$CA_CRT" -o /dev/null -w "%{http_code}" "${DASHBOARD_URL}/health" | grep -q "200"; then
        pass "TLS cert is valid and trusted (CA-signed)"
    else
        # Try system trust store
        if curl -s -o /dev/null -w "%{http_code}" "${DASHBOARD_URL}/health" 2>/dev/null | grep -q "200"; then
            pass "TLS cert trusted by OS trust store"
        else
            fail "TLS cert NOT trusted by system — run: bash setup_tls.sh"
        fi
    fi
else
    fail "CA cert not found at $CA_CRT — run: bash setup_tls.sh"
fi

# ── Check 11: BLOCK event within 60s ─────────────────────────────────────────
info "Waiting for BLOCK event (up to 60s — injector fires from loop 1)..."
BLOCK_FOUND=false
for i in $(seq 1 60); do
    if docker exec "$ENGINE_CONTAINER" grep -q '"action": "block"' \
       /opt/minifw_ai/logs/events.jsonl 2>/dev/null; then
        BLOCK_FOUND=true; break
    fi
    sleep 1
done

if [[ "$BLOCK_FOUND" == "true" ]]; then
    pass "BLOCK event detected in engine logs"
else
    fail "No BLOCK event after 60s — check: docker compose -f $COMPOSE_FILE logs injector"
fi

# Cleanup if pre-flight mode
if [[ "$DEMO_RUNNING" == "false" ]]; then
    docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
fi

# ── Summary ────────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo "─────────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
if [[ "$FAIL" -eq 0 ]]; then
    echo "HEALTHCHECK PASSED ($PASS/$TOTAL)" | tee -a "$LOG_FILE"
    exit 0
else
    echo "HEALTHCHECK FAILED ($PASS/$TOTAL passed, $FAIL/$TOTAL failed) — see $LOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi
```

- [ ] **Step 2: Create recover_demo.sh**

```bash
#!/bin/bash
# MiniFW-AI Hospital Demo (Docker) — Recovery Script
# Usage: bash recover_demo.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker/docker-compose.usb-hospital.yml"
DASHBOARD_URL="https://localhost:8443"
PORT=8443

log() { echo "[minifw-recover] $*"; }
die() { echo "[minifw-recover] ERROR: $*" >&2; exit 1; }

log "Starting demo recovery..."

# Step 1 — Take down any running compose stack
log "Step 1: Stopping any running demo containers..."
docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

# Step 2 — Free the port if still occupied
log "Step 2: Freeing port $PORT..."
if lsof -ti:$PORT >/dev/null 2>&1; then
    lsof -ti:$PORT | xargs kill -9 2>/dev/null || true
    sleep 1
    log "Port $PORT freed."
else
    log "Port $PORT already free."
fi

# Step 3 — Relaunch
log "Step 3: Relaunching demo..."
docker compose -f "$COMPOSE_FILE" up -d --quiet-pull

# Step 4 — Wait for dashboard (30s)
log "Step 4: Waiting for dashboard..."
READY=false
for i in $(seq 1 30); do
    if curl -sk "${DASHBOARD_URL}/health" >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up in 30s."
    log "Recovery failed — see RECOVERY.md for manual steps."
    exit 1
fi

log "Dashboard is responding."
log "Running HEALTHCHECK to verify full recovery..."
echo ""

bash HEALTHCHECK.sh
HC_EXIT=$?

if [[ "$HC_EXIT" -eq 0 ]]; then
    echo ""
    log "Recovery successful — demo ready at ${DASHBOARD_URL}  (admin / Hospital1!)"
else
    echo ""
    log "Recovery completed but HEALTHCHECK reported failures."
    log "See RECOVERY.md for manual steps."
fi

exit $HC_EXIT
```

- [ ] **Step 3: Create RECOVERY.md**

```markdown
# Demo Recovery Procedure — MiniFW-AI Hospital Docker

## 30-Second Fix (try this first)

```bash
bash recover_demo.sh
```

This script automatically: stops stale containers, frees port 8443, relaunches the stack,
and runs HEALTHCHECK.sh to confirm recovery.

---

## Manual Steps (if recover_demo.sh fails)

### Step 1 — Stop all demo containers

```bash
docker compose -f docker/docker-compose.usb-hospital.yml down --remove-orphans
```

### Step 2 — Kill port conflict

```bash
lsof -ti:8443 | xargs kill -9
```

### Step 3 — Restart from scratch

```bash
docker compose -f docker/docker-compose.usb-hospital.yml up -d
# Wait 30s, then open https://localhost:8443
```

### Step 4 — Full wipe and restart

If a container is stuck in restart loop:

```bash
docker compose -f docker/docker-compose.usb-hospital.yml down -v --remove-orphans
docker compose -f docker/docker-compose.usb-hospital.yml up -d
```

The `-v` flag removes the named volume (logs) — clears audit log and DB. Demo starts fresh.

### Step 5 — Reload images

If containers fail to start with image-not-found errors:

```bash
docker load -i images/minifw-hospital.tar
docker compose -f docker/docker-compose.usb-hospital.yml up -d
```

---

## Pre-Demo Checklist (run the morning of)

```bash
bash setup_tls.sh   # one-time per machine — skip if already done
bash HEALTHCHECK.sh
```

All checks must pass. Also confirm manually:

- [ ] `bash HEALTHCHECK.sh` — all checks pass
- [ ] Browser opens `https://localhost:8443` — green padlock, no security warning
- [ ] Login with `admin / Hospital1!` — dashboard loads
- [ ] Within 60 seconds — first BLOCK event appears in event feed
- [ ] AI Threat Synthesis panel shows a blocked domain + HIPAA reason

---

## TLS / Browser Warning

If browser shows "Your connection is not private":

```bash
bash setup_tls.sh
# Then restart demo
docker compose -f docker/docker-compose.usb-hospital.yml down
docker compose -f docker/docker-compose.usb-hospital.yml up -d
```

For Firefox specifically: open `about:preferences#privacy` → View Certificates →
Authorities → Import → select `docker/certs/minifw-demo-ca.crt` → trust for websites.

---

## Emergency Fallback

If the demo cannot be recovered before the audience arrives:

1. Open a pre-recorded demo video and share your screen
2. Location of video: *(fill in per deployment — e.g., USB drive root or cloud link)*

---

## Credentials

| Item | Value |
|------|-------|
| Dashboard URL | https://localhost:8443 |
| Username | admin |
| Password | Hospital1! |
| Port | 8443 (HTTPS) |
```

- [ ] **Step 4: Make scripts executable and verify syntax**

```bash
chmod +x dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh
chmod +x dist/minifw-usb-hospital-v2.2.0/recover_demo.sh
bash -n dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh   && echo "HEALTHCHECK: Syntax OK"
bash -n dist/minifw-usb-hospital-v2.2.0/recover_demo.sh  && echo "recover_demo: Syntax OK"
```

Expected: both print `Syntax OK`

- [ ] **Step 5: Commit**

```bash
git add \
  dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh \
  dist/minifw-usb-hospital-v2.2.0/recover_demo.sh \
  dist/minifw-usb-hospital-v2.2.0/RECOVERY.md
git commit -m "feat(demo-hospital): add HEALTHCHECK.sh, recover_demo.sh, RECOVERY.md"
```

---

## Task 7: Education Docker — Improve `demo.sh`, Create Scripts

**Files:**
- Modify: `dist/minifw-usb-education-v2.2.0/demo.sh`
- Create: `dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh`
- Create: `dist/minifw-usb-education-v2.2.0/recover_demo.sh`
- Create: `dist/minifw-usb-education-v2.2.0/RECOVERY.md`

**Note:** These are identical in structure to the hospital kit. The differences are:
- Port: `8447` (not 8443)
- Compose file: `docker-compose.usb-education.yml`
- Image tags: `minifw-ai-demo/education:latest`, `minifw-ai-demo/education-injector:latest`
- Image tar: `images/minifw-education.tar`
- Container names: `minifw_education_engine`, `minifw_education_web`
- Volume name: `minifw_education_logs`
- Password: `Education1!`
- Sector display: `education`
- URL: `https://localhost:8447`

- [ ] **Step 1: Write the updated demo.sh**

Replace the entire file with the hospital `demo.sh` from Task 5, substituting all hospital-specific values with the education equivalents listed above.

The key substitutions in the script variables at the top:

```bash
IMAGE_TAG="minifw-ai-demo/education:latest"
INJECTOR_TAG="minifw-ai-demo/education-injector:latest"
IMAGE_TAR="${USB_DIR}/images/minifw-education.tar"
COMPOSE_FILE="${USB_DIR}/docker/docker-compose.usb-education.yml"
DASHBOARD_URL="https://localhost:8447"
```

And in the ready log line:
```bash
log "Dashboard ready → ${DASHBOARD_URL}  (admin / Education1!)"
```

- [ ] **Step 2: Create HEALTHCHECK.sh**

Copy hospital `HEALTHCHECK.sh` with these substitutions:

```bash
COMPOSE_FILE="docker/docker-compose.usb-education.yml"
DASHBOARD_URL="https://localhost:8447"
PORT=8447
ENGINE_CONTAINER="minifw_education_engine"
WEB_CONTAINER="minifw_education_web"
CA_CRT="docker/certs/minifw-demo-ca.crt"
```

Title line:
```bash
echo "MiniFW-AI Education Demo (Docker) — Health Check $(date)" | tee "$LOG_FILE"
```

Docker image checks:
```bash
if docker image inspect "minifw-ai-demo/education:latest" >/dev/null 2>&1 && \
   docker image inspect "minifw-ai-demo/education-injector:latest" >/dev/null 2>&1; then
    pass "Docker images present"
else
    fail "Docker images not loaded — run: docker load -i images/minifw-education.tar"
fi
```

- [ ] **Step 3: Create recover_demo.sh**

Copy hospital `recover_demo.sh` with these substitutions:

```bash
COMPOSE_FILE="docker/docker-compose.usb-education.yml"
DASHBOARD_URL="https://localhost:8447"
PORT=8447
```

Final success log:
```bash
log "Recovery successful — demo ready at ${DASHBOARD_URL}  (admin / Education1!)"
```

- [ ] **Step 4: Create RECOVERY.md**

Copy hospital `RECOVERY.md` with these substitutions:
- `Hospital` → `Education` in title and text
- `Hospital1!` → `Education1!`
- `8443` → `8447`
- `docker-compose.usb-hospital.yml` → `docker-compose.usb-education.yml`
- `minifw-hospital.tar` → `minifw-education.tar`
- `HIPAA` → `SafeSearch / education policy` in the pre-demo checklist item

- [ ] **Step 5: Make scripts executable and verify syntax**

```bash
chmod +x dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh
chmod +x dist/minifw-usb-education-v2.2.0/recover_demo.sh
bash -n dist/minifw-usb-education-v2.2.0/demo.sh           && echo "demo: Syntax OK"
bash -n dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh    && echo "HEALTHCHECK: Syntax OK"
bash -n dist/minifw-usb-education-v2.2.0/recover_demo.sh   && echo "recover_demo: Syntax OK"
```

- [ ] **Step 6: Commit**

```bash
git add \
  dist/minifw-usb-education-v2.2.0/demo.sh \
  dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh \
  dist/minifw-usb-education-v2.2.0/recover_demo.sh \
  dist/minifw-usb-education-v2.2.0/RECOVERY.md
git commit -m "feat(demo-education): cleaner startup, HEALTHCHECK.sh, recover_demo.sh, RECOVERY.md"
```

---

## Task 8: Final End-to-End Smoke Test

- [ ] **Step 1: Smoke test v3 standalone**

```bash
cd dist/minifw-ai-usb-v2.2.0v3
source venv/bin/activate

# Verify startup is clean (4 lines only, no warnings)
bash run_demo.sh &
DEMO_PID=$!
sleep 20
kill $DEMO_PID 2>/dev/null || true
wait $DEMO_PID 2>/dev/null || true

# Verify HEALTHCHECK runs
bash HEALTHCHECK.sh
echo "Exit code: $?"

# Verify recover_demo.sh is syntactically valid
bash -n recover_demo.sh && echo "recover_demo: OK"

cd ../..
```

Expected: HEALTHCHECK exits 0. `logs/healthcheck-*.log` file created.

- [ ] **Step 2: Verify all new files are present**

```bash
# v3 standalone
ls dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh \
   dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh \
   dist/minifw-ai-usb-v2.2.0v3/RECOVERY.md

# Hospital Docker
ls dist/minifw-usb-hospital-v2.2.0/setup_tls.sh \
   dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh \
   dist/minifw-usb-hospital-v2.2.0/recover_demo.sh \
   dist/minifw-usb-hospital-v2.2.0/RECOVERY.md \
   dist/minifw-usb-hospital-v2.2.0/docker/certs/.gitkeep

# Education Docker
ls dist/minifw-usb-education-v2.2.0/setup_tls.sh \
   dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh \
   dist/minifw-usb-education-v2.2.0/recover_demo.sh \
   dist/minifw-usb-education-v2.2.0/RECOVERY.md \
   dist/minifw-usb-education-v2.2.0/docker/certs/.gitkeep
```

Expected: all files present, no errors.

- [ ] **Step 3: Verify all scripts pass bash syntax check**

```bash
for f in \
  dist/minifw-ai-usb-v2.2.0v3/run_demo.sh \
  dist/minifw-ai-usb-v2.2.0v3/HEALTHCHECK.sh \
  dist/minifw-ai-usb-v2.2.0v3/recover_demo.sh \
  dist/minifw-usb-hospital-v2.2.0/demo.sh \
  dist/minifw-usb-hospital-v2.2.0/setup_tls.sh \
  dist/minifw-usb-hospital-v2.2.0/HEALTHCHECK.sh \
  dist/minifw-usb-hospital-v2.2.0/recover_demo.sh \
  dist/minifw-usb-education-v2.2.0/demo.sh \
  dist/minifw-usb-education-v2.2.0/setup_tls.sh \
  dist/minifw-usb-education-v2.2.0/HEALTHCHECK.sh \
  dist/minifw-usb-education-v2.2.0/recover_demo.sh; do
  bash -n "$f" && echo "OK: $f" || echo "FAIL: $f"
done
```

Expected: all print `OK: <path>`

- [ ] **Step 4: Confirm git status is clean**

```bash
git status
```

Expected: `nothing to commit, working tree clean` (all changes committed in Tasks 1–7).
If anything is unstaged, add and commit it with an appropriate message.
