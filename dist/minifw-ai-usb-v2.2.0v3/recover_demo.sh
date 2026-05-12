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
