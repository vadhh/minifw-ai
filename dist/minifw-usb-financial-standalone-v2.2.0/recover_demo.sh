#!/bin/bash
# MiniFW-AI Financial Demo — Recovery Script
# Kills stale processes, resets database if corrupt, relaunches demo.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-recover] $*"; }
die() { echo "[minifw-recover] ERROR: $*" >&2; exit 1; }

log "Starting demo recovery..."

log "Step 1: Freeing port 8443..."
if lsof -ti:8443 >/dev/null 2>&1; then
    lsof -ti:8443 | xargs kill -9 2>/dev/null || true
    sleep 1
    log "Port 8443 freed."
else
    log "Port 8443 already free."
fi

log "Step 2: Killing orphaned engine processes..."
if pgrep -f "minifw_ai/main.py" >/dev/null 2>&1; then
    pgrep -f "minifw_ai/main.py" | xargs kill 2>/dev/null || true
    sleep 1
fi

log "Step 3: Killing orphaned scheduler processes..."
if pgrep -f "demo_scheduler.py" >/dev/null 2>&1; then
    pgrep -f "demo_scheduler.py" | xargs kill 2>/dev/null || true
    sleep 1
fi

log "Step 4: Checking database..."
if [[ -f minifw.db ]]; then
    if ! python3 -c "import sqlite3; sqlite3.connect('minifw.db').execute('SELECT 1')" 2>/dev/null; then
        log "Database corrupt — removing..."
        rm -f minifw.db
    else
        log "Database OK."
    fi
fi

log "Step 5: Clearing stale event log..."
rm -f logs/events.jsonl

log "Step 6: Relaunching demo..."
[[ -f run_demo.sh ]] || die "run_demo.sh not found"

bash run_demo.sh &
DEMO_PID=$!

log "Waiting for dashboard (30s)..."
READY=false
for i in $(seq 1 30); do
    if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up — see RECOVERY.md for manual steps."
    exit 1
fi

log "Recovery successful — demo ready at https://localhost:8443  (admin / Finance1!)"
