#!/bin/bash
# MiniFW-AI Hospital Demo — Fast Reset
# Target: dashboard ready in ≤ 45 seconds.
# Preserves minifw.db (admin user stays provisioned).
# Usage: bash fast_reset.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-reset] $*"; }
die() { echo "[minifw-reset] ERROR: $*" >&2; exit 1; }

# ── Venv auto-activation ────────────────────────────────────────────────────────
[[ -f venv/bin/activate ]] && source venv/bin/activate

log "Fast reset starting..."

# ── Step 1: Kill all three processes in parallel ─────────────────────────────
log "Killing engine, web, and scheduler..."
pkill -f "minifw_ai/main.py"  2>/dev/null || true
pkill -f "uvicorn app.web"    2>/dev/null || true
pkill -f "demo_scheduler.py"  2>/dev/null || true
sleep 1

# ── Step 2: Free port 8000 if still held ────────────────────────────────────
if lsof -ti:8000 >/dev/null 2>&1; then
    log "Port 8000 still held — force-killing..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# ── Step 3: Clear event log only (preserve DB and admin user) ───────────────
log "Clearing event log..."
rm -f logs/events.jsonl

# ── Step 4: Relaunch demo ────────────────────────────────────────────────────
log "Relaunching..."
[[ -f run_demo.sh ]] || die "run_demo.sh not found"
bash run_demo.sh &

# ── Step 5: Health poll at 0.5s intervals, 45s timeout ──────────────────────
log "Waiting for dashboard (45s max)..."
READY=false
START=$(date +%s)
while true; do
    if curl -s --max-time 2 --connect-timeout 1 http://localhost:8000/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    NOW=$(date +%s)
    if (( NOW - START >= 45 )); then
        break
    fi
    sleep 0.5
done

ELAPSED=$(( $(date +%s) - START ))

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up in ${ELAPSED}s — see RECOVERY.md for manual steps."
    exit 1
fi

log "Ready in ${ELAPSED}s — http://localhost:8000  (admin / Hospital1!)"
