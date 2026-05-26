#!/bin/bash
# five_min_demo.sh — 5-Minute Executive Demo Launcher
# Hospital Sector · St. Roch Memorial Hospital
#
# Starts engine + dashboard + compressed scheduler.
# First BLOCK appears ~38 seconds in.
# Second BLOCK appears ~2 minutes in.
# Safe for any non-technical audience.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[[ -f venv/bin/activate ]] && source venv/bin/activate

log()  { echo "[minifw-5min] $*"; }
die()  { echo "[minifw-5min] ERROR: $*" >&2; exit 1; }

export DEMO_MODE=1
export PRODUCT_MODE=minifw_hospital
export MINIFW_SECTOR=hospital
export AI_ENABLED=1
export MINIFW_DISABLE_FLOWS=1
export MINIFW_DNS_SOURCE=none
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

# ── Ensure clean start ───────────────────────────────────────────────────────
if [[ -f logs/events.jsonl ]]; then
    log "Clearing previous events for clean demo start..."
    rm -f logs/events.jsonl logs/audit.jsonl logs/scheduler.log
fi

log "Starting 5-minute Hospital Demo..."
log ""
log "  Timeline:"
log "    T+0s   : Normal clinical traffic (EMR, PACS, lab systems)"
log "    T+38s  : [BLOCK] IoMT ransomware — score 47, mednet threshold 45"
log "    T+60s  : Staff still working normally"
log "    T+110s : [BLOCK] PHI exfiltration — score 82, internal threshold 80"
log "    T+120s+: Clean network — both attackers isolated"
log ""

ENGINE_PID=0
WEB_PID=0
SCHEDULER_PID=0
_CLEANED=0

cleanup() {
    [[ "$_CLEANED" -eq 1 ]] && return
    _CLEANED=1
    kill "$ENGINE_PID"    2>/dev/null || true
    kill "$WEB_PID"       2>/dev/null || true
    kill "$SCHEDULER_PID" 2>/dev/null || true
    log "Demo stopped."
}
trap cleanup EXIT INT TERM

python3 app/minifw_ai/main.py > logs/engine.log 2>&1 &
ENGINE_PID=$!

uvicorn app.web.app:app \
    --host 0.0.0.0 --port 8000 \
    --log-level warning \
    > logs/web.log 2>&1 &
WEB_PID=$!

# Wait for dashboard (max 20s)
READY=false
for i in $(seq 1 20); do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done
[[ "$READY" == "false" ]] && die "Dashboard did not start. Check logs/web.log"

python3 scheduler/five_min_scheduler.py > logs/scheduler.log 2>&1 &
SCHEDULER_PID=$!

if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:8000" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "http://localhost:8000" >/dev/null 2>&1 || true
fi

log "Dashboard ready → http://localhost:8000  (admin / Hospital1!)"
log "First BLOCK appears in ~38 seconds. Press Ctrl+C to stop."

wait "$WEB_PID" || true
