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

WEB_PID=0

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
