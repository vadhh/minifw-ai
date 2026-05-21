#!/bin/bash
# MiniFW-AI — Financial Sector Executive Demo
# Usage: bash run_demo.sh
# Prerequisites: bash setup_tls.sh must be run once first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw] $*"; }
die() { echo "[minifw] ERROR: $*" >&2; exit 1; }

# ── Pre-flight ──────────────────────────────────────────────────────────────────
[[ -f certs/server.crt ]] || die "TLS cert not found. Run: bash setup_tls.sh"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c "import uvicorn" 2>/dev/null || die "uvicorn not installed — run: pip install -r requirements.txt"

# ── Environment ─────────────────────────────────────────────────────────────────
export DEMO_MODE=1
export PRODUCT_MODE=minifw_financial
export MINIFW_SECTOR=finance
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
export MINIFW_SECRET_KEY="demo-financial-key-change-in-prod!!"
export MINIFW_ADMIN_PASSWORD="Finance1!"
export DATABASE_URL="sqlite:///./minifw.db"
export PYTHONPATH="$(pwd):$(pwd)/app:${PYTHONPATH:-}"
export PYTHONWARNINGS="ignore::UserWarning"

mkdir -p logs

# ── Provision admin user ─────────────────────────────────────────────────────────
python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
sys.path.insert(0, os.path.join(os.getcwd(), "app"))
from app.database import SessionLocal, init_db
from app.services.auth.user_service import get_user_by_username, create_user
init_db()
db = SessionLocal()
try:
    if get_user_by_username(db, "admin"):
        print("[minifw] Admin user already exists — skipping creation.")
    else:
        create_user(db, username="admin", email="admin@minifw.local",
                    password=os.environ["MINIFW_ADMIN_PASSWORD"])
        print("[minifw] Admin user created.")
except Exception as e:
    print(f"[minifw] WARNING: Could not create admin user: {e}", file=sys.stderr)
finally:
    db.close()
PYEOF

# ── Start engine ────────────────────────────────────────────────────────────────
log "Starting Financial Demo..."
python3 app/minifw_ai/main.py > logs/engine.log 2>&1 &
ENGINE_PID=$!

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

log "Engine started (PID $ENGINE_PID)"

# ── Start web (HTTPS) ───────────────────────────────────────────────────────────
uvicorn app.web.app:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile  certs/server.key \
    --ssl-certfile certs/server.crt \
    --log-level warning \
    > logs/web.log 2>&1 &
WEB_PID=$!

# ── Health poll (20s) ───────────────────────────────────────────────────────────
READY=false
for i in $(seq 1 20); do
    if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    die "Dashboard did not start in 20s — see logs/web.log"
fi

# ── Start scheduler ─────────────────────────────────────────────────────────────
python3 scheduler/demo_scheduler.py > logs/scheduler.log 2>&1 &
SCHEDULER_PID=$!

# ── Browser launch ──────────────────────────────────────────────────────────────
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "https://localhost:8443" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "https://localhost:8443" >/dev/null 2>&1 || true
fi

log "Dashboard ready → https://localhost:8443  (admin / Finance1!)"
log "Press Ctrl+C to stop."

wait "$WEB_PID" || true
