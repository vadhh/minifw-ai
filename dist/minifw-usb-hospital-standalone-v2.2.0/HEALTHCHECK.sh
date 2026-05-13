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
