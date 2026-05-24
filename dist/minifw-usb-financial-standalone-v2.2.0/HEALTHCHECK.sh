#!/bin/bash
# MiniFW-AI Financial Demo — Health Check
# Usage: bash HEALTHCHECK.sh
# Exit 0 = all checks pass. Exit 1 = one or more failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/healthcheck-$(date +%Y-%m-%d-%H%M).log"

PASS=0; FAIL=0

log()  { echo "$(date +%H:%M:%S) $*" | tee -a "$LOG_FILE"; }
pass() { echo "[PASS] $*" | tee -a "$LOG_FILE"; ((PASS++)); }
fail() { echo "[FAIL] $*" | tee -a "$LOG_FILE"; ((FAIL++)); }
info() { echo "       $*" | tee -a "$LOG_FILE"; }

echo "MiniFW-AI Financial Demo — Health Check $(date)" | tee "$LOG_FILE"
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"

# Check 1: Python 3.10+
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
    pass "Python $PY_VER present"
else
    fail "Python 3.10+ required, found $PY_VER"
fi

# Check 2: venv + fastapi
if source venv/bin/activate 2>/dev/null && python3 -c "import fastapi" 2>/dev/null; then
    pass "venv activatable, fastapi importable"
    deactivate 2>/dev/null || true
else
    fail "venv missing or fastapi not installed — run: python3 -m venv venv && pip install -r requirements.txt"
fi

# Check 3: TLS certs present
if [[ -f certs/server.crt && -f certs/server.key && -f certs/minifw-ca.crt ]]; then
    pass "TLS certs present (server.crt, server.key, minifw-ca.crt)"
else
    fail "TLS certs missing — run: bash setup_tls.sh"
fi

# Check 4: Port 8443 free (pre-flight only)
if ! lsof -ti:8443 >/dev/null 2>&1; then
    pass "Port 8443 is free"
else
    info "Port 8443 in use — demo may already be running"
    ((PASS++))
fi

# Check 5: Demo data
if [[ -f demo_data/normal_traffic.json && -f demo_data/attack_traffic.json ]]; then
    pass "Demo data files present"
else
    fail "Missing demo_data/ files — package may be incomplete"
fi

# Check 6: MLP model
if [[ -f models/mlp_model.pkl ]]; then
    pass "MLP model present"
else
    fail "models/mlp_model.pkl missing"
fi

# Check 7: YARA rules
YARA_COUNT=$(find yara_rules -name "*.yar" 2>/dev/null | wc -l)
if [[ "$YARA_COUNT" -gt 0 ]]; then
    pass "YARA rules: $YARA_COUNT file(s)"
else
    fail "yara_rules/ is empty or missing"
fi

# Check 8: Dashboard HTTPS 200 (if running) or skip
if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert certs/minifw-ca.crt https://localhost:8443/health)
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "307" ]]; then
        pass "Dashboard HTTPS responds (HTTP $HTTP_CODE)"
    else
        fail "Dashboard returned HTTP $HTTP_CODE"
    fi
else
    info "Check 8: Dashboard not running — skipped (run bash run_demo.sh first)"
    ((PASS++))
fi

# Check 9: BLOCK event detection (if events.jsonl exists)
if [[ -f logs/events.jsonl ]]; then
    if grep -q '"action": "block"' logs/events.jsonl 2>/dev/null; then
        pass "BLOCK event detected in logs/events.jsonl"
    else
        info "Check 9: No BLOCK event yet — demo may still be in normal traffic phase (wait ~2 min)"
        ((PASS++))
    fi
else
    info "Check 9: logs/events.jsonl not found — run bash run_demo.sh first"
    ((PASS++))
fi

# Summary
TOTAL=$((PASS + FAIL))
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
if [[ "$FAIL" -eq 0 ]]; then
    echo "HEALTHCHECK PASSED ($PASS/$TOTAL)" | tee -a "$LOG_FILE"
    exit 0
else
    echo "HEALTHCHECK FAILED ($PASS/$TOTAL passed, $FAIL/$TOTAL failed) — see $LOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi
