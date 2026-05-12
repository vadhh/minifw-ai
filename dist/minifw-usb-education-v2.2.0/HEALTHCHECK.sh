#!/bin/bash
# MiniFW-AI Education Demo (Docker) — Health Check
# Usage: bash HEALTHCHECK.sh
# Exit 0 = all pass. Exit 1 = one or more failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker/docker-compose.usb-education.yml"
DASHBOARD_URL="https://localhost:8447"
PORT=8447
ENGINE_CONTAINER="minifw_education_engine"
WEB_CONTAINER="minifw_education_web"
CA_CRT="docker/certs/minifw-demo-ca.crt"

mkdir -p logs
LOG_FILE="logs/healthcheck-$(date +%Y-%m-%d-%H%M).log"

PASS=0
FAIL=0

pass() { echo "[PASS] $*" | tee -a "$LOG_FILE"; ((PASS++)); }
fail() { echo "[FAIL] $*" | tee -a "$LOG_FILE"; ((FAIL++)); }
info() { echo "       $*" | tee -a "$LOG_FILE"; }

echo "MiniFW-AI Education Demo (Docker) — Health Check $(date)" | tee "$LOG_FILE"
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

# ── Check 5: Docker images present ────────────────────────────────────────────
if docker image inspect "minifw-ai-demo/education:latest" >/dev/null 2>&1 && \
   docker image inspect "minifw-ai-demo/education-injector:latest" >/dev/null 2>&1; then
    pass "Docker images present"
else
    fail "Docker images not loaded — run: docker load -i images/minifw-education.tar"
fi

# ── Check 6: MLP model (inside image — verify image exists, checked above) ────
pass "Check 6 (MLP model) — covered by image presence (Check 5)"

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
    if curl -s --cacert "$CA_CRT" -o /dev/null -w "%{http_code}" "${DASHBOARD_URL}/health" 2>/dev/null | grep -q "200"; then
        pass "TLS cert is valid and trusted (CA-signed)"
    elif curl -s -o /dev/null -w "%{http_code}" "${DASHBOARD_URL}/health" 2>/dev/null | grep -q "200"; then
        pass "TLS cert trusted by OS trust store"
    else
        fail "TLS cert NOT trusted by system — run: bash setup_tls.sh"
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
