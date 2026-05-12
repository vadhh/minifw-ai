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
