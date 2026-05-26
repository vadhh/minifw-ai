#!/bin/bash
# MiniFW-AI Government Demo — Fast Reset (Docker)
# Tears down all containers + log volume, relaunches fresh.
# Usage: bash fast_reset.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.usb-government.yml"

log() { echo "[minifw-reset] $*"; }
die() { echo "[minifw-reset] ERROR: $*" >&2; exit 1; }

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: $COMPOSE_FILE"
command -v docker >/dev/null 2>&1 || die "Docker not found"

log "Fast reset starting..."

log "Stopping containers..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

log "Clearing log volume..."
docker volume rm minifw_government_logs 2>/dev/null || true

log "Relaunching..."
docker compose -f "$COMPOSE_FILE" up -d

log "Waiting for dashboard (60s max)..."
READY=false
START=$(date +%s)
while true; do
    if curl -s --max-time 2 --connect-timeout 1 -k https://localhost:8449/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    NOW=$(date +%s)
    if (( NOW - START >= 60 )); then
        break
    fi
    sleep 1
done

ELAPSED=$(( $(date +%s) - START ))

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up in ${ELAPSED}s — check: docker compose -f docker/docker-compose.usb-government.yml logs"
    exit 1
fi

log "Ready in ${ELAPSED}s — https://localhost:8449  (admin / Government1!)"
