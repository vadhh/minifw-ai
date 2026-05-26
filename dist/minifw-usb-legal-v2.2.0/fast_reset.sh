#!/bin/bash
# MiniFW-AI Legal Demo — Fast Reset (Docker)
# Usage: bash fast_reset.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.usb-legal.yml"

log() { echo "[minifw-reset] $*"; }
die() { echo "[minifw-reset] ERROR: $*" >&2; exit 1; }

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: $COMPOSE_FILE"
command -v docker >/dev/null 2>&1 || die "Docker not found"

log "Fast reset starting..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
docker volume rm minifw_legal_logs 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d

log "Waiting for dashboard (60s max)..."
READY=false
START=$(date +%s)
while true; do
    if curl -s --max-time 2 --connect-timeout 1 -k https://localhost:8448/health >/dev/null 2>&1; then
        READY=true; break
    fi
    (( $(date +%s) - START >= 60 )) && break
    sleep 1
done

ELAPSED=$(( $(date +%s) - START ))
[[ "$READY" == "false" ]] && { log "Did not come up in ${ELAPSED}s — check docker logs"; exit 1; }
log "Ready in ${ELAPSED}s — https://localhost:8448  (admin / Legal1!)"
