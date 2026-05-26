#!/bin/bash
# MiniFW-AI Education Demo — Fast Reset (Docker)
# Tears down all containers + log volume, relaunches fresh.
# Admin user is re-provisioned automatically on next start.
# Usage: bash fast_reset.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker/docker-compose.usb-education.yml"

log() { echo "[minifw-reset] $*"; }
die() { echo "[minifw-reset] ERROR: $*" >&2; exit 1; }

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: $COMPOSE_FILE"
command -v docker >/dev/null 2>&1 || die "Docker not found"

log "Fast reset starting..."

# ── Step 1: Stop all containers ──────────────────────────────────────────────
log "Stopping containers..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

# ── Step 2: Clear log volume (events.jsonl, dnsmasq.log) ─────────────────────
log "Clearing log volume..."
docker volume rm minifw_education_logs 2>/dev/null || true

# ── Step 3: Relaunch ─────────────────────────────────────────────────────────
log "Relaunching..."
docker compose -f "$COMPOSE_FILE" up -d

# ── Step 4: Health poll ───────────────────────────────────────────────────────
log "Waiting for dashboard (60s max)..."
READY=false
START=$(date +%s)
while true; do
    if curl -s --max-time 2 --connect-timeout 1 -k https://localhost:8447/health >/dev/null 2>&1; then
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
    log "Dashboard did not come up in ${ELAPSED}s — check: docker compose -f docker/docker-compose.usb-education.yml logs"
    exit 1
fi

log "Ready in ${ELAPSED}s — https://localhost:8447  (admin / Education1!)"
