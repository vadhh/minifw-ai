#!/usr/bin/env bash
# MiniFW-AI — Establishment Sector Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2 installed on host

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="minifw-ai-demo/establishment:latest"
INJECTOR_TAG="minifw-ai-demo/establishment-injector:latest"
IMAGE_TAR="${USB_DIR}/images/minifw-establishment.tar"
COMPOSE_FILE="${USB_DIR}/docker/docker-compose.usb-sme.yml"

log()  { echo "[minifw-demo] $*"; }
die()  { echo "[minifw-demo] ERROR: $*" >&2; exit 1; }

# ── Guard checks ──────────────────────────────────────────────────────────────

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: ${COMPOSE_FILE} — is the USB copy complete?"

command -v docker >/dev/null 2>&1 || die "Docker is not installed or not in PATH"
docker compose version >/dev/null 2>&1  || die "Docker Compose v2 is required (docker compose)"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

# ── Load images if not already present ───────────────────────────────────────

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1 || \
   ! docker image inspect "$INJECTOR_TAG" >/dev/null 2>&1; then
    log "Images not found on this machine — loading from USB (this takes ~2-3 minutes)..."
    [[ -f "$IMAGE_TAR" ]] || die "Image archive not found: ${IMAGE_TAR}"
    docker load -i "$IMAGE_TAR"
    log "Images loaded."
else
    log "Images already loaded — skipping docker load."
fi

# ── Start demo ────────────────────────────────────────────────────────────────

echo ""
echo "  ● MiniFW-AI Demo — Establishment / SME"
echo "  ─────────────────────────────────────────────────────"
echo "  Dashboard : https://localhost:8444"
echo "  Login     : admin / SME_Demo1!"
echo "  Sector    : establishment"
echo ""
echo "  Ctrl+C to stop."
echo ""

trap 'echo ""; echo "  Demo stopped. To clean up: docker compose -f \"${COMPOSE_FILE}\" down"' EXIT

docker compose -f "$COMPOSE_FILE" \
    --project-directory "$USB_DIR" \
    up --remove-orphans
