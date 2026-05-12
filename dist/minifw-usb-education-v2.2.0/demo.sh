#!/usr/bin/env bash
# MiniFW-AI — education Sector Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2 installed on host

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="minifw-ai-demo/education:latest"
INJECTOR_TAG="minifw-ai-demo/education-injector:latest"
IMAGE_TAR="${USB_DIR}/images/minifw-education.tar"
COMPOSE_FILE="${USB_DIR}/docker/docker-compose.usb-education.yml"

log()  { echo "[minifw-demo] $*"; }
die()  { echo "[minifw-demo] ERROR: $*" >&2; exit 1; }

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: ${COMPOSE_FILE} — is the USB copy complete?"
command -v docker >/dev/null 2>&1 || die "Docker is not installed or not in PATH"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose)"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

# Suggest TLS setup if certs haven't been provisioned
if [[ ! -f "${USB_DIR}/docker/certs/server.crt" ]]; then
    log "TIP: For a green padlock in Chrome/Firefox, run 'bash setup_tls.sh' before starting the demo."
    log "     (Self-signed cert will be used if you proceed — browser will show a security warning)"
fi

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1 || \
   ! docker image inspect "$INJECTOR_TAG" >/dev/null 2>&1; then
    log "Images not found on this machine — loading from USB (this takes ~2-3 minutes)..."
    [[ -f "$IMAGE_TAR" ]] || die "Image archive not found: ${IMAGE_TAR}"
    docker load -i "$IMAGE_TAR"
    log "Images loaded."
else
    log "Images already loaded — skipping docker load."
fi

echo ""
echo "  ● MiniFW-AI Demo — education"
echo "  ─────────────────────────────────────────────────────"
echo "  Dashboard : https://localhost:8447"
echo "  Login     : admin / Education1!"
echo "  Sector    : education"
echo ""
echo "  Ctrl+C to stop."
echo ""

trap 'echo ""; echo "  Demo stopped. To clean up: docker compose -f \"${COMPOSE_FILE}\" down"' EXIT

docker compose -f "$COMPOSE_FILE" up
