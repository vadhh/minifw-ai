#!/usr/bin/env bash
# MiniFW-AI — Hospital Sector Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="minifw-ai-demo/hospital:latest"
INJECTOR_TAG="minifw-ai-demo/hospital-injector:latest"
IMAGE_TAR="${USB_DIR}/images/minifw-hospital.tar"
COMPOSE_FILE="${USB_DIR}/docker/docker-compose.usb-hospital.yml"
DASHBOARD_URL="https://localhost:8443"

log() { echo "[minifw] $*"; }
die() { echo "[minifw] ERROR: $*" >&2; exit 1; }

# Pre-flight checks
[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: ${COMPOSE_FILE} — is the USB copy complete?"
command -v docker        >/dev/null 2>&1 || die "Docker is not installed or not in PATH"
docker compose version   >/dev/null 2>&1 || die "Docker Compose v2 is required (try: docker compose version)"
docker info              >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

# Suggest TLS setup if certs haven't been provisioned
if [[ ! -f "${USB_DIR}/docker/certs/server.crt" ]]; then
    log "TIP: For a green padlock in Chrome/Firefox, run 'bash setup_tls.sh' before starting the demo."
    log "     (Self-signed cert will be used if you proceed — browser will show a security warning)"
fi

# Load images if needed
if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1 || \
   ! docker image inspect "$INJECTOR_TAG" >/dev/null 2>&1; then
    log "Loading images from USB (this takes ~2-3 minutes on first run)..."
    [[ -f "$IMAGE_TAR" ]] || die "Image archive not found: ${IMAGE_TAR}"
    docker load -i "$IMAGE_TAR"
    log "Images loaded."
else
    log "Images ready."
fi

trap 'echo ""; log "Demo stopped. To clean up: docker compose -f \"${COMPOSE_FILE}\" down"' EXIT

log "Starting Hospital Demo..."
docker compose -f "$COMPOSE_FILE" up -d --quiet-pull

# Poll for dashboard ready (30s)
log "Waiting for dashboard..."
READY=false
for i in $(seq 1 30); do
    if curl -sk "${DASHBOARD_URL}/health" >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not respond in 30s — check: docker compose -f ${COMPOSE_FILE} logs web"
    exit 1
fi

log "Dashboard ready → ${DASHBOARD_URL}  (admin / Hospital1!)"
log "Press Ctrl+C to stop."

# Best-effort browser open
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "$DASHBOARD_URL" >/dev/null 2>&1 || true
fi

# Stream logs in foreground (Ctrl+C stops here and triggers trap)
docker compose -f "$COMPOSE_FILE" logs -f --no-log-prefix 2>/dev/null || true
