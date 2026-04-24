#!/usr/bin/env bash
# build_usb.sh — stages a self-contained USB demo kit for a given sector.
#
# Usage:
#   bash build_usb.sh hospital              # → dist/minifw-usb-hospital-v2.2.0/
#   bash build_usb.sh establishment         # → dist/minifw-usb-establishment-v2.2.0/
#   bash build_usb.sh hospital 2.3.0        # custom version
#
# After this script completes, copy dist/minifw-usb-<sector>-vX.Y.Z/
# to the root of a formatted USB drive (FAT32 or exFAT, 8GB+).

set -euo pipefail

SECTOR="${1:-}"
VERSION="${2:-2.2.0}"

log()  { echo "[build_usb] $*"; }
die()  { echo "[build_usb] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

# ── Sector config ─────────────────────────────────────────────────────────────

case "$SECTOR" in
  hospital)
    SOURCE_COMPOSE="docker/docker-compose.yml"
    USB_COMPOSE="docker/docker-compose.usb-hospital.yml"
    INJECTOR_DIR="docker/demo-injector"
    IMAGE_TAG="minifw-ai-demo/hospital:latest"
    INJECTOR_TAG="minifw-ai-demo/hospital-injector:latest"
    IMAGE_TAR_NAME="minifw-hospital.tar"
    CONFIG_MODE="minifw_hospital"
    COMPOSE_PROJECT="minifw-hospital"
    DASHBOARD_PORT="8443"
    ADMIN_PASS="Hospital1!"
    ;;
  establishment)
    SOURCE_COMPOSE="docker/docker-compose.sme.yml"
    USB_COMPOSE="docker/docker-compose.usb-sme.yml"
    INJECTOR_DIR="docker/demo-injector-sme"
    IMAGE_TAG="minifw-ai-demo/establishment:latest"
    INJECTOR_TAG="minifw-ai-demo/establishment-injector:latest"
    IMAGE_TAR_NAME="minifw-establishment.tar"
    CONFIG_MODE="minifw_establishment"
    COMPOSE_PROJECT="minifw-establishment"
    DASHBOARD_PORT="8444"
    ADMIN_PASS="SME_Demo1!"
    ;;
  financial)
    SOURCE_COMPOSE="docker/docker-compose.financial.yml"
    USB_COMPOSE="docker/docker-compose.usb-financial.yml"
    INJECTOR_DIR="docker/demo-injector-financial"
    IMAGE_TAG="minifw-ai-demo/financial:latest"
    INJECTOR_TAG="minifw-ai-demo/financial-injector:latest"
    IMAGE_TAR_NAME="minifw-financial.tar"
    CONFIG_MODE="minifw_financial"
    COMPOSE_PROJECT="minifw-financial"
    DASHBOARD_PORT="8445"
    ADMIN_PASS="Finance1!"
    ;;
  *)
    echo "Usage: bash build_usb.sh <sector> [version]"
    echo "       sector: hospital | establishment | financial"
    exit 1
    ;;
esac

USB_COMPOSE_FILE="$(basename "$USB_COMPOSE")"
PACKAGE_NAME="minifw-usb-${SECTOR}-v${VERSION}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="${SCRIPT_DIR}/dist/${PACKAGE_NAME}"

need docker
need cp
need mkdir

docker compose version >/dev/null 2>&1 || die "Docker Compose v2 required"

cd "$SCRIPT_DIR"

[[ -f docker/Dockerfile  ]] || die "docker/Dockerfile not found — run from repo root"
[[ -f "$SOURCE_COMPOSE"  ]] || die "${SOURCE_COMPOSE} not found"
[[ -f "$USB_COMPOSE"     ]] || die "${USB_COMPOSE} not found"
[[ -d "$INJECTOR_DIR"    ]] || die "${INJECTOR_DIR}/ not found"

# ── Build images ──────────────────────────────────────────────────────────────

log "Building ${SECTOR} images (this may take a few minutes on first run)..."
docker compose -f "$SOURCE_COMPOSE" build

log "Tagging images..."
docker tag "${COMPOSE_PROJECT}-engine"   "$IMAGE_TAG"
docker tag "${COMPOSE_PROJECT}-web"      "$IMAGE_TAG"
docker tag "${COMPOSE_PROJECT}-injector" "$INJECTOR_TAG"

log "  engine+web  → ${IMAGE_TAG}"
log "  injector    → ${INJECTOR_TAG}"

# ── Save images to tar ────────────────────────────────────────────────────────

log "Saving images to tar (~2-3 GB, may take a few minutes)..."
mkdir -p "${SCRIPT_DIR}/dist"
TMP_TAR="${SCRIPT_DIR}/dist/${IMAGE_TAR_NAME}"
docker save "$IMAGE_TAG" "$INJECTOR_TAG" -o "$TMP_TAR"
TAR_SIZE=$(du -sh "$TMP_TAR" | cut -f1)
log "  Saved: ${TMP_TAR} (${TAR_SIZE})"

# ── Stage USB layout ──────────────────────────────────────────────────────────

log "Staging USB layout to ${STAGE_DIR}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Generate demo.sh for this sector
cat > "${STAGE_DIR}/demo.sh" <<LAUNCHER
#!/usr/bin/env bash
# MiniFW-AI — ${SECTOR} Sector Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2 installed on host

set -euo pipefail

USB_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG}"
INJECTOR_TAG="${INJECTOR_TAG}"
IMAGE_TAR="\${USB_DIR}/images/${IMAGE_TAR_NAME}"
COMPOSE_FILE="\${USB_DIR}/docker/${USB_COMPOSE_FILE}"

log()  { echo "[minifw-demo] \$*"; }
die()  { echo "[minifw-demo] ERROR: \$*" >&2; exit 1; }

[[ -f "\$COMPOSE_FILE" ]] || die "Compose file not found: \${COMPOSE_FILE} — is the USB copy complete?"
command -v docker >/dev/null 2>&1 || die "Docker is not installed or not in PATH"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose)"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

if ! docker image inspect "\$IMAGE_TAG" >/dev/null 2>&1 || \\
   ! docker image inspect "\$INJECTOR_TAG" >/dev/null 2>&1; then
    log "Images not found on this machine — loading from USB (this takes ~2-3 minutes)..."
    [[ -f "\$IMAGE_TAR" ]] || die "Image archive not found: \${IMAGE_TAR}"
    docker load -i "\$IMAGE_TAR"
    log "Images loaded."
else
    log "Images already loaded — skipping docker load."
fi

echo ""
echo "  ● MiniFW-AI Demo — ${SECTOR}"
echo "  ─────────────────────────────────────────────────────"
echo "  Dashboard : https://localhost:${DASHBOARD_PORT}"
echo "  Login     : admin / ${ADMIN_PASS}"
echo "  Sector    : ${SECTOR}"
echo ""
echo "  Ctrl+C to stop."
echo ""

trap 'echo ""; echo "  Demo stopped. To clean up: docker compose -f \"\${COMPOSE_FILE}\" down"' EXIT

docker compose -f "\$COMPOSE_FILE" up
LAUNCHER
chmod +x "${STAGE_DIR}/demo.sh"

# Generate README.txt for this sector
cat > "${STAGE_DIR}/README.txt" <<README
MiniFW-AI — ${SECTOR} Sector Demo
======================================

Requirements
------------
  - Windows 10/11 with WSL2 + Docker Desktop, OR native Linux with Docker
  - Docker Compose v2  (docker compose version  — should print v2.x)
  - Port ${DASHBOARD_PORT} free on localhost

Run the Demo
------------
  bash demo.sh

  First run on a new machine: loads Docker images from USB (~2-3 min, one-time).
  Subsequent runs: starts immediately.

  Dashboard → https://localhost:${DASHBOARD_PORT}
  Login     → admin / ${ADMIN_PASS}

  Accept the self-signed certificate warning in your browser.
  Wait ~33 seconds for the first injector loop to populate events.

Stop
----
  Ctrl+C in the terminal. The demo script will print the cleanup command.
  To force-stop manually (run from the USB root directory):

  docker compose -f docker/${USB_COMPOSE_FILE} down

Troubleshooting
---------------
  Port ${DASHBOARD_PORT} in use?
    docker compose -f docker/${USB_COMPOSE_FILE} down
    then re-run demo.sh

  Docker not found?
    Windows: open Docker Desktop and ensure WSL integration is enabled.
    Linux:   sudo systemctl start docker

Full demo script: ask your MiniFW-AI contact for DEMO_MASTER_SCRIPT.md
README

# Docker files
mkdir -p "${STAGE_DIR}/docker"
cp "$USB_COMPOSE"                        "${STAGE_DIR}/docker/${USB_COMPOSE_FILE}"
cp docker/entrypoint-engine.sh           "${STAGE_DIR}/docker/entrypoint-engine.sh"
cp docker/entrypoint-web.sh              "${STAGE_DIR}/docker/entrypoint-web.sh"
cp -r "${INJECTOR_DIR}/"                 "${STAGE_DIR}/docker/$(basename "$INJECTOR_DIR")/"

# Config — sector mode only
mkdir -p "${STAGE_DIR}/config/modes"
if [[ -d "config/modes/${CONFIG_MODE}" ]]; then
    cp -r "config/modes/${CONFIG_MODE}" "${STAGE_DIR}/config/modes/${CONFIG_MODE}"
else
    log "WARNING: config/modes/${CONFIG_MODE} not found — skipping"
fi

# Feeds
mkdir -p "${STAGE_DIR}/config/feeds"
for feed in \
    allow_domains.txt \
    deny_domains.txt \
    deny_asn.txt \
    deny_ips.txt \
    asn_prefixes.txt \
    tor_exit_nodes.txt; do
    src="config/feeds/${feed}"
    if [[ -f "$src" ]]; then
        cp "$src" "${STAGE_DIR}/config/feeds/${feed}"
    else
        log "WARNING: ${src} not found — skipping"
    fi
done

# YARA rules
if [[ -d yara_rules ]]; then
    cp -r yara_rules/ "${STAGE_DIR}/yara_rules/"
else
    log "WARNING: yara_rules/ not found — skipping"
fi

# Images tar
mkdir -p "${STAGE_DIR}/images"
mv "$TMP_TAR" "${STAGE_DIR}/images/${IMAGE_TAR_NAME}"

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL_SIZE=$(du -sh "$STAGE_DIR" | cut -f1)

log ""
log "Done."
log "  Staged : ${STAGE_DIR}"
log "  Size   : ${TOTAL_SIZE}"
log ""
log "Next step: copy ${STAGE_DIR}/* to the root of a formatted USB drive."
log ""
log "  Example (Linux — replace sdX with your USB device):"
log "    cp -r ${STAGE_DIR}/. /media/\$USER/<usb-label>/"
log ""
log "  Example (WSL — USB mounted at /mnt/e):"
log "    cp -r ${STAGE_DIR}/. /mnt/e/"
log ""
log "Sales team runs: bash demo.sh"
