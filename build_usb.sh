#!/usr/bin/env bash
# build_usb.sh
# Stages a self-contained USB demo kit for the establishment sector.
#
# Usage:
#   bash build_usb.sh              # → dist/minifw-usb-establishment-v2.2.0/
#   bash build_usb.sh 2.3.0        # → minifw-usb-establishment-v2.3.0/
#
# After this script completes, copy dist/minifw-usb-establishment-vX.Y.Z/
# to the root of a formatted USB drive (FAT32 or exFAT, 8GB+).

set -euo pipefail

VERSION="${1:-2.2.0}"
SECTOR="establishment"
PACKAGE_NAME="minifw-usb-${SECTOR}-v${VERSION}"
OUT_DIR="$(pwd)/dist"
STAGE_DIR="${OUT_DIR}/${PACKAGE_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_TAG="minifw-ai-demo/establishment:latest"
INJECTOR_TAG="minifw-ai-demo/establishment-injector:latest"
IMAGE_TAR_NAME="minifw-establishment.tar"

log()  { echo "[build_usb] $*"; }
die()  { echo "[build_usb] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

need docker
need cp
need mkdir

docker compose version >/dev/null 2>&1 || die "Docker Compose v2 required"

cd "$SCRIPT_DIR"

[[ -f docker/Dockerfile                    ]] || die "docker/Dockerfile not found — run from repo root"
[[ -f docker/docker-compose.usb-sme.yml    ]] || die "docker/docker-compose.usb-sme.yml not found — run Task 1 first"
[[ -f docker/docker-compose.sme.yml        ]] || die "docker/docker-compose.sme.yml not found"
[[ -d docker/demo-injector-sme             ]] || die "docker/demo-injector-sme/ not found"
[[ -f usb/demo.sh                          ]] || die "usb/demo.sh not found — run Task 2 first"
[[ -f usb/README.txt                       ]] || die "usb/README.txt not found — run Task 3 first"

# ── Build images ──────────────────────────────────────────────────────────────

log "Building establishment images (this may take a few minutes on first run)..."
docker compose -f docker/docker-compose.sme.yml build

log "Tagging images..."
# Compose names images as: <project>-<service>  (project = 'minifw-establishment')
docker tag minifw-establishment-engine   "$IMAGE_TAG"
docker tag minifw-establishment-web      "$IMAGE_TAG"
docker tag minifw-establishment-injector "$INJECTOR_TAG"

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

# Launcher + README
cp usb/demo.sh    "${STAGE_DIR}/demo.sh"
cp usb/README.txt "${STAGE_DIR}/README.txt"
chmod +x "${STAGE_DIR}/demo.sh"

# Docker files (USB compose + entrypoints + injector)
mkdir -p "${STAGE_DIR}/docker"
cp docker/docker-compose.usb-sme.yml  "${STAGE_DIR}/docker/docker-compose.usb-sme.yml"
cp docker/entrypoint-engine.sh        "${STAGE_DIR}/docker/entrypoint-engine.sh"
cp docker/entrypoint-web.sh           "${STAGE_DIR}/docker/entrypoint-web.sh"
cp -r docker/demo-injector-sme/       "${STAGE_DIR}/docker/demo-injector-sme/"

# Config — establishment mode only
mkdir -p "${STAGE_DIR}/config/modes"
if [[ -d config/modes/minifw_establishment ]]; then
    cp -r config/modes/minifw_establishment "${STAGE_DIR}/config/modes/minifw_establishment"
else
    log "WARNING: config/modes/minifw_establishment not found — skipping"
fi

# Feeds — same subset as build_demo_zip.sh
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

# YARA rules — sme only
mkdir -p "${STAGE_DIR}/yara_rules"
if [[ -f yara_rules/sme_rules.yar ]]; then
    cp yara_rules/sme_rules.yar "${STAGE_DIR}/yara_rules/sme_rules.yar"
else
    log "WARNING: yara_rules/sme_rules.yar not found — skipping"
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
