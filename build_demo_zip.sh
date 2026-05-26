#!/usr/bin/env bash
# build_demo_zip.sh
# Packages the MiniFW-AI demo runtime into a clean distributable zip.
# Only runtime files are included — no engine source, no tests, no legacy variants.
#
# Usage:
#   bash build_demo_zip.sh              # → minifw-ai-demo-v2.2.0.zip
#   bash build_demo_zip.sh 2.3.0        # → minifw-ai-demo-v2.3.0.zip

set -euo pipefail

VERSION="${1:-2.2.0}"
PACKAGE_NAME="minifw-ai-demo-v${VERSION}"
OUT_DIR="$(pwd)/dist"
STAGE_DIR="${OUT_DIR}/${PACKAGE_NAME}"
ZIP_FILE="${OUT_DIR}/${PACKAGE_NAME}.zip"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo "[build_demo_zip] $*"; }
die()  { echo "[build_demo_zip] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

need zip
need cp
need mkdir

# ---------------------------------------------------------------------------
# Validate source layout
# ---------------------------------------------------------------------------

cd "$SCRIPT_DIR"

[[ -d docker             ]] || die "docker/ directory not found — run from repo root"
[[ -d config/modes       ]] || die "config/modes/ not found"
[[ -d config/feeds       ]] || die "config/feeds/ not found"
[[ -d yara_rules         ]] || die "yara_rules/ not found"
[[ -f docker/demo.sh     ]] || die "docker/demo.sh not found"

# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------

log "Staging to ${STAGE_DIR}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Docker runtime
log "  → docker/"
cp -r docker/ "${STAGE_DIR}/docker/"

# Sector mode configs (hospital / establishment / gambling only — no financial/school/legal)
log "  → config/modes/"
mkdir -p "${STAGE_DIR}/config/modes"
for mode in minifw_hospital minifw_establishment minifw_gambling; do
    src="config/modes/${mode}"
    if [[ -d "$src" ]]; then
        cp -r "$src" "${STAGE_DIR}/config/modes/${mode}"
    else
        log "  WARNING: ${src} not found — skipping"
    fi
done

# Feeds — only what the three demo modes use
log "  → config/feeds/ (demo subset)"
mkdir -p "${STAGE_DIR}/config/feeds"
for feed in \
    allow_domains.txt \
    deny_domains.txt \
    deny_asn.txt \
    deny_ips.txt \
    asn_prefixes.txt \
    tor_exit_nodes.txt \
    healthcare_threats.txt \
    gambling_domains.txt; do
    src="config/feeds/${feed}"
    if [[ -f "$src" ]]; then
        cp "$src" "${STAGE_DIR}/config/feeds/${feed}"
    else
        log "  WARNING: ${src} not found — skipping"
    fi
done

# YARA rules — hospital and sme only (no test_rules)
log "  → yara_rules/ (hospital + sme)"
mkdir -p "${STAGE_DIR}/yara_rules"
for rule in hospital_rules.yar sme_rules.yar; do
    src="yara_rules/${rule}"
    if [[ -f "$src" ]]; then
        cp "$src" "${STAGE_DIR}/yara_rules/${rule}"
    else
        log "  WARNING: ${src} not found — skipping"
    fi
done

# Env files — demo modes only
log "  → .env files"
for env_file in \
    .env.minifw_hospital \
    .env.minifw_establishment \
    .env.minifw_gambling; do
    if [[ -f "$env_file" ]]; then
        cp "$env_file" "${STAGE_DIR}/${env_file}"
    else
        log "  WARNING: ${env_file} not found — skipping"
    fi
done

# Demo docs
log "  → demo docs"
for doc in DEMO.md DEMO_MASTER_SCRIPT.md; do
    if [[ -f "$doc" ]]; then
        cp "$doc" "${STAGE_DIR}/${doc}"
    else
        log "  WARNING: ${doc} not found — skipping"
    fi
done

# Quick-start README
log "  → README.txt"
cat > "${STAGE_DIR}/README.txt" <<EOF
MiniFW-AI Demo Package — v${VERSION}
=====================================

Prerequisites
-------------
  - Docker + Docker Compose installed
  - Ports 8443 / 8444 / 8445 free on localhost

Quick Start
-----------
  cd docker
  ./demo.sh hospital up      # https://localhost:8443  admin / Hospital1!
  ./demo.sh sme up           # https://localhost:8444  admin / SME_Demo1!
  ./demo.sh gambling up      # https://localhost:8445  admin / Gambling1!

  Wait ~33 seconds for the first injector loop to populate events.
  Accept the self-signed certificate warning in your browser.

Stop / Clean
------------
  ./demo.sh hospital down
  ./demo.sh sme down
  ./demo.sh gambling down

  ./demo.sh hospital clean   # stop + wipe logs

Full walkthrough: DEMO_MASTER_SCRIPT.md
Reference:        DEMO.md
EOF

# ---------------------------------------------------------------------------
# Zip
# ---------------------------------------------------------------------------

log "Creating ${ZIP_FILE}"
mkdir -p "$OUT_DIR"
rm -f "$ZIP_FILE"

(cd "$OUT_DIR" && zip -r "${ZIP_FILE}" "${PACKAGE_NAME}/" -x "*.DS_Store" -x "__pycache__/*" -x "*.pyc")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

ZIP_SIZE=$(du -sh "$ZIP_FILE" | cut -f1)

log ""
log "Done."
log "  Package : ${ZIP_FILE}"
log "  Size    : ${ZIP_SIZE}"
log ""
log "Contents:"
(cd "$OUT_DIR" && zip -sf "${ZIP_FILE}" | sed 's/^/  /')
