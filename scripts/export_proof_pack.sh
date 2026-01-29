#!/usr/bin/env bash
set -euo pipefail

# =====================================================
# MiniFW-AI Proof Pack Exporter
# Generates auditable archive with integrity checksums
# =====================================================
# 
# This script is "Fail-Closed" by design:
# - Missing audit log = CRITICAL ERROR (abort)
# - Missing optional files = Warning only
#

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${1:-/tmp/minifw_proof_pack_${TIMESTAMP}}"
ARCHIVE_NAME="minifw_proof_pack_${TIMESTAMP}.tar.gz"

# Source file locations (configurable via environment)
CONFIG_DIR="${MINIFW_CONFIG:-/opt/minifw_ai/config}"
LOG_DIR="${MINIFW_LOGS:-/opt/minifw_ai/logs}"
SECTOR_FILE="${MINIFW_SECTOR_LOCK:-/etc/minifw/sector.lock}"

echo "🔒 MiniFW-AI Proof Pack Generator"
echo "   Timestamp: ${TIMESTAMP}"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# ===== CRITICAL: Audit Log is MANDATORY =====
if [[ -f "${LOG_DIR}/audit.jsonl" ]]; then
    cp "${LOG_DIR}/audit.jsonl" "$OUTPUT_DIR/"
    echo "✅ audit.jsonl copied"
else
    echo "❌ CRITICAL ERROR: Audit log not found at ${LOG_DIR}/audit.jsonl"
    echo "   Proof Pack generation aborted. Governance failure."
    echo ""
    echo "   A Proof Pack without an audit trail is invalid for compliance."
    echo "   Ensure the MiniFW-AI service has been running and generating audit logs."
    rm -rf "$OUTPUT_DIR"
    exit 1
fi

# ===== Optional files (warn if missing) =====

if [[ -f "${CONFIG_DIR}/policy.json" ]]; then
    cp "${CONFIG_DIR}/policy.json" "$OUTPUT_DIR/"
    echo "✅ policy.json copied"
else
    echo "⚠️  Warning: policy.json not found at ${CONFIG_DIR}/policy.json"
fi

if [[ -f "${SECTOR_FILE}" ]]; then
    cp "${SECTOR_FILE}" "$OUTPUT_DIR/sector.lock"
    echo "✅ sector.lock copied"
else
    echo "⚠️  Warning: sector.lock not found at ${SECTOR_FILE}"
fi

if [[ -f "${LOG_DIR}/events.jsonl" ]]; then
    cp "${LOG_DIR}/events.jsonl" "$OUTPUT_DIR/"
    echo "✅ events.jsonl copied"
else
    echo "⚠️  Warning: events.jsonl not found at ${LOG_DIR}/events.jsonl"
fi

# ===== Generate SHA256 Checksums =====
echo ""
echo "📝 Generating checksums..."
cd "$OUTPUT_DIR"
sha256sum * > SHA256SUMS.txt 2>/dev/null || true
echo "✅ SHA256SUMS.txt generated"

# ===== Create Archive =====
echo ""
echo "📦 Creating archive..."
cd "$(dirname "$OUTPUT_DIR")"
tar -czf "$ARCHIVE_NAME" "$(basename "$OUTPUT_DIR")"

ARCHIVE_PATH="$(dirname "$OUTPUT_DIR")/${ARCHIVE_NAME}"
ARCHIVE_SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)

# ===== Summary =====
echo ""
echo "════════════════════════════════════════════════════════"
echo "✅ Proof Pack created successfully!"
echo ""
echo "   Archive: ${ARCHIVE_PATH}"
echo "   Size:    ${ARCHIVE_SIZE}"
echo ""
echo "   Contents:"
for f in "$OUTPUT_DIR"/*; do
    echo "     - $(basename "$f")"
done
echo ""
echo "   Verify with: tar -tzf ${ARCHIVE_PATH}"
echo "   Validate:    sha256sum -c SHA256SUMS.txt"
echo "════════════════════════════════════════════════════════"
