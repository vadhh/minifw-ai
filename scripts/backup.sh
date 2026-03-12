#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
BACKUP_DIR="/opt/minifw_ai/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="minifw-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

mkdir -p "${BACKUP_DIR}"

echo "============================================"
echo " MiniFW-AI Backup"
echo " Timestamp: ${TIMESTAMP}"
echo " Target: ${BACKUP_PATH}"
echo "============================================"
echo ""

# 1. Export nftables ruleset
echo "[1/5] Exporting nftables ruleset..."
NFT_EXPORT="${BACKUP_DIR}/nft-rules-${TIMESTAMP}.nft"
nft list ruleset > "${NFT_EXPORT}" 2>/dev/null || echo "(no nftables rules found)"
echo "  Saved: ${NFT_EXPORT}"

# 2. Create full backup archive
echo "[2/5] Backing up configuration..."
ITEMS_TO_BACKUP=""

# Config files
[ -d "${APP_ROOT}/config" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} ${APP_ROOT}/config"

# YARA rules
[ -d "${APP_ROOT}/yara_rules" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} ${APP_ROOT}/yara_rules"

# MLP model + scaler
[ -d "${APP_ROOT}/models" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} ${APP_ROOT}/models"

# Database
[ -f "${APP_ROOT}/minifw.db" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} ${APP_ROOT}/minifw.db"

# Secrets (env file)
[ -f "/etc/minifw/minifw.env" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} /etc/minifw/minifw.env"

# TLS certificates
[ -d "/etc/minifw/tls" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} /etc/minifw/tls"

# Systemd unit files
[ -f "/etc/systemd/system/minifw-ai.service" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} /etc/systemd/system/minifw-ai.service"
[ -f "/etc/systemd/system/minifw-ai-web.service" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} /etc/systemd/system/minifw-ai-web.service"

# nftables export
[ -f "${NFT_EXPORT}" ] && ITEMS_TO_BACKUP="${ITEMS_TO_BACKUP} ${NFT_EXPORT}"

echo "[3/5] Creating archive..."
tar -czf "${BACKUP_PATH}" ${ITEMS_TO_BACKUP} 2>/dev/null
echo "  Archive: ${BACKUP_PATH}"

# 4. Backup logs separately (can be large)
echo "[4/5] Backing up logs..."
LOGS_BACKUP="${BACKUP_DIR}/minifw-logs-${TIMESTAMP}.tar.gz"
if [ -d "${APP_ROOT}/logs" ]; then
    tar -czf "${LOGS_BACKUP}" "${APP_ROOT}/logs" 2>/dev/null
    echo "  Logs: ${LOGS_BACKUP}"
else
    echo "  No logs directory found, skipping."
fi

# 5. Verify backup
echo "[5/5] Verifying backup..."
BACKUP_SIZE=$(du -h "${BACKUP_PATH}" | cut -f1)
FILE_COUNT=$(tar -tzf "${BACKUP_PATH}" | wc -l)
echo "  Size: ${BACKUP_SIZE}"
echo "  Files: ${FILE_COUNT}"

# Verify key files are in archive
VERIFY_OK=true
for check in "config/policy.json" "models/" "minifw.env"; do
    if tar -tzf "${BACKUP_PATH}" 2>/dev/null | grep -q "${check}"; then
        echo "  [OK] Contains: ${check}"
    else
        echo "  [WARN] Missing: ${check}"
        VERIFY_OK=false
    fi
done

echo ""
echo "============================================"
echo " Backup Complete"
echo "============================================"
echo " Archive:   ${BACKUP_PATH}"
echo " Size:      ${BACKUP_SIZE}"
echo " Files:     ${FILE_COUNT}"
echo " nftables:  ${NFT_EXPORT}"
if [ -f "${LOGS_BACKUP}" ]; then
    LOGS_SIZE=$(du -h "${LOGS_BACKUP}" | cut -f1)
    echo " Logs:      ${LOGS_BACKUP} (${LOGS_SIZE})"
fi
echo " Verified:  ${VERIFY_OK}"
echo "============================================"
echo ""
echo "To restore on another host:"
echo "  sudo tar -xzf ${BACKUP_PATH} -C /"
echo "  sudo nft -f ${NFT_EXPORT}"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl restart minifw-ai minifw-ai-web"
echo ""

# Cleanup old nft export (already in archive)
rm -f "${NFT_EXPORT}"
