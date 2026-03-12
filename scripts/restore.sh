#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0 <backup-file>"; exit 1; fi

if [[ $# -lt 1 ]]; then
    echo "Usage: sudo $0 <backup-archive.tar.gz> [nft-rules.nft]"
    echo ""
    echo "Example:"
    echo "  sudo $0 /opt/minifw_ai/backups/minifw-backup-20260312.tar.gz"
    exit 1
fi

BACKUP_FILE="$1"
NFT_FILE="${2:-}"

if [[ ! -f "${BACKUP_FILE}" ]]; then
    echo "Error: Backup file not found: ${BACKUP_FILE}"
    exit 1
fi

echo "============================================"
echo " MiniFW-AI Restore"
echo " Source: ${BACKUP_FILE}"
echo "============================================"
echo ""

# 1. Stop services
echo "[1/5] Stopping services..."
systemctl stop minifw-ai-web 2>/dev/null || true
systemctl stop minifw-ai 2>/dev/null || true
echo "  Services stopped."

# 2. List archive contents
echo "[2/5] Verifying backup contents..."
FILE_COUNT=$(tar -tzf "${BACKUP_FILE}" | wc -l)
echo "  Files in archive: ${FILE_COUNT}"

# 3. Extract backup
echo "[3/5] Restoring files..."
tar -xzf "${BACKUP_FILE}" -C /
echo "  Files restored."

# 4. Restore nftables rules
echo "[4/5] Restoring nftables rules..."
if [[ -n "${NFT_FILE}" && -f "${NFT_FILE}" ]]; then
    nft -f "${NFT_FILE}" 2>/dev/null && echo "  nftables rules restored from ${NFT_FILE}" || echo "  [WARN] nftables restore failed"
else
    # Check if nft export is in the backup dir
    LATEST_NFT=$(ls -t /opt/minifw_ai/backups/nft-rules-*.nft 2>/dev/null | head -1)
    if [[ -n "${LATEST_NFT}" ]]; then
        nft -f "${LATEST_NFT}" 2>/dev/null && echo "  nftables rules restored from ${LATEST_NFT}" || echo "  [WARN] nftables restore failed"
    else
        echo "  No nftables backup found, skipping. Run install.sh to recreate."
    fi
fi

# 5. Restart services
echo "[5/5] Restarting services..."
systemctl daemon-reload
chmod 600 /etc/minifw/minifw.env 2>/dev/null || true
chmod 600 /etc/minifw/tls/server.key 2>/dev/null || true
systemctl start minifw-ai
systemctl start minifw-ai-web

echo ""
echo "============================================"
echo " Restore Complete"
echo "============================================"
echo ""
echo "Verify:"
echo "  systemctl status minifw-ai --no-pager"
echo "  systemctl status minifw-ai-web --no-pager"
echo "  sudo nft list table inet minifw"
echo ""
