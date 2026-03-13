#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "============================================"
echo " MiniFW-AI Installation"
echo " Source: ${REPO_DIR}"
echo " Target: ${APP_ROOT}"
echo "============================================"

# VSentinel Scope Gate - Fail-Closed Check
export GAMBLING_ONLY=1
if [ -f "${REPO_DIR}/scripts/vsentinel_scope_gate.sh" ]; then
    chmod +x "${REPO_DIR}/scripts/vsentinel_scope_gate.sh"
    "${REPO_DIR}/scripts/vsentinel_scope_gate.sh"
else
    echo "[WARN] VSentinel Scope Gate not found, skipping."
fi

# 1. Install system dependencies
echo ""
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip python3-ensurepip curl dnsmasq nftables 2>/dev/null || \
apt-get install -y -qq python3 python3-venv python3-pip curl dnsmasq nftables

# 2. Create directory structure
echo "[2/6] Creating directory structure..."
mkdir -p "${APP_ROOT}/logs"
mkdir -p "${APP_ROOT}/config/feeds"
mkdir -p "${APP_ROOT}/models"
mkdir -p "${APP_ROOT}/yara_rules"

# 3. Copy application code
echo "[3/6] Copying application code..."
rm -rf "${APP_ROOT}/app"
cp -r "${REPO_DIR}/app" "${APP_ROOT}/app"

# Copy prometheus and scheduler modules
rm -rf "${APP_ROOT}/prometheus" "${APP_ROOT}/scheduler"
cp -r "${REPO_DIR}/prometheus" "${APP_ROOT}/prometheus"
cp -r "${REPO_DIR}/scheduler" "${APP_ROOT}/scheduler"

# Copy config (don't overwrite existing feeds — they may be customised)
cp -f "${REPO_DIR}/config/policy.json" "${APP_ROOT}/config/policy.json"
for feed_file in "${REPO_DIR}"/config/feeds/*.txt; do
    dest="${APP_ROOT}/config/feeds/$(basename "$feed_file")"
    if [ ! -f "$dest" ]; then
        cp "$feed_file" "$dest"
    fi
done

# Copy MLP model
cp -f "${REPO_DIR}/models/mlp_model.pkl" "${APP_ROOT}/models/mlp_model.pkl"

# Copy YARA rules
cp -f "${REPO_DIR}"/yara_rules/*.yar "${APP_ROOT}/yara_rules/" 2>/dev/null || true

# Copy requirements
cp -f "${REPO_DIR}/requirements.txt" "${APP_ROOT}/requirements.txt"

# 4. Create Python virtual environment
echo "[4/6] Setting up Python virtual environment..."
if [ ! -d "${APP_ROOT}/venv" ]; then
    python3 -m venv --without-pip "${APP_ROOT}/venv"
fi
# Bootstrap pip if missing (handles fresh installs and leftover venvs without pip)
if ! "${APP_ROOT}/venv/bin/python" -m pip --version &>/dev/null; then
    echo "  Bootstrapping pip..."
    curl -sS https://bootstrap.pypa.io/get-pip.py | "${APP_ROOT}/venv/bin/python"
fi
"${APP_ROOT}/venv/bin/pip" install --upgrade pip -q
"${APP_ROOT}/venv/bin/pip" install -r "${APP_ROOT}/requirements.txt" -q

# 5. Set up nftables
echo "[5/6] Setting up nftables..."
systemctl enable nftables 2>/dev/null || true
systemctl start nftables 2>/dev/null || true
nft add table inet minifw 2>/dev/null || true
nft add set inet minifw minifw_block_v4 '{ type ipv4_addr; flags timeout; timeout 86400s; }' 2>/dev/null || true
nft add chain inet minifw forward '{ type filter hook forward priority 0; policy accept; }' 2>/dev/null || true
# Add drop rule for blocked IPs
nft add rule inet minifw forward ip saddr @minifw_block_v4 drop 2>/dev/null || true
nft add rule inet minifw forward ip daddr @minifw_block_v4 drop 2>/dev/null || true

echo "[6/6] Setting permissions..."
chmod -R 755 "${APP_ROOT}/app"
chmod 644 "${APP_ROOT}/config/policy.json"

echo ""
echo "============================================"
echo " Installation complete!"
echo " Installed to: ${APP_ROOT}"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Configure sector:  Edit MINIFW_SECTOR in systemd unit"
echo "  2. Enable DNS logging: sudo ${REPO_DIR}/scripts/enable_dnsmasq_logging.sh"
echo "  3. Install service:    sudo ${REPO_DIR}/scripts/install_systemd.sh"
echo "  4. Check status:       systemctl status minifw-ai"
echo ""
