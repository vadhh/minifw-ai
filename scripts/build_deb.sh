#!/usr/bin/env bash
set -euo pipefail

VERSION="2.0.0"
PKG_NAME="minifw-ai"
ARCH="amd64"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${REPO_DIR}/build/${PKG_NAME}_${VERSION}_${ARCH}"
DEB_OUTPUT="${REPO_DIR}/build/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "============================================"
echo " Building ${PKG_NAME} ${VERSION}"
echo " Output: ${DEB_OUTPUT}"
echo "============================================"

# Clean previous build
rm -rf "${BUILD_DIR}"

# --- Directory structure ---
# /opt/minifw_ai/app          — application code
# /opt/minifw_ai/prometheus    — prometheus module
# /opt/minifw_ai/scheduler     — retraining scheduler module
# /opt/minifw_ai/config        — policy + feeds
# /opt/minifw_ai/models        — pre-trained MLP
# /opt/minifw_ai/yara_rules    — YARA detection rules
# /opt/minifw_ai/scripts       — install helpers
# /etc/systemd/system          — service units

mkdir -p "${BUILD_DIR}/opt/minifw_ai/app"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/config/feeds"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/models"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/yara_rules"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/logs"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/scripts"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/prometheus"
mkdir -p "${BUILD_DIR}/opt/minifw_ai/scheduler"
mkdir -p "${BUILD_DIR}/etc/systemd/system"
mkdir -p "${BUILD_DIR}/DEBIAN"

# --- Copy application code ---
echo "[1/7] Copying application code..."
cp -r "${REPO_DIR}/app/"* "${BUILD_DIR}/opt/minifw_ai/app/"
cp -r "${REPO_DIR}/prometheus/"* "${BUILD_DIR}/opt/minifw_ai/prometheus/"
cp -r "${REPO_DIR}/scheduler/"* "${BUILD_DIR}/opt/minifw_ai/scheduler/"

# Strip __pycache__ and .pyc files
find "${BUILD_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -name "*.pyc" -delete 2>/dev/null || true

# --- Copy config ---
echo "[2/7] Copying configuration..."
cp "${REPO_DIR}/config/policy.json" "${BUILD_DIR}/opt/minifw_ai/config/"
cp "${REPO_DIR}"/config/feeds/*.txt "${BUILD_DIR}/opt/minifw_ai/config/feeds/"

# --- Copy models ---
echo "[3/7] Copying ML models..."
cp "${REPO_DIR}/models/mlp_model.pkl" "${BUILD_DIR}/opt/minifw_ai/models/"

# --- Copy YARA rules ---
echo "[4/7] Copying YARA rules..."
cp "${REPO_DIR}"/yara_rules/*.yar "${BUILD_DIR}/opt/minifw_ai/yara_rules/"

# --- Copy requirements ---
cp "${REPO_DIR}/requirements.txt" "${BUILD_DIR}/opt/minifw_ai/"

# --- Copy install helpers ---
echo "[5/7] Copying scripts..."
cp "${REPO_DIR}/scripts/install_systemd.sh" "${BUILD_DIR}/opt/minifw_ai/scripts/"
cp "${REPO_DIR}/scripts/backup.sh" "${BUILD_DIR}/opt/minifw_ai/scripts/"
cp "${REPO_DIR}/scripts/restore.sh" "${BUILD_DIR}/opt/minifw_ai/scripts/"
cp "${REPO_DIR}/scripts/create_admin.py" "${BUILD_DIR}/opt/minifw_ai/scripts/"
cp "${REPO_DIR}/scripts/train_mlp.py" "${BUILD_DIR}/opt/minifw_ai/scripts/"
chmod +x "${BUILD_DIR}/opt/minifw_ai/scripts/"*.sh

# --- Systemd units ---
echo "[6/7] Installing systemd units..."
cp "${REPO_DIR}/systemd/minifw-ai.service" "${BUILD_DIR}/etc/systemd/system/"
cp "${REPO_DIR}/systemd/minifw-ai-web.service" "${BUILD_DIR}/etc/systemd/system/"

# --- DEBIAN control files ---
echo "[7/7] Creating package metadata..."

cat > "${BUILD_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.10), python3-venv, nftables, openssl
Recommends: dnsmasq
Maintainer: Afridho Ikhsan <afridho@minifw.local>
Description: MiniFW-AI Behavioral Firewall Engine (ARCHANGEL 2.0)
 AI-powered network behavioral firewall for gateway appliances.
 Features: DNS/flow analysis, MLP threat detection, YARA scanning,
 nftables enforcement, sector-specific policies, web admin dashboard.
 Supports 6 deployment sectors: school, hospital, government,
 finance, legal, establishment.
EOF

cat > "${BUILD_DIR}/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

APP_ROOT="/opt/minifw_ai"

echo "MiniFW-AI: Post-install setup..."

# Create venv if missing
if [ ! -d "${APP_ROOT}/venv" ]; then
    echo "  Creating Python virtual environment..."
    python3 -m venv "${APP_ROOT}/venv"
fi

# Install/upgrade pip and dependencies
echo "  Installing Python dependencies..."
"${APP_ROOT}/venv/bin/python" -m pip install --upgrade pip -q 2>/dev/null || true
"${APP_ROOT}/venv/bin/pip" install -r "${APP_ROOT}/requirements.txt" -q

# Set permissions
chmod -R 755 "${APP_ROOT}/app"
chmod 644 "${APP_ROOT}/config/policy.json"
chmod 755 "${APP_ROOT}/logs"

# Reload systemd
systemctl daemon-reload

echo ""
echo "============================================"
echo " MiniFW-AI ${VERSION} installed successfully"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Run setup:   sudo /opt/minifw_ai/scripts/install_systemd.sh"
echo "     (generates TLS certs, secrets, admin user, starts services)"
echo ""
echo "  Or manually:"
echo "  2. Enable:      sudo systemctl enable --now minifw-ai"
echo "  3. Dashboard:   sudo systemctl enable --now minifw-ai-web"
echo "  4. Status:      systemctl status minifw-ai minifw-ai-web"
echo ""
POSTINST
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"

cat > "${BUILD_DIR}/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e

echo "MiniFW-AI: Stopping services..."
systemctl stop minifw-ai-web 2>/dev/null || true
systemctl stop minifw-ai 2>/dev/null || true
systemctl disable minifw-ai-web 2>/dev/null || true
systemctl disable minifw-ai 2>/dev/null || true

echo "MiniFW-AI: Services stopped."
PRERM
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

cat > "${BUILD_DIR}/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e

if [ "$1" = "purge" ]; then
    echo "MiniFW-AI: Purging data..."
    rm -rf /opt/minifw_ai/venv
    rm -rf /opt/minifw_ai/logs
    rm -f /opt/minifw_ai/minifw.db
    rm -rf /etc/minifw
    echo "MiniFW-AI: Purged. Config feeds and models preserved in /opt/minifw_ai/"
fi

systemctl daemon-reload
POSTRM
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

cat > "${BUILD_DIR}/DEBIAN/conffiles" <<'CONFFILES'
/opt/minifw_ai/config/policy.json
/opt/minifw_ai/config/feeds/allow_domains.txt
/opt/minifw_ai/config/feeds/deny_domains.txt
/opt/minifw_ai/config/feeds/deny_ips.txt
/opt/minifw_ai/config/feeds/deny_asn.txt
/opt/minifw_ai/config/feeds/tor_exit_nodes.txt
/opt/minifw_ai/config/feeds/asn_prefixes.txt
CONFFILES

# --- Build the .deb ---
dpkg-deb --build "${BUILD_DIR}" "${DEB_OUTPUT}"

# --- Checksum ---
SHA256=$(sha256sum "${DEB_OUTPUT}" | awk '{print $1}')
echo "${SHA256}  $(basename "${DEB_OUTPUT}")" > "${DEB_OUTPUT}.sha256"

echo ""
echo "============================================"
echo " Package built successfully"
echo " File: ${DEB_OUTPUT}"
echo " Size: $(du -h "${DEB_OUTPUT}" | awk '{print $1}')"
echo " SHA256: ${SHA256}"
echo "============================================"
