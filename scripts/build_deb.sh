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
ENV_DIR="/etc/minifw"
ENV_FILE="${ENV_DIR}/minifw.env"
TLS_DIR="${ENV_DIR}/tls"

echo ""
echo "============================================"
echo " MiniFW-AI: Post-install setup"
echo "============================================"

# --- 1. Python virtual environment ---
echo "[1/6] Python environment..."
if [ ! -d "${APP_ROOT}/venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv "${APP_ROOT}/venv"
fi
echo "  Installing dependencies..."
"${APP_ROOT}/venv/bin/python" -m pip install --upgrade pip -q 2>/dev/null || true
"${APP_ROOT}/venv/bin/pip" install -r "${APP_ROOT}/requirements.txt" -q

# --- 2. Generate secrets ---
echo "[2/6] Secrets..."
mkdir -p "${ENV_DIR}"
chmod 755 "${ENV_DIR}"

if [ ! -f "${ENV_FILE}" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    ADMIN_PASS=$(openssl rand -base64 12)
    cat > "${ENV_FILE}" <<EOF
MINIFW_SECRET_KEY=${SECRET_KEY}
MINIFW_ADMIN_PASSWORD=${ADMIN_PASS}
EOF
    chmod 600 "${ENV_FILE}"
    echo "  Generated new secrets."
    echo ""
    echo "  *** ADMIN PASSWORD: ${ADMIN_PASS} ***"
    echo "  *** Save this! Stored in ${ENV_FILE} ***"
    echo ""
else
    echo "  Secrets exist: ${ENV_FILE}"
fi

# Inject EnvironmentFile into daemon unit if not present
if [ -f /etc/systemd/system/minifw-ai.service ]; then
    if ! grep -q "EnvironmentFile=" /etc/systemd/system/minifw-ai.service; then
        sed -i '/^\[Service\]/a EnvironmentFile=/etc/minifw/minifw.env' \
            /etc/systemd/system/minifw-ai.service
    fi
fi

# --- 3. Generate TLS certificate ---
echo "[3/6] TLS certificate..."
mkdir -p "${TLS_DIR}"
if [ ! -f "${TLS_DIR}/server.crt" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${TLS_DIR}/server.key" \
        -out "${TLS_DIR}/server.crt" \
        -days 365 -nodes \
        -subj "/CN=minifw-ai/O=MiniFW-AI/C=ID" 2>/dev/null
    chmod 600 "${TLS_DIR}/server.key"
    chmod 644 "${TLS_DIR}/server.crt"
    echo "  Self-signed certificate generated (365 days)."
else
    echo "  Certificate exists: ${TLS_DIR}/server.crt"
fi

# --- 4. Create admin user ---
echo "[4/6] Admin user..."
export GAMBLING_ONLY=1
export PYTHONPATH="${APP_ROOT}/app"
# shellcheck disable=SC2046
export $(grep -v '^#' "${ENV_FILE}" | xargs)
cd "${APP_ROOT}"
"${APP_ROOT}/venv/bin/python" -c "
import os, sys
sys.path.insert(0, '${APP_ROOT}')
from app.database import SessionLocal, init_db
from app.services.auth.user_service import create_user
init_db()
db = SessionLocal()
try:
    from app.models.user import User
    existing = db.query(User).filter(User.username == 'admin').first()
    if existing:
        print('  Admin user already exists, skipping.')
    else:
        admin = create_user(
            db=db,
            username='admin',
            email='admin@minifw.local',
            password=os.environ['MINIFW_ADMIN_PASSWORD']
        )
        admin.role = 'super_admin'
        admin.full_name = 'System Administrator'
        admin.must_change_password = True
        db.commit()
        print(f'  Admin user created: {admin.username} (super_admin)')
except Exception as e:
    print(f'  Warning: Could not create admin user: {e}')
finally:
    db.close()
" 2>&1 || echo "  Warning: Admin user creation failed (non-fatal)."

# Fix SQLite database permissions
chmod 664 "${APP_ROOT}/minifw.db" 2>/dev/null || true
chmod 775 "${APP_ROOT}" 2>/dev/null || true

# --- 5. Set permissions ---
echo "[5/6] Permissions..."
chmod -R 755 "${APP_ROOT}/app"
chmod 644 "${APP_ROOT}/config/policy.json"
chmod 755 "${APP_ROOT}/logs"

# --- 6. Enable and start services ---
echo "[6/6] Starting services..."
systemctl daemon-reload
systemctl enable --now minifw-ai
systemctl enable --now minifw-ai-web

echo ""
echo "============================================"
echo " MiniFW-AI installed and running"
echo "============================================"
echo ""
echo "  Engine:    systemctl status minifw-ai"
echo "  Dashboard: https://localhost:8443"
echo "  Logs:      journalctl -u minifw-ai -f"
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
