#!/usr/bin/env bash
set -euo pipefail

BASE_VERSION="${2:-2.2.10}"
PKG_NAME="minifw-ai"
ARCH="amd64"
SECTOR="${1:-establishment}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${BASE_VERSION}-${SECTOR}"
BUILD_DIR="${REPO_DIR}/build/${PKG_NAME}_${VERSION}_${ARCH}"
DEB_OUTPUT="${REPO_DIR}/build/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Validate sector
VALID_SECTORS="hospital education government finance legal establishment"
if ! echo "${VALID_SECTORS}" | grep -qw "${SECTOR}"; then
    echo "ERROR: Invalid sector '${SECTOR}'"
    echo "Valid sectors: ${VALID_SECTORS}"
    exit 1
fi

if [[ ! "${BASE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid version '${BASE_VERSION}' (expected MAJOR.MINOR.PATCH)"
    exit 1
fi

echo "============================================"
echo " Building ${PKG_NAME} ${VERSION}"
echo " Sector:  ${SECTOR}"
echo " Output:  ${DEB_OUTPUT}"
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
cp "${REPO_DIR}/config/license_public_keys.json" "${BUILD_DIR}/opt/minifw_ai/config/"
cp "${REPO_DIR}"/config/feeds/*.txt "${BUILD_DIR}/opt/minifw_ai/config/feeds/"

# Sector-specific: copy modes/minifw_<product_mode>/ policy.
# Resolve product mode name early (finance → minifw_financial, others → minifw_<sector>).
case "${SECTOR}" in
    finance)    _PMODE="minifw_financial" ;;
    education)  _PMODE="minifw_school" ;;
    *)          _PMODE="minifw_${SECTOR}" ;;
esac
SECTOR_MODE_DIR="${REPO_DIR}/config/modes/${_PMODE}"
if [ -d "${SECTOR_MODE_DIR}" ]; then
    mkdir -p "${BUILD_DIR}/opt/minifw_ai/config/modes/${_PMODE}"
    cp "${SECTOR_MODE_DIR}/policy.json" \
       "${BUILD_DIR}/opt/minifw_ai/config/modes/${_PMODE}/policy.json"
    echo "  Sector policy: config/modes/${_PMODE}/policy.json"
fi

# --- Copy models ---
echo "[3/7] Copying ML models..."
cp "${REPO_DIR}/models/mlp_model.pkl" "${BUILD_DIR}/opt/minifw_ai/models/"
if [ -f "${REPO_DIR}/models/mlp_packet14.pkl" ]; then
    cp "${REPO_DIR}/models/mlp_packet14.pkl" "${BUILD_DIR}/opt/minifw_ai/models/"
fi

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
cp "${REPO_DIR}/scripts/enable_dnsmasq_logging.sh" "${BUILD_DIR}/opt/minifw_ai/scripts/"
cp "${REPO_DIR}/scripts/uninstall.sh" "${BUILD_DIR}/opt/minifw_ai/scripts/"
chmod +x "${BUILD_DIR}/opt/minifw_ai/scripts/"*.sh
mkdir -p "${BUILD_DIR}/etc/logrotate.d"
install -m 644 "${REPO_DIR}/scripts/minifw-ai.logrotate" "${BUILD_DIR}/etc/logrotate.d/minifw-ai"

# --- Systemd units ---
echo "[6/7] Installing systemd units..."
cp "${REPO_DIR}/systemd/minifw-ai.service" "${BUILD_DIR}/etc/systemd/system/"
cp "${REPO_DIR}/systemd/minifw-ai-web.service" "${BUILD_DIR}/etc/systemd/system/"
cp "${REPO_DIR}/systemd/minifw-ai-apply.path" "${REPO_DIR}/systemd/minifw-ai-apply.service" "${BUILD_DIR}/etc/systemd/system/"
# Bake the target sector and product mode into the service unit
sed -i "s/^Environment=MINIFW_SECTOR=.*/Environment=MINIFW_SECTOR=${SECTOR}/" \
    "${BUILD_DIR}/etc/systemd/system/minifw-ai.service"
# Bake PRODUCT_MODE and point MINIFW_POLICY at the sector-specific file.
# Sector "finance" maps to PRODUCT_MODE "minifw_financial" (not minifw_finance).
case "${SECTOR}" in
    finance)    PRODUCT_MODE="minifw_financial" ;;
    education)  PRODUCT_MODE="minifw_school" ;;
    *)          PRODUCT_MODE="minifw_${SECTOR}" ;;
esac
sed -i "/^Environment=PYTHONPATH=/a Environment=MINIFW_SECTOR=${SECTOR}\nEnvironment=PRODUCT_MODE=${PRODUCT_MODE}" \
    "${BUILD_DIR}/etc/systemd/system/minifw-ai-web.service"
SECTOR_POLICY_PATH="/opt/minifw_ai/config/modes/${PRODUCT_MODE}/policy.json"
if [ -f "${REPO_DIR}/config/modes/${PRODUCT_MODE}/policy.json" ]; then
    # Engine and dashboard must read and edit the same sector policy.
    sed -i "s|^Environment=MINIFW_POLICY=.*|Environment=MINIFW_POLICY=${SECTOR_POLICY_PATH}|" \
        "${BUILD_DIR}/etc/systemd/system/minifw-ai.service" \
        "${BUILD_DIR}/etc/systemd/system/minifw-ai-web.service"
    # Insert PRODUCT_MODE after MINIFW_SECTOR line if not already present
    if ! grep -q "^Environment=PRODUCT_MODE=" "${BUILD_DIR}/etc/systemd/system/minifw-ai.service"; then
        sed -i "/^Environment=MINIFW_SECTOR=/a Environment=PRODUCT_MODE=${PRODUCT_MODE}" \
            "${BUILD_DIR}/etc/systemd/system/minifw-ai.service"
    fi
    echo "  PRODUCT_MODE=${PRODUCT_MODE} baked into minifw-ai.service"
    echo "  MINIFW_POLICY → ${SECTOR_POLICY_PATH}"
fi
echo "  Sector '${SECTOR}' baked into minifw-ai.service"

# --- DEBIAN control files ---
echo "[7/7] Creating package metadata..."

cat > "${BUILD_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.10), python3-venv, nftables, openssl, conntrack, logrotate, adduser
Recommends: dnsmasq, zeek
Maintainer: Afridho Ikhsan <afridho@minifw.local>
Description: MiniFW-AI Behavioral Firewall Engine (ARCHANGEL 2.0) [${SECTOR}]
 AI-powered network behavioral firewall for gateway appliances.
 Features: DNS/flow analysis, MLP threat detection, YARA scanning,
 nftables enforcement, sector-specific policies, web admin dashboard.
 Sector: ${SECTOR}
 Supports 6 deployment sectors: education, hospital, government,
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

# --- Protect executable inputs before invoking the installed Python ---
# dpkg preserves ownership of pre-existing directories on upgrade.
[ ! -L "${APP_ROOT}" ] || { echo "Refusing symlinked ${APP_ROOT}" >&2; exit 1; }
chown root:root "${APP_ROOT}"
chmod 755 "${APP_ROOT}"
for protected_path in app prometheus scheduler models yara_rules scripts venv config requirements.txt; do
    target="${APP_ROOT}/${protected_path}"
    [ ! -L "${target}" ] || { echo "Refusing symlinked ${target}" >&2; exit 1; }
    [ -e "${target}" ] || continue
    # The venv legitimately links its Python binary to the system interpreter.
    if [ "${protected_path}" != venv ] && [ -n "$(find -P "${target}" -type l -print -quit)" ]; then
        echo "Refusing symlink inside ${target}" >&2; exit 1
    fi
    chown -hR root:root "${target}"
    find -P "${target}" -type d -exec chmod go-w {} +
    find -P "${target}" -type f -exec chmod go-w {} +
done

# --- 1. Python virtual environment ---
echo "[1/10] Python environment..."
if [ ! -d "${APP_ROOT}/venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv "${APP_ROOT}/venv"
fi
echo "  Installing dependencies..."
"${APP_ROOT}/venv/bin/python" -m pip install --upgrade pip -q 2>/dev/null || true
"${APP_ROOT}/venv/bin/pip" install -r "${APP_ROOT}/requirements.txt" -q

# --- Dashboard service account (no login, no capabilities) ---
WEB_USER="minifw-web"
STATE_DIR="/var/lib/minifw-ai"
if ! getent passwd "${WEB_USER}" >/dev/null; then
    adduser --system --group --no-create-home --home /nonexistent --shell /usr/sbin/nologin "${WEB_USER}" >/dev/null
fi
install -d -m 0750 -o "${WEB_USER}" -g "${WEB_USER}" "${STATE_DIR}"
# Move dashboard state written by earlier root-run versions.
if [ -f "${APP_ROOT}/minifw.db" ] && [ ! -e "${STATE_DIR}/minifw.db" ]; then
    # Services are stopped by prerm; move WAL companions too so committed writes are kept.
    for suffix in "" -wal -shm; do
        [ ! -e "${APP_ROOT}/minifw.db${suffix}" ] || mv "${APP_ROOT}/minifw.db${suffix}" "${STATE_DIR}/minifw.db${suffix}"
    done
fi
if [ -f /etc/minifw/license.json ] && [ ! -e "${STATE_DIR}/license.json" ]; then
    mv /etc/minifw/license.json "${STATE_DIR}/license.json"
fi
export MINIFW_DB_PATH="${STATE_DIR}/minifw.db"

# --- 2. Generate secrets ---
echo "[2/10] Secrets..."
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


# --- 3. Generate TLS certificate ---
echo "[3/10] TLS certificate..."
mkdir -p "${TLS_DIR}"
if [ ! -f "${TLS_DIR}/server.crt" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "${TLS_DIR}/server.key" \
        -out "${TLS_DIR}/server.crt" \
        -days 365 -nodes \
        -subj "/CN=minifw-ai/O=MiniFW-AI/C=ID" 2>/dev/null
    chmod 644 "${TLS_DIR}/server.crt"
    echo "  Self-signed certificate generated (365 days)."
else
    echo "  Certificate exists: ${TLS_DIR}/server.crt"
fi
# uvicorn reads the key as the dashboard user; minifw.env stays root-only (read by systemd).
chgrp "${WEB_USER}" "${TLS_DIR}/server.key"
chmod 640 "${TLS_DIR}/server.key"

# --- 4. Create admin user ---
echo "[4/10] Admin user..."
export PYTHONPATH="${APP_ROOT}/app"
# shellcheck disable=SC2046
export $(grep -v '^#' "${ENV_FILE}" | xargs)
cd "${APP_ROOT}"
# Run as the dashboard user: root must never open a database in a directory that user controls.
chown -R "${WEB_USER}:${WEB_USER}" "${STATE_DIR}"  # -R never follows symlinks (physical walk)
setpriv --reuid="${WEB_USER}" --regid="${WEB_USER}" --clear-groups \
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

# --- 5. Set permissions ---
echo "[5/10] Permissions..."
# Root owns code; the dashboard user owns only its state, logs group and editable config.
chmod 755 "${APP_ROOT}"
chmod -R 755 "${APP_ROOT}/app"
chmod 644 "${APP_ROOT}/config/policy.json"
chown -R "${WEB_USER}:${WEB_USER}" "${STATE_DIR}"
chgrp -R "${WEB_USER}" "${APP_ROOT}/logs"
chmod -R g+rX,o-rwx "${APP_ROOT}/logs"
chmod 2750 "${APP_ROOT}/logs"
touch "${APP_ROOT}/logs/audit.jsonl"
chmod 660 "${APP_ROOT}/logs/audit.jsonl"
# Dashboard edits feeds in place and replaces the sector policy by rename.
chgrp "${WEB_USER}" "${APP_ROOT}"/config/feeds/*.txt
chmod 664 "${APP_ROOT}"/config/feeds/*.txt
# The dashboard can create entries inside each mode directory, so never follow a link there:
# the web service is stopped (prerm) while this runs, and policy.json must be a regular file.
for mode_dir in "${APP_ROOT}"/config/modes/*/; do
    [ ! -L "${mode_dir%/}" ] || { echo "  Refusing symlinked mode directory ${mode_dir}" >&2; exit 1; }
    chgrp -h "${WEB_USER}" "${mode_dir}"
    chmod 2775 "${mode_dir}"
    policy_file="${mode_dir}policy.json"
    if [ -L "${policy_file}" ] || { [ -e "${policy_file}" ] && [ ! -f "${policy_file}" ]; }; then
        echo "  Refusing non-regular ${policy_file}" >&2; exit 1
    fi
    if [ -f "${policy_file}" ]; then
        chgrp -h "${WEB_USER}" "${policy_file}"
        chmod 664 "${policy_file}"
    fi
done

# --- 6. Load nf_conntrack kernel module ---
echo "[6/10] Flow tracking (nf_conntrack)..."
if ! lsmod | grep -q nf_conntrack; then
    modprobe nf_conntrack 2>/dev/null && echo "  nf_conntrack loaded." || echo "  Warning: could not load nf_conntrack (check kernel config)."
else
    echo "  nf_conntrack already loaded."
fi
if [ ! -f /etc/modules-load.d/minifw-conntrack.conf ]; then
    echo "nf_conntrack" > /etc/modules-load.d/minifw-conntrack.conf
    echo "  Persisted to /etc/modules-load.d/minifw-conntrack.conf"
fi

# --- 7. Restrict Grafana to localhost ---
echo "[7/10] Grafana hardening..."
GRAFANA_INI="/etc/grafana/grafana.ini"
if [ -f "${GRAFANA_INI}" ]; then
    if grep -qE "^;?http_addr\s*=" "${GRAFANA_INI}"; then
        sed -i 's/^;*http_addr\s*=.*/http_addr = 127.0.0.1/' "${GRAFANA_INI}"
    else
        sed -i '/^\[server\]/a http_addr = 127.0.0.1' "${GRAFANA_INI}"
    fi
    echo "  Grafana bound to 127.0.0.1"
    systemctl restart grafana-server 2>/dev/null && echo "  grafana-server restarted." || echo "  Warning: grafana-server restart failed (non-fatal)."
else
    echo "  grafana.ini not found — skipping (Grafana not installed)."
fi

# --- 8. Configure Zeek TLS/SNI collector ---
echo "[8/10] Zeek TLS collector..."
if command -v zeek >/dev/null 2>&1 || command -v zeekctl >/dev/null 2>&1; then
    ZEEK_SITE="/etc/zeek/site/local.zeek"
    if [ -f "${ZEEK_SITE}" ]; then
        # Ensure ssl.log is written
        if ! grep -q "frameworks/protocols/ssl/log" "${ZEEK_SITE}" 2>/dev/null; then
            echo "@load frameworks/protocols/ssl/log" >> "${ZEEK_SITE}"
            echo "  Added ssl.log to Zeek site config."
        else
            echo "  Zeek ssl.log already configured."
        fi
    fi
    # Start Zeek if not running
    if command -v zeekctl >/dev/null 2>&1; then
        zeekctl deploy 2>/dev/null && echo "  Zeek deployed." || echo "  Warning: zeekctl deploy failed (check zeekctl status)."
    fi
    echo "  Zeek TLS collector active — SNI scoring and TLS features enabled."
else
    echo "  Zeek not installed — Zeek TLS/SNI collection disabled."
    echo "  Optional packet metadata requires tshark and an explicit client interface."
    echo "  Install with: apt install zeek   then re-run: dpkg-reconfigure minifw-ai"
fi

# --- 9. Disable CUPS (not required on a firewall appliance) ---
echo "[9/10] Removing unnecessary services..."
systemctl stop cups cups-browsed 2>/dev/null || true
systemctl disable cups cups-browsed 2>/dev/null || true
echo "  CUPS disabled."

# --- 10. Enable and start services ---
echo "[10/10] Starting services..."
systemctl daemon-reload
systemctl enable --now minifw-ai
systemctl enable --now minifw-ai-web
systemctl enable --now minifw-ai-apply.path

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
systemctl disable --now minifw-ai-apply.path 2>/dev/null || true
systemctl stop minifw-ai-apply.service 2>/dev/null || true
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
    rm -rf /var/lib/minifw-ai
    rm -rf /etc/minifw
    echo "MiniFW-AI: Purged. Config feeds and models preserved in /opt/minifw_ai/"
fi

systemctl daemon-reload
POSTRM
chmod 755 "${BUILD_DIR}/DEBIAN/postrm"

CONFFILES_BASE="/opt/minifw_ai/config/policy.json
/opt/minifw_ai/config/feeds/allow_domains.txt
/opt/minifw_ai/config/feeds/deny_domains.txt
/opt/minifw_ai/config/feeds/deny_ips.txt
/opt/minifw_ai/config/feeds/deny_asn.txt
/opt/minifw_ai/config/feeds/tor_exit_nodes.txt
/opt/minifw_ai/config/feeds/asn_prefixes.txt"

CONFFILES_HOSPITAL="/opt/minifw_ai/config/feeds/healthcare_threats.txt"
CONFFILES_FINANCE="/opt/minifw_ai/config/feeds/financial_fraud.txt
/opt/minifw_ai/config/feeds/crypto_scams.txt
/opt/minifw_ai/config/modes/minifw_financial/policy.json"
CONFFILES_EDUCATION="/opt/minifw_ai/config/feeds/school_blacklist.txt
/opt/minifw_ai/config/modes/minifw_school/policy.json"
CONFFILES_GOVERNMENT="/opt/minifw_ai/config/feeds/government_sensitive.txt
/opt/minifw_ai/config/feeds/apt_indicators.txt
/opt/minifw_ai/config/modes/minifw_government/policy.json"
CONFFILES_LEGAL="/opt/minifw_ai/config/feeds/legal_threats.txt
/opt/minifw_ai/config/modes/minifw_legal/policy.json"
CONFFILES_ESTABLISHMENT="/opt/minifw_ai/config/modes/minifw_establishment/policy.json"

{
    echo "${CONFFILES_BASE}"
    if [ "${SECTOR}" = "hospital" ]; then
        echo "${CONFFILES_HOSPITAL}"
    fi
    if [ "${SECTOR}" = "finance" ]; then
        echo "${CONFFILES_FINANCE}"
    fi
    if [ "${SECTOR}" = "education" ]; then
        echo "${CONFFILES_EDUCATION}"
    fi
    if [ "${SECTOR}" = "government" ]; then
        echo "${CONFFILES_GOVERNMENT}"
    fi
    if [ "${SECTOR}" = "legal" ]; then
        echo "${CONFFILES_LEGAL}"
    fi
    if [ "${SECTOR}" = "establishment" ]; then
        echo "${CONFFILES_ESTABLISHMENT}"
    fi
} > "${BUILD_DIR}/DEBIAN/conffiles"

# --- Build the .deb ---
dpkg-deb --root-owner-group --build "${BUILD_DIR}" "${DEB_OUTPUT}"

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
