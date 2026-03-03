#!/usr/bin/env bash
# build_deb.sh — Build a minifw-ai sector .deb from the BASE source tree.
#
# Usage:  bash build_deb.sh <sector>
#   sector: hospital | education | government | finance | legal | establishment
#
# Run from the BASE minifw-ai directory (where app/, config/, yara_rules/ live).
set -euo pipefail

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------
SECTOR="${1:-}"
VALID_SECTORS="hospital education government finance legal establishment"

if [[ -z "${SECTOR}" ]]; then
    echo "Usage: bash build_deb.sh <sector>"
    echo "  sector: ${VALID_SECTORS// / | }"
    exit 1
fi

if ! echo "${VALID_SECTORS}" | grep -qw "${SECTOR}"; then
    echo "ERROR: unknown sector '${SECTOR}'"
    echo "  valid: ${VALID_SECTORS// / | }"
    exit 1
fi

# ---------------------------------------------------------------------------
# Sector-specific metadata
# ---------------------------------------------------------------------------
VERSION="1.0.0"

case "${SECTOR}" in
    hospital)
        PACKAGE="minifw-ai-hospital"
        INSTALL_ROOT="/opt/minifw_ai_hospital"
        ETC_DIR_NAME="minifw_ai_hospital"
        SERVICE_NAME="minifw-ai-hospital"
        DESCRIPTION_SHORT="MiniFW-AI Hospital Edition — Gateway Metadata Protection Layer"
        DESCRIPTION_LONG=\
"MiniFW-AI Hospital Edition is a network gateway protection system for
 healthcare environments. It analyses DNS and TLS SNI metadata to detect
 and block threats without requiring TLS inspection or browser proxies.
 .
 Detection engines: rule-based blocklists, burst/rate detection, MLP
 machine-learning scoring, and YARA pattern matching. Configured with
 hospital-grade sector lock to protect IoMT (Internet of Medical Things)
 subnets and enforce strict threat thresholds.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
    education)
        PACKAGE="minifw-ai-education"
        INSTALL_ROOT="/opt/minifw_ai_education"
        ETC_DIR_NAME="minifw_ai_education"
        SERVICE_NAME="minifw-ai-education"
        DESCRIPTION_SHORT="MiniFW-AI Education Edition — Education Sector Gateway Protection"
        DESCRIPTION_LONG=\
"MiniFW-AI Education Edition enforces SafeSearch, blocks VPNs and proxies,
 restricts AI tools during class hours, and applies stricter DDoS
 thresholds to protect school and university network environments.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
    government)
        PACKAGE="minifw-ai-government"
        INSTALL_ROOT="/opt/minifw_ai_government"
        ETC_DIR_NAME="minifw_ai_government"
        SERVICE_NAME="minifw-ai-government"
        DESCRIPTION_SHORT="MiniFW-AI Government Edition — Strict Audit and Geo-IP Gateway"
        DESCRIPTION_LONG=\
"MiniFW-AI Government Edition enforces Geo-IP restrictions, extended
 audit logging (365-day retention), and APT detection mode for
 government network environments.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
    finance)
        PACKAGE="minifw-ai-finance"
        INSTALL_ROOT="/opt/minifw_ai_finance"
        ETC_DIR_NAME="minifw_ai_finance"
        SERVICE_NAME="minifw-ai-finance"
        DESCRIPTION_SHORT="MiniFW-AI Finance Edition — PCI-DSS Compliant Gateway Protection"
        DESCRIPTION_LONG=\
"MiniFW-AI Finance Edition enforces strict TLS (minimum 1.2), blocks
 Tor and anonymizers, and applies PCI-DSS compliance mode for financial
 network environments.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
    legal)
        PACKAGE="minifw-ai-legal"
        INSTALL_ROOT="/opt/minifw_ai_legal"
        ETC_DIR_NAME="minifw_ai_legal"
        SERVICE_NAME="minifw-ai-legal"
        DESCRIPTION_SHORT="MiniFW-AI Legal Edition — Data Exfiltration Detection Gateway"
        DESCRIPTION_LONG=\
"MiniFW-AI Legal Edition detects large upload anomalies, enforces
 confidentiality mode, and applies strict monitoring thresholds for
 legal sector network environments.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
    establishment)
        PACKAGE="minifw-ai-establishment"
        INSTALL_ROOT="/opt/minifw_ai_establishment"
        ETC_DIR_NAME="minifw_ai_establishment"
        SERVICE_NAME="minifw-ai-establishment"
        DESCRIPTION_SHORT="MiniFW-AI Establishment Edition — SME/Retail Gateway Protection"
        DESCRIPTION_LONG=\
"MiniFW-AI Establishment Edition provides balanced gateway protection for
 SME and retail environments, including Cowrie honeypot awareness and
 VPN allowance from trusted network segments.
 .
 Installs to: ${INSTALL_ROOT}"
        ;;
esac

STAGING="$(pwd)/dist/${PACKAGE}_${VERSION}"
DEB_OUT="$(pwd)/dist/${PACKAGE}_${VERSION}.deb"

echo "==> Building ${PACKAGE} ${VERSION} (sector: ${SECTOR})"

# ---------------------------------------------------------------------------
# Clean staging
# ---------------------------------------------------------------------------
rm -rf "${STAGING}"
mkdir -p "${STAGING}"

# ---------------------------------------------------------------------------
# Helper: copy a tree, skipping __pycache__ and editor-leftover "copy" files
# ---------------------------------------------------------------------------
_copy_tree() {
    local src="$1" dst="$2"
    rsync -a \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        --exclude='* copy*.py' \
        --exclude='* copy *.py' \
        "${src}/" "${dst}/"
}

# ---------------------------------------------------------------------------
# DEBIAN packaging files (generated inline — no external template files needed)
# ---------------------------------------------------------------------------
DEB_DIR="${STAGING}/DEBIAN"
mkdir -p "${DEB_DIR}"

# control
cat > "${DEB_DIR}/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: all
Maintainer: RitAPI-AI <support@ritapi.ai>
Depends: python3 (>= 3.10), python3-venv, python3-pip, dnsmasq, nftables, ipset, openssl
Recommends: zeek
Section: net
Priority: optional
Description: ${DESCRIPTION_SHORT}
 ${DESCRIPTION_LONG}
EOF

# conffiles
cat > "${DEB_DIR}/conffiles" <<EOF
/etc/${ETC_DIR_NAME}/mode
${INSTALL_ROOT}/config/policy.json
${INSTALL_ROOT}/config/sector_lock.json
EOF

# postinst
cat > "${DEB_DIR}/postinst" <<POSTINST
#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${INSTALL_ROOT}"
ENV_DIR="/etc/${ETC_DIR_NAME}"
ENV_FILE="\${ENV_DIR}/minifw.env"
VENV="\${APP_ROOT}/venv"
SERVICE="${SERVICE_NAME}"

# 1. Directory permissions
mkdir -p "\${APP_ROOT}/logs" "\${APP_ROOT}/config/feeds"
chmod 750 "\${APP_ROOT}/logs"

# 2. Python virtual environment
if [[ ! -d "\${VENV}" ]]; then
    python3 -m venv "\${VENV}"
fi
"\${VENV}/bin/pip" install --quiet --upgrade pip
"\${VENV}/bin/pip" install --quiet -r "\${APP_ROOT}/requirements.txt"

# 3. Generate secrets (only on first install)
mkdir -p "\${ENV_DIR}"
chmod 750 "\${ENV_DIR}"

if [[ ! -f "\${ENV_FILE}" ]]; then
    SECRET_KEY=\$(openssl rand -hex 32)
    ADMIN_PASS=\$(openssl rand -base64 12)

    cat > "\${ENV_FILE}" <<EOF
MINIFW_SECRET_KEY=\${SECRET_KEY}
MINIFW_ADMIN_PASSWORD=\${ADMIN_PASS}
MINIFW_SECTOR=${SECTOR}
MINIFW_POLICY=\${APP_ROOT}/config/policy.json
MINIFW_FEEDS=\${APP_ROOT}/config/feeds
MINIFW_LOG=\${APP_ROOT}/logs/events.jsonl
MINIFW_FLOW_RECORDS=\${APP_ROOT}/logs/flow_records.jsonl
EOF
    chmod 600 "\${ENV_FILE}"

    echo ""
    echo "┌──────────────────────────────────────────────────────────────┐"
    echo "│   MiniFW-AI ${SECTOR^} — first-install credentials"
    echo "├──────────────────────────────────────────────────────────────┤"
    printf "│  Admin password: %-44s│\n" "\${ADMIN_PASS}"
    echo "│  Stored in: \${ENV_FILE}"
    echo "│  ⚠  Save this password — it will not be shown again.        │"
    echo "└──────────────────────────────────────────────────────────────┘"
    echo ""
fi

# 4. Sector lock: bake in the sector at install time
SECTOR_LOCK="\${APP_ROOT}/config/sector_lock.json"
if [[ ! -f "\${SECTOR_LOCK}" ]]; then
    SERIAL_SUFFIX=\$(openssl rand -hex 4 | tr '[:lower:]' '[:upper:]')
    cat > "\${SECTOR_LOCK}" <<EOF
{
    "sector": "${SECTOR}",
    "locked": true,
    "lock_reason": "Factory-set deployment configuration",
    "set_at": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "device_serial": "MINIFW-${SECTOR^^}-\${SERIAL_SUFFIX}",
    "_comment": "This file is factory-set and should not be modified by end users"
}
EOF
fi

# 5. Mode file (default: enforce)
MODE_FILE="\${ENV_DIR}/mode"
if [[ ! -f "\${MODE_FILE}" ]]; then
    echo "enforce" > "\${MODE_FILE}"
    chmod 644 "\${MODE_FILE}"
fi

# 6. ipset baseline
if command -v ipset &>/dev/null; then
    ipset create minifw_block_v4 hash:ip timeout 86400 -exist || true
fi

# 7. Systemd
systemctl daemon-reload
systemctl enable --now "\${SERVICE}" || true

echo "${PACKAGE} installed and started."
echo "Check: systemctl status \${SERVICE} --no-pager"

exit 0
POSTINST

# prerm
cat > "${DEB_DIR}/prerm" <<PRERM
#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE_NAME}"

if systemctl is-active --quiet "\${SERVICE}" 2>/dev/null; then
    systemctl stop "\${SERVICE}" || true
fi

if systemctl is-enabled --quiet "\${SERVICE}" 2>/dev/null; then
    systemctl disable "\${SERVICE}" || true
fi

exit 0
PRERM

# postrm
cat > "${DEB_DIR}/postrm" <<POSTRM
#!/usr/bin/env bash
set -euo pipefail

ACTION="\${1:-}"

systemctl daemon-reload 2>/dev/null || true

if [[ "\${ACTION}" == "purge" ]]; then
    rm -rf "${INSTALL_ROOT}"
    rm -rf "/etc/${ETC_DIR_NAME}"
    if command -v ipset &>/dev/null; then
        ipset destroy minifw_block_v4 2>/dev/null || true
    fi
    echo "${PACKAGE} purged."
fi

exit 0
POSTRM

chmod 755 \
    "${DEB_DIR}/postinst" \
    "${DEB_DIR}/prerm" \
    "${DEB_DIR}/postrm"

# ---------------------------------------------------------------------------
# Application files
# ---------------------------------------------------------------------------
APP="${STAGING}${INSTALL_ROOT}"
mkdir -p \
    "${APP}/app" \
    "${APP}/config/feeds" \
    "${APP}/logs" \
    "${APP}/models" \
    "${APP}/yara_rules"

# Engine (sector_rules/* are already part of the app tree)
_copy_tree app/minifw_ai "${APP}/app/minifw_ai"

# Web dashboard
_copy_tree app/web          "${APP}/app/web"
_copy_tree app/controllers  "${APP}/app/controllers" 2>/dev/null || true
_copy_tree app/services     "${APP}/app/services"
_copy_tree app/models       "${APP}/app/models"
_copy_tree app/middleware   "${APP}/app/middleware"
_copy_tree app/schemas      "${APP}/app/schemas"    2>/dev/null || true
[[ -f app/database.py ]] && cp app/database.py "${APP}/app/database.py"

# Config (sector_lock.json is written by postinst; include the template here)
cp config/policy.json      "${APP}/config/policy.json"
cp config/feeds/*.txt      "${APP}/config/feeds/" 2>/dev/null || true

# Bake a placeholder sector_lock.json so the path exists (postinst overwrites it)
cat > "${APP}/config/sector_lock.json" <<EOF
{
    "sector": "${SECTOR}",
    "locked": true,
    "lock_reason": "Factory-set deployment configuration",
    "_comment": "Overwritten by postinst on first install"
}
EOF

# Requirements & ML model (if present)
cp requirements.txt "${APP}/"
[[ -f models/mlp_engine.pkl ]] && cp models/mlp_engine.pkl "${APP}/models/"

# YARA rules — full subdirectory tree (not flat *.yar)
_copy_tree yara_rules "${APP}/yara_rules"

# Control script (if present)
if [[ -f scripts/ctl.sh ]]; then
    mkdir -p "${APP}/scripts"
    cp scripts/ctl.sh "${APP}/scripts/ctl.sh"
fi

# Startup wrapper — PYTHONPATH uses sector-specific install root
cat > "${APP}/run_minifw.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=${INSTALL_ROOT}/app
exec ${INSTALL_ROOT}/venv/bin/python -m minifw_ai
EOF
chmod +x "${APP}/run_minifw.sh"

# ---------------------------------------------------------------------------
# Mode file (/etc/<sector>/mode)
# ---------------------------------------------------------------------------
ETC_STAGING="${STAGING}/etc/${ETC_DIR_NAME}"
mkdir -p "${ETC_STAGING}"
echo "enforce" > "${ETC_STAGING}/mode"
chmod 644 "${ETC_STAGING}/mode"

# ---------------------------------------------------------------------------
# Systemd unit (generated inline)
# ---------------------------------------------------------------------------
SYSTEMD_DIR="${STAGING}/lib/systemd/system"
mkdir -p "${SYSTEMD_DIR}"

cat > "${SYSTEMD_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=MiniFW-AI ${SECTOR^} Edition (RitAPI-AI V-Sentinel — ${SECTOR^} Gateway)
Documentation=https://ritapi.ai/minifw-ai
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=simple
EnvironmentFile=/etc/${ETC_DIR_NAME}/minifw.env
ExecStart=${INSTALL_ROOT}/run_minifw.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Hardening
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# Fix permissions
# ---------------------------------------------------------------------------
find "${STAGING}" -type d -exec chmod 755 {} \;
find "${STAGING}" -type f -exec chmod 644 {} \;
chmod 755 "${APP}/run_minifw.sh"
[[ -f "${APP}/scripts/ctl.sh" ]] && chmod 755 "${APP}/scripts/ctl.sh"
chmod 755 \
    "${DEB_DIR}/postinst" \
    "${DEB_DIR}/prerm" \
    "${DEB_DIR}/postrm"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
mkdir -p dist
dpkg-deb --build "${STAGING}" "${DEB_OUT}"

echo ""
echo "Package built: ${DEB_OUT}"
echo ""
echo "Install on target:"
echo "  sudo dpkg -i ${DEB_OUT}"
echo "  sudo apt-get install -f   # resolve any missing deps"
