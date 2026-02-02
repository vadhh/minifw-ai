#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# MiniFW-AI "One-Click" Hardened Installer
# Purpose: Automated deployment for Informatics Engineering Thesis/Gateway logic.
# Target: Debian/Ubuntu (Python 3.10+)
# ==============================================================================

if [[ $EUID -ne 0 ]]; then
   echo "❌ Error: This script must be run as root (sudo)." 
   exit 1
fi

# --- Configuration ---
APP_ROOT="/opt/minifw_ai"
CONFIG_DIR="/etc/minifw"
ENV_FILE="${CONFIG_DIR}/minifw.env"
SECTOR_FILE="${CONFIG_DIR}/sector.lock"
SERVICE_NAME="minifw-ai"
USER="minifw"
GROUP="minifw"
LOG_TARGET="/var/log/dnsmasq.log"

# Path Logic
REPO_ROOT=$(dirname "$(dirname "$(realpath "$0")")")
REQ_PATH="$REPO_ROOT/requirements.txt"

echo "🔒 Starting MiniFW-AI Hardened Deployment..."

# 0. Pre-flight: System Dependencies
# Required for YARA-python, Bcrypt, and Scikit-learn compilation
echo "   [0/7] Installing System Build Tools & Headers..."
apt-get update -y >/dev/null
apt-get install -y build-essential python3-dev python3-venv libssl-dev \
                   libffi-dev pkg-config whiptail nftables curl >/dev/null

# 1. User & Group Management
echo "   [1/7] Creating System User..."
if ! id -u "$USER" >/dev/null 2>&1; then
    useradd -r -s /bin/false "$USER"
    echo "         Created user: $USER"
fi
usermod -aG adm "$USER"

# 2. Prepare Application Directory
echo "   [2/7] Installing Code to $APP_ROOT..."
mkdir -p "$APP_ROOT"/{logs,config,models}

if [ -d "$REPO_ROOT/app" ]; then
    cp -r "$REPO_ROOT/app" "$APP_ROOT/"
    cp -r "$REPO_ROOT/config"/* "$APP_ROOT/config/" 2>/dev/null || true
    touch "$APP_ROOT/config/policy.json"
    mkdir -p "$APP_ROOT/config/feeds"
else
    echo "❌ Error: Could not find 'app' folder in $REPO_ROOT"
    exit 1
fi

# 3. Virtual Environment & Requirements
echo "   [3/7] Building Python Environment..."
if [ ! -d "$APP_ROOT/venv" ]; then
    python3 -m venv "$APP_ROOT/venv"
fi

# Upgrade core pip tools
"$APP_ROOT/venv/bin/pip" install --upgrade pip setuptools wheel >/dev/null

if [[ -f "$REQ_PATH" ]]; then
    echo "         Installing dependencies from requirements.txt..."
    "$APP_ROOT/venv/bin/pip" install -r "$REQ_PATH" >/dev/null
else
    echo "❌ Error: requirements.txt not found at $REQ_PATH"
    exit 1
fi

# --- CRITICAL FIX: FORCE PYTHON PATH via .pth ---
echo "   [Patch] Injecting Python Path Fix..."
SITE_PACKAGES=$(find "$APP_ROOT/venv/lib" -type d -name "site-packages" | head -n 1)
cat > "${SITE_PACKAGES}/minifw_paths.pth" <<EOF
${APP_ROOT}
${APP_ROOT}/app
EOF

# 4. Secret Management
echo "   [4/7] Securing Secrets..."
mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "         Generating new secrets..."
    cat > "$ENV_FILE" <<EOF
MINIFW_SECRET_KEY=$(openssl rand -hex 32)
MINIFW_ADMIN_PASSWORD=$(openssl rand -base64 12)
MINIFW_SECTOR_LOCK=${SECTOR_FILE}
EOF
else
    echo "         Preserving existing secrets."
    grep -q "MINIFW_SECTOR_LOCK" "$ENV_FILE" || echo "MINIFW_SECTOR_LOCK=${SECTOR_FILE}" >> "$ENV_FILE"
fi
chown root:$GROUP "$ENV_FILE"
chmod 640 "$ENV_FILE"

# 5. Sector Lock Initialization
SECTOR=""
if [[ -n "${1:-}" ]]; then
    SECTOR="$1"
elif command -v whiptail >/dev/null; then
    SECTOR=$(whiptail --title "MiniFW-AI Sector Selection" \
              --menu "Select the deployment sector for this gateway:" 15 60 6 \
              "school" "Content filtering, VPN blocking, Safe Search" \
              "hospital" "IoMT protection, Critical alert priority" \
              "finance" "Anonymizer blocking, High-audit mode" \
              "government" "Geo-IP strictness, Long-term retention" \
              "establishment" "General usage (Shops, Cafes)" 3>&1 1>&2 2>&3)
fi

SECTOR=${SECTOR:-school}
echo "   [5/7] Initializing Sector Lock ($(echo "$SECTOR" | tr '[:lower:]' '[:upper:]'))..."
echo "{\"sector\": \"${SECTOR,,}\", \"locked_at\": \"$(date -Iseconds)\"}" > "$SECTOR_FILE"
chown root:$GROUP "$SECTOR_FILE"
chmod 640 "$SECTOR_FILE"

# 6. Permissions & Entrypoint
echo "   [6/7] Finalizing Permissions..."
chown -R $USER:$GROUP "$APP_ROOT"
[[ -f "$LOG_TARGET" ]] && (chown root:adm "$LOG_TARGET"; chmod 640 "$LOG_TARGET")

# Grant invoking user ACL access for manual debugging (without breaking minifw ownership)
if [[ -n "${SUDO_USER:-}" ]] && command -v setfacl >/dev/null; then
    echo "         Granting ACL access to $SUDO_USER for manual debugging..."
    setfacl -R -m u:${SUDO_USER}:rwx "$APP_ROOT/logs/"
    setfacl -R -d -m u:${SUDO_USER}:rwx "$APP_ROOT/logs/"
fi

cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -e
# Initialize NFTables structures
nft add table inet filter 2>/dev/null || true
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null || true
nft 'add set inet filter minifw_block_v4 { type ipv4_addr ; flags timeout ; }' 2>/dev/null || true

# Execution using virtualenv python
exec /opt/minifw_ai/venv/bin/python -m app.minifw_ai.main
EOF
chmod 750 "${APP_ROOT}/run_minifw.sh"
chown $USER:$GROUP "${APP_ROOT}/run_minifw.sh"

# 7. Systemd Installation
echo "   [7/7] Installing Systemd Unit..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=MiniFW-AI (Gateway Metadata Layer)
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=simple
User=${USER}
Group=${GROUP}
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
EnvironmentFile=${ENV_FILE}
Environment=MINIFW_POLICY=${APP_ROOT}/config/policy.json
Environment=MINIFW_FEEDS=${APP_ROOT}/config/feeds
Environment=MINIFW_LOG=${APP_ROOT}/logs/events.jsonl
ExecStart=${APP_ROOT}/run_minifw.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "✅ DEPLOYMENT COMPLETE!"
echo "   Monitor: journalctl -u $SERVICE_NAME -f"