#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# MiniFW-AI "One-Click" Hardened Installer
# ==========================================

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

echo "🔒 Starting MiniFW-AI Hardened Deployment..."

# 1. User & Group Management
echo "   [1/7] Creating System User..."
if ! id -u "$USER" >/dev/null 2>&1; then
    useradd -r -s /bin/false "$USER"
    echo "         Created user: $USER"
fi
# Add user to 'adm' group to read system logs (dnsmasq/zeek)
usermod -aG adm "$USER"

# 2. Prepare Application Directory
echo "   [2/7] Installing Code to $APP_ROOT..."
# Create directory structure
mkdir -p "$APP_ROOT"
mkdir -p "$APP_ROOT/logs"
mkdir -p "$APP_ROOT/config"

# Copy application files (Assuming we are running from the repo root)
# If script is run from ./scripts/, repo root is ..
REPO_ROOT=$(dirname "$(dirname "$(realpath "$0")")")

if [ -d "$REPO_ROOT/app" ]; then
    cp -r "$REPO_ROOT/app" "$APP_ROOT/"
    cp -r "$REPO_ROOT/config"/* "$APP_ROOT/config/" 2>/dev/null || true
    # Create empty policy/feeds if missing
    touch "$APP_ROOT/config/policy.json"
    mkdir -p "$APP_ROOT/config/feeds"
else
    echo "❌ Error: Could not find 'app' folder in $REPO_ROOT"
    exit 1
fi

# 3. Create Virtual Environment & Install Deps
echo "   [3/7] Building Python Environment..."
if [ ! -d "$APP_ROOT/venv" ]; then
    python3 -m venv "$APP_ROOT/venv"
fi

# Install dependencies inside venv
"$APP_ROOT/venv/bin/pip" install --upgrade pip >/dev/null
# Install minimal requirements (Add more if needed)
"$APP_ROOT/venv/bin/pip" install pytest sqlalchemy scikit-learn pandas python-jose[cryptography] yara-python >/dev/null

# --- CRITICAL FIX: FORCE PYTHON PATH via .pth ---
echo "   [Patch] Injecting Python Path Fix..."
SITE_PACKAGES=$(find "$APP_ROOT/venv/lib" -type d -name "site-packages" | head -n 1)
cat > "${SITE_PACKAGES}/minifw_paths.pth" <<EOF
${APP_ROOT}
${APP_ROOT}/app
EOF
# ------------------------------------------------

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
    if ! grep -q "MINIFW_SECTOR_LOCK" "$ENV_FILE"; then
        echo "MINIFW_SECTOR_LOCK=${SECTOR_FILE}" >> "$ENV_FILE"
    fi
fi
chown root:$GROUP "$ENV_FILE"
chmod 640 "$ENV_FILE"

# 5. Sector Lock Initialization
# --- SECTOR SELECTION LOGIC ---
SECTOR=""

if [[ -n "${1:-}" ]]; then
    SECTOR="$1"
    echo "   [!] Sector selected via argument: $SECTOR"
fi

if [[ -z "$SECTOR" ]]; then
    if command -v whiptail >/dev/null; then
        SECTOR=$(whiptail --title "MiniFW-AI Sector Selection" \
                  --menu "Select the deployment sector for this gateway:" 15 60 6 \
                  "school" "Content filtering, VPN blocking, Safe Search" \
                  "hospital" "IoMT protection, Critical alert priority" \
                  "finance" "Anonymizer blocking, High-audit mode" \
                  "government" "Geo-IP strictness, Long-term retention" \
                  "legal" "Privileged traffic handling" \
                  "establishment" "General usage (Shops, Cafes)" \
                  3>&1 1>&2 2>&3)
    else
        echo "   [?] Select Sector (school/hospital/finance/government/legal/establishment):"
        read -r SECTOR
    fi
fi

if [[ -z "$SECTOR" ]]; then
    SECTOR="school"
fi
SECTOR=$(echo "$SECTOR" | tr '[:upper:]' '[:lower:]')

echo "   [5/7] Initializing Sector Lock ($SECTOR)..."
echo "{\"sector\": \"$SECTOR\", \"locked_at\": \"$(date -Iseconds)\"}" > "$SECTOR_FILE"
chown root:$GROUP "$SECTOR_FILE"
chmod 640 "$SECTOR_FILE"

# 6. Application Permissions & Wrapper
echo "   [6/7] Finalizing Permissions..."
chown -R $USER:$GROUP "$APP_ROOT"

if [[ -f "$LOG_TARGET" ]]; then
    chown root:adm "$LOG_TARGET"
    chmod 640 "$LOG_TARGET"
fi

# Create Wrapper
cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -e
# Initialize NFTables
nft add table inet filter 2>/dev/null || true
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null || true
nft 'add set inet filter minifw_block_v4 { type ipv4_addr ; flags timeout ; }' 2>/dev/null || true

# Start App (Path is handled by .pth file now)
exec /opt/minifw_ai/venv/bin/python -m app.minifw_ai.main
EOF

chmod 750 "${APP_ROOT}/run_minifw.sh"
chown $USER:$GROUP "${APP_ROOT}/run_minifw.sh"

# 7. Install Systemd Service
echo "   [7/7] Installing Systemd Unit..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=MiniFW-AI (RitAPI-AI V-Sentinel - Gateway Metadata Layer)
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
# Explicitly set the MLP model path if you have one, or comment out
# Environment=MINIFW_MLP_MODEL=${APP_ROOT}/models/mlp_engine.pkl

ExecStart=${APP_ROOT}/run_minifw.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "✅ DONE! MiniFW-AI is hardened and running."
echo "   Logs: journalctl -u $SERVICE_NAME -f"