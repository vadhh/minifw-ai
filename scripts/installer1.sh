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
echo "   [1/6] Creating System User..."
if ! id -u "$USER" >/dev/null 2>&1; then
    useradd -r -s /bin/false "$USER"
    echo "         Created user: $USER"
fi
# Add user to 'adm' group to read system logs (dnsmasq/zeek)
usermod -aG adm "$USER"

# 2. Secret Management (Environment File)
echo "   [2/6] Securing Secrets..."
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
    # Ensure Sector Lock var exists in current env file
    if ! grep -q "MINIFW_SECTOR_LOCK" "$ENV_FILE"; then
        echo "MINIFW_SECTOR_LOCK=${SECTOR_FILE}" >> "$ENV_FILE"
    fi
fi

# Set Permissions: Root owns, Group (minifw) reads, Others see nothing.
chown root:$GROUP "$ENV_FILE"
chmod 640 "$ENV_FILE"

# 3. Sector Lock Initialization
# --- SECTOR SELECTION LOGIC ---
SECTOR=""

# 1. Check Command Line Argument (Automation Friendly)
if [[ -n "${1:-}" ]]; then
    SECTOR="$1"
    echo "   [!] Sector selected via argument: $SECTOR"
fi

# 2. TUI Selection (Human Friendly)
if [[ -z "$SECTOR" ]]; then
    # Check if whiptail is available
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
        # Fallback for systems without whiptail
        echo "   [?] Select Sector (school/hospital/finance/government/legal/establishment):"
        read -r SECTOR
    fi
fi

# 3. Final Validation & Default
if [[ -z "$SECTOR" ]]; then
    echo "   [!] No sector selected. Defaulting to 'school'."
    SECTOR="school"
fi

# Convert to lowercase just in case
SECTOR=$(echo "$SECTOR" | tr '[:upper:]' '[:lower:]')

echo "   [3/6] Initializing Sector Lock ($SECTOR)..."
echo "{\"sector\": \"$SECTOR\", \"locked_at\": \"$(date -Iseconds)\"}" > "$SECTOR_FILE"
chown root:$GROUP "$SECTOR_FILE"
chmod 640 "$SECTOR_FILE"

# 4. Application Permissions
echo "   [4/6] Fixing App Permissions..."
# Fix ownership of the app directory
chown -R $USER:$GROUP "$APP_ROOT"

# Ensure target log file exists and is readable by 'adm' group
if [[ -f "$LOG_TARGET" ]]; then
    chown root:adm "$LOG_TARGET"
    chmod 640 "$LOG_TARGET"
else
    echo "⚠️  Warning: $LOG_TARGET not found. Ensure Dnsmasq is installed."
fi

# 5. Create Firewall Wrapper (The 'nft' Loader)
echo "   [5/6] Creating Firewall Wrapper..."
cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -e

# Initialize NFTables (Safe Mode)
# We add the table/chains if they don't exist to avoid flushing unrelated rules
nft add table inet filter 2>/dev/null || true
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null || true
nft 'add set inet filter minifw_block_v4 { type ipv4_addr ; flags timeout ; }' 2>/dev/null || true

# Start the Application
# PYTHONPATH must include BOTH:
#   /opt/minifw_ai     - for "from app.minifw_ai..." imports
#   /opt/minifw_ai/app - for "from minifw_ai..." internal imports
export PYTHONPATH=/opt/minifw_ai:/opt/minifw_ai/app
exec /opt/minifw_ai/venv/bin/python -m app.minifw_ai.main
EOF

chmod 750 "${APP_ROOT}/run_minifw.sh"
chown $USER:$GROUP "${APP_ROOT}/run_minifw.sh"

# 6. Install Systemd Service
echo "   [6/6] Installing Systemd Unit..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=MiniFW-AI (RitAPI-AI V-Sentinel - Gateway Metadata Layer)
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=simple
User=${USER}
Group=${GROUP}
# Grant Network Capabilities to unprivileged user
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

EnvironmentFile=${ENV_FILE}
Environment=MINIFW_POLICY=${APP_ROOT}/config/policy.json
Environment=MINIFW_FEEDS=${APP_ROOT}/config/feeds
Environment=MINIFW_LOG=${APP_ROOT}/logs/events.jsonl

ExecStart=${APP_ROOT}/run_minifw.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Reload and Restart
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "✅ DONE! MiniFW-AI is hardened and running."
echo "   User: $USER (reading logs via 'adm' group)"
echo "   Logs: journalctl -u $SERVICE_NAME -f"