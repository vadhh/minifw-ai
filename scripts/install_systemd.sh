#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
UNIT_DST="/etc/systemd/system/minifw-ai.service"
ENV_DIR="/etc/minifw"
ENV_FILE="${ENV_DIR}/minifw.env"
USER="minifw"
GROUP="minifw"

# 1. Create User and Group
if ! id -u "$USER" >/dev/null 2>&1; then
    echo "Creating system user: $USER"
    useradd -r -s /bin/false "$USER"
fi

# 2. Create Environment File and set Permissions
mkdir -p "${ENV_DIR}"
chmod 750 "${ENV_DIR}"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Creating secure environment file: ${ENV_FILE}"
    
    # Generate random secret key (32 bytes hex)
    SECRET_KEY=$(openssl rand -hex 32)
    # Generate random admin password if not provided
    ADMIN_PASS=$(openssl rand -base64 12)
    
    cat > "${ENV_FILE}" <<EOF
MINIFW_SECRET_KEY=${SECRET_KEY}
MINIFW_ADMIN_PASSWORD=${ADMIN_PASS}
EOF
else
    echo "✅ Environment file exists: ${ENV_FILE}"
fi

# Set ownership to root:minifw and 640 so service can read it, but others cannot
chown root:$GROUP "${ENV_FILE}"
chmod 640 "${ENV_FILE}"
chown root:$GROUP "${ENV_DIR}"

# 3. Directories Ownership
# Grant minifw ownership of app directory (for logs/temp files)
chown -R $USER:$GROUP "${APP_ROOT}"

# 4. Generate Firewall Init Wrapper
# This script initializes nftables tables/chains BEFORE starting the app.
# It runs with the service's privileges (CAP_NET_ADMIN required).
cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "Initializing NFTables..."
# Flush ruleset to strictly define our state (WARNING: clears existing rules)
# nft flush ruleset # CAUTION: We might not want to flush everything if other services use nft
# Safer: Initialize our specific table
nft add table inet filter 2>/dev/null || true
# Create forward chain if not exists. Note escaped semi-colons for bash.
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy accept ; }' 2>/dev/null || true
# Create the set if not exists (app/enforce.py also does this, but good to be sure)
nft 'add set inet filter minifw_block_v4 { type ipv4_addr ; flags timeout ; }' 2>/dev/null || true

# PYTHONPATH must include BOTH:
#   /opt/minifw_ai     - for "from app.minifw_ai..." imports  
#   /opt/minifw_ai/app - for "from minifw_ai..." internal imports
export PYTHONPATH=/opt/minifw_ai:/opt/minifw_ai/app
echo "Starting MiniFW-AI..."
exec /opt/minifw_ai/venv/bin/python -m app.minifw_ai.main
EOF
chmod 750 "${APP_ROOT}/run_minifw.sh"
chown $USER:$GROUP "${APP_ROOT}/run_minifw.sh"

# 5. Create Systemd Unit directly
# We inject User, Group, AmbientCapabilities (for nftables), and EnvironmentFile using header merging
echo "Creating systemd unit: ${UNIT_DST}"
cat > "${UNIT_DST}" <<EOF
[Unit]
Description=MiniFW-AI (RitAPI-AI V-Sentinel - Gateway Metadata Layer)
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=simple
User=${USER}
Group=${GROUP}
# Grant permission to manage network (nftables) without being fully root
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

systemctl daemon-reload
systemctl enable --now minifw-ai

# 6. Install Logrotate Configuration for Audit Logs
echo "Installing logrotate configuration for audit logs..."
LOGROTATE_SRC="${APP_ROOT}/config/minifw-audit.logrotate"
LOGROTATE_DST="/etc/logrotate.d/minifw-audit"

if [[ -f "${LOGROTATE_SRC}" ]]; then
    cp "${LOGROTATE_SRC}" "${LOGROTATE_DST}"
    chmod 644 "${LOGROTATE_DST}"
    chown root:root "${LOGROTATE_DST}"
    echo "✅ Logrotate configuration installed: ${LOGROTATE_DST}"
    
    # Test logrotate configuration
    echo "Testing logrotate configuration (dry-run)..."
    logrotate -d "${LOGROTATE_DST}" 2>&1 | head -20
else
    echo "⚠️  Logrotate configuration not found at ${LOGROTATE_SRC}"
fi

echo "Service installed & started: minifw-ai (User: $USER)"
echo "Check: systemctl status minifw-ai --no-pager"
