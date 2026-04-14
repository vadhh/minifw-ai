#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
UNIT_DST="/etc/systemd/system/minifw-ai.service"
ENV_DIR="/etc/minifw"
ENV_FILE="${ENV_DIR}/minifw.env"

# 1. Create Environment File
mkdir -p "${ENV_DIR}"
chmod 755 "${ENV_DIR}"

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
    chmod 600 "${ENV_FILE}"
    echo "✅ Generated new secrets."
    echo "⚠️  Admin Password: ${ADMIN_PASS}"
    echo "⚠️  Save this password! It is stored in ${ENV_FILE}"
else
    echo "✅ Environment file exists: ${ENV_FILE}"
fi

# 2. Update Systemd Unit to use EnvironmentFile
# We assume the source unit file doesn't have it, so we inject it or use a sed replacement if we copied it.
# Better: Write the unit file content directly here or modify the copied one.
# 2a. Install Firewall Engine service
UNIT_DST="/etc/systemd/system/minifw-ai.service"
cp -f ./systemd/minifw-ai.service "${UNIT_DST}"

# Inject EnvironmentFile directive into the [Service] section
if ! grep -q "EnvironmentFile=" "${UNIT_DST}"; then
    sed -i '/^\[Service\]/a EnvironmentFile=/etc/minifw/minifw.env' "${UNIT_DST}"
fi

cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=/opt/minifw_ai/app
exec /opt/minifw_ai/venv/bin/python -m minifw_ai
EOF
chmod +x "${APP_ROOT}/run_minifw.sh"

# 2b. Generate TLS certificate for web admin (self-signed)
TLS_DIR="${ENV_DIR}/tls"
mkdir -p "${TLS_DIR}"
if [[ ! -f "${TLS_DIR}/server.crt" ]]; then
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout "${TLS_DIR}/server.key" \
        -out "${TLS_DIR}/server.crt" -days 365 -nodes \
        -subj "/CN=minifw-ai/O=MiniFW-AI/C=ID" 2>/dev/null
    chmod 600 "${TLS_DIR}/server.key"
    chmod 644 "${TLS_DIR}/server.crt"
    echo "  TLS certificate generated (valid 365 days)."
else
    echo "  TLS certificate exists: ${TLS_DIR}/server.crt"
fi

# 2c. Install Web Admin service
WEB_UNIT_DST="/etc/systemd/system/minifw-ai-web.service"
cp -f ./systemd/minifw-ai-web.service "${WEB_UNIT_DST}"

# 3. Create admin user in database
echo "Creating admin user..."
export $(cat "${ENV_FILE}" | xargs)
export GAMBLING_ONLY=1
export PYTHONPATH="${APP_ROOT}/app"
cd "${APP_ROOT}"
"${APP_ROOT}/venv/bin/python" -c "
import os, sys
sys.path.insert(0, '${APP_ROOT}')
from app.database import SessionLocal, init_db
from app.services.auth.user_service import create_user
init_db()
db = SessionLocal()
try:
    # Check if admin already exists
    from app.models.user import User
    existing = db.query(User).filter(User.username == 'admin').first()
    if existing:
        print('Admin user already exists, skipping.')
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
        print(f'Admin user created: {admin.username} (super_admin)')
except Exception as e:
    print(f'Warning: Could not create admin user: {e}')
finally:
    db.close()
" 2>&1 || echo "Warning: Admin user creation failed (non-fatal)."

# 3b. Fix SQLite database permissions (writable for journal file)
chmod 664 "${APP_ROOT}/minifw.db" 2>/dev/null || true
chmod 775 "${APP_ROOT}" 2>/dev/null || true

# 4. Start services
systemctl daemon-reload
systemctl enable --now minifw-ai
systemctl enable --now minifw-ai-web

echo ""
echo "Services installed & started:"
echo "  minifw-ai      — Firewall engine daemon"
echo "  minifw-ai-web  — Web admin panel (https://localhost:8443)"
echo ""
echo "Check:"
echo "  systemctl status minifw-ai --no-pager"
echo "  systemctl status minifw-ai-web --no-pager"
