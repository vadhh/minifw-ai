#!/bin/bash
set -euo pipefail

cd /opt/minifw_ai

echo "[WEB] Initialising database and admin user..."
# create_admin.py calls init_db() (idempotent) then creates the admin user.
# "|| true" absorbs the IntegrityError if the user already exists from a
# previous container run (volume persisted).
python scripts/create_admin.py || true

# Elevate admin to SUPER_ADMIN so all dashboard features are accessible.
python -c "
import sys
sys.path.insert(0, 'app')
from database import SessionLocal
from models.user import User, UserRole
db = SessionLocal()
u = db.query(User).filter(User.username == 'admin').first()
if u:
    u.role = UserRole.SUPER_ADMIN.value
    db.commit()
    print('[WEB] Admin role → SUPER_ADMIN')
db.close()
"

# Copy policy to the writable logs volume so the Web UI can update it.
# config/modes is a read-only bind-mount; logs/ (named volume) is writable.
# MINIFW_POLICY points to the seed (read-only); we shadow it with a writable copy.
POLICY_SEED="${MINIFW_POLICY:-/opt/minifw_ai/config/modes/minifw_hospital/policy.json}"
POLICY_WRITABLE="/opt/minifw_ai/logs/policy.json"
if [ ! -f "$POLICY_WRITABLE" ]; then
    cp "$POLICY_SEED" "$POLICY_WRITABLE"
    echo "[WEB] Policy seeded to writable volume: $POLICY_WRITABLE"
fi
export MINIFW_POLICY="$POLICY_WRITABLE"

echo "[WEB] Generating self-signed TLS certificate..."
if [ ! -f tls/server.crt ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout tls/server.key \
        -out    tls/server.crt \
        -days   365 \
        -nodes \
        -subj "/CN=minifw-${MINIFW_SECTOR:-demo}" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    echo "[WEB] TLS certificate generated."
fi

echo "[WEB] Dashboard → https://localhost:${MINIFW_EXTERNAL_PORT:-8443}   login: admin / ${MINIFW_ADMIN_PASSWORD}"
exec uvicorn web.app:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile tls/server.key \
    --ssl-certfile tls/server.crt
