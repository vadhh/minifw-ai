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
