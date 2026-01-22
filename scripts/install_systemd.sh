#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
UNIT_DST="/etc/systemd/system/minifw-ai.service"

cp -f ./systemd/minifw-ai.service "${UNIT_DST}"

cat > "${APP_ROOT}/run_minifw.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=/opt/minifw_ai/app
exec /opt/minifw_ai/venv/bin/python -m minifw_ai
EOF
chmod +x "${APP_ROOT}/run_minifw.sh"

systemctl daemon-reload
systemctl enable --now minifw-ai

echo "Service installed & started: minifw-ai"
echo "Check: systemctl status minifw-ai --no-pager"
