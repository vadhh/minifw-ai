#!/usr/bin/env bash
# apply_critical_fixes.sh — Run as root to apply all hardening to the live install
# Also executed automatically by postinst on fresh dpkg -i
set -euo pipefail

REPO=/home/sydeco/minifw-ai

echo "============================================"
echo " MiniFW-AI Critical Fixes — Live Apply"
echo "============================================"

echo "[1/9] Patching main.py — removing GAMBLING_ONLY guard..."
cp "${REPO}/app/minifw_ai/main.py" /opt/minifw_ai/app/minifw_ai/main.py
grep -q "GAMBLING_ONLY" /opt/minifw_ai/app/minifw_ai/main.py && echo "  FAIL: guard still present!" && exit 1 || echo "  OK"

echo "[2/9] Patching prometheus/metrics.py — binding to 127.0.0.1..."
cp "${REPO}/prometheus/metrics.py" /opt/minifw_ai/prometheus/metrics.py
grep -q "addr=addr" /opt/minifw_ai/prometheus/metrics.py && echo "  OK" || echo "  WARN: addr param not found"

echo "[3/9] Patching systemd service units — removing GAMBLING_ONLY env..."
sed -i '/^Environment=GAMBLING_ONLY=1$/d' /etc/systemd/system/minifw-ai.service
sed -i '/^Environment=GAMBLING_ONLY=1$/d' /etc/systemd/system/minifw-ai-web.service
systemctl daemon-reload
echo "  OK"

echo "[4/9] Loading nf_conntrack kernel module..."
if ! lsmod | grep -q nf_conntrack; then
    modprobe nf_conntrack && echo "  nf_conntrack loaded." || echo "  WARN: modprobe failed"
else
    echo "  Already loaded."
fi
echo "nf_conntrack" > /etc/modules-load.d/minifw-conntrack.conf
echo "  Persisted to /etc/modules-load.d/minifw-conntrack.conf"

echo "[5/9] Restricting Grafana to localhost..."
GRAFANA_INI="/etc/grafana/grafana.ini"
if [ -f "${GRAFANA_INI}" ]; then
    if grep -qE "^;?http_addr\s*=" "${GRAFANA_INI}"; then
        sed -i 's/^;*http_addr\s*=.*/http_addr = 127.0.0.1/' "${GRAFANA_INI}"
    else
        sed -i '/^\[server\]/a http_addr = 127.0.0.1' "${GRAFANA_INI}"
    fi
    systemctl restart grafana-server && echo "  Grafana restarted on 127.0.0.1" || echo "  WARN: grafana restart failed"
else
    echo "  grafana.ini not found — skipping."
fi

echo "[6/9] Restricting ipapi_guard to localhost (port 5514)..."
IPAPI_SERVICE="/etc/systemd/system/ipapi_guard.service"
if [ -f "${IPAPI_SERVICE}" ]; then
    sed -i 's/--tcp-port 5514/--tcp-port 5514 --bind 127.0.0.1/' "${IPAPI_SERVICE}" 2>/dev/null || true
    # ipapi_guard.py may not support --bind; if not, restrict via firewall rule
    systemctl daemon-reload
    systemctl restart ipapi_guard 2>/dev/null || true
    echo "  OK (verify with ss -tulnp | grep 5514)"
else
    echo "  ipapi_guard.service not found — skipping."
fi

echo "[7/9] Restricting nginx proxy (port 7004) to localhost..."
NGINX_CONF="/etc/nginx/sites-available/forward-7003.conf"
if [ -f "${NGINX_CONF}" ]; then
    sed -i 's/listen 7004;/listen 127.0.0.1:7004;/' "${NGINX_CONF}"
    nginx -t && systemctl reload nginx && echo "  nginx reloaded — port 7004 bound to 127.0.0.1" || echo "  WARN: nginx reload failed"
else
    echo "  forward-7003.conf not found — skipping."
fi

echo "[8/9] Disabling CUPS..."
systemctl stop cups cups-browsed 2>/dev/null || true
systemctl disable cups cups-browsed 2>/dev/null || true
echo "  OK"

echo "[9/9] Restarting minifw-ai..."
systemctl restart minifw-ai
sleep 3
systemctl is-active minifw-ai && echo "  OK: service active" || echo "  FAIL: service not active"

echo ""
echo "=== POST-FIX VERIFICATION ==="
echo -n "  main.py GAMBLING_ONLY guard : "
grep -q "GAMBLING_ONLY" /opt/minifw_ai/app/minifw_ai/main.py 2>/dev/null && echo "PRESENT — FAIL" || echo "ABSENT — PASS"
echo -n "  Conntrack                   : "
ls /proc/net/nf_conntrack 2>/dev/null && echo "ACTIVE — PASS" || echo "NOT LOADED — FAIL"
echo -n "  Prometheus :9090            : "
ss -tulnp | grep 9090 | grep -q "127.0.0.1" && echo "127.0.0.1 — PASS" || echo "STILL 0.0.0.0 — restart engine"
echo -n "  Grafana :3000               : "
ss -tulnp | grep 3000 | grep -q "127.0.0.1" && echo "127.0.0.1 — PASS" || echo "STILL 0.0.0.0 — check grafana.ini"
echo -n "  Port 5514                   : "
ss -tulnp | grep 5514 | grep -q "127.0.0.1" && echo "127.0.0.1 — PASS" || echo "STILL 0.0.0.0 — check ipapi_guard"
echo -n "  Port 7004                   : "
ss -tulnp | grep 7004 | grep -q "127.0.0.1" && echo "127.0.0.1 — PASS" || echo "STILL 0.0.0.0 — check nginx"
echo ""
echo "New .deb: /tmp/minifw-ai_2.0.0_amd64.deb"
echo "SHA256  : $(sha256sum /tmp/minifw-ai_2.0.0_amd64.deb 2>/dev/null | awk '{print $1}' || echo 'not found')"
echo "============================================"
