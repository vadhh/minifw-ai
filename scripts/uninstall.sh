#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

APP_ROOT="/opt/minifw_ai"
ENV_DIR="/etc/minifw"
CONF="/etc/dnsmasq.conf"
RESOLVED_CONF="/etc/systemd/resolved.conf"

echo "============================================"
echo " MiniFW-AI Uninstall"
echo "============================================"
echo ""
echo "This will remove all MiniFW-AI components and revert system changes."
read -r -p "Continue? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
    echo "Aborted."
    exit 0
fi

# ── 1. Stop and disable services ──
echo ""
echo "[1/6] Stopping services..."
for svc in minifw-ai minifw-ai-web; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}"
        echo "  Stopped ${svc}."
    fi
    if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        systemctl disable "${svc}"
        echo "  Disabled ${svc}."
    fi
done

# Remove systemd unit files
rm -f /etc/systemd/system/minifw-ai.service
rm -f /etc/systemd/system/minifw-ai-web.service
systemctl daemon-reload
echo "  Systemd units removed."

# ── 2. Remove application files ──
echo ""
echo "[2/6] Removing application files..."
if [ -d "${APP_ROOT}" ]; then
    rm -rf "${APP_ROOT}"
    echo "  Removed ${APP_ROOT}."
fi
if [ -d "${ENV_DIR}" ]; then
    rm -rf "${ENV_DIR}"
    echo "  Removed ${ENV_DIR}."
fi

# ── 3. Remove nftables rules ──
echo ""
echo "[3/6] Removing nftables rules..."
if nft list table inet minifw &>/dev/null; then
    nft delete table inet minifw
    echo "  Removed nftables table inet minifw."
else
    echo "  nftables table inet minifw not found, skipping."
fi

# ── 4. Revert dnsmasq config ──
echo ""
echo "[4/6] Reverting dnsmasq configuration..."
if [ -f "${CONF}" ]; then
    # Remove lines added by enable_dnsmasq_logging.sh
    sed -i '/^interface=/d' "${CONF}"
    sed -i '/^bind-interfaces/d' "${CONF}"
    sed -i '/^server=8\.8\.8\.8/d' "${CONF}"
    sed -i '/^server=8\.8\.4\.4/d' "${CONF}"
    sed -i '/^log-queries/d' "${CONF}"
    sed -i '/^log-facility=\/var\/log\/dnsmasq\.log/d' "${CONF}"
    echo "  dnsmasq.conf cleaned."
fi
rm -f /var/log/dnsmasq.log

# Stop dnsmasq (it was installed by the installer; leave the package but stop the service)
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true
echo "  dnsmasq stopped and disabled."

# ── 5. Restore systemd-resolved ──
echo ""
echo "[5/6] Restoring systemd-resolved..."
if [ -f "${RESOLVED_CONF}" ]; then
    if grep -q "^DNSStubListener=no" "${RESOLVED_CONF}" 2>/dev/null; then
        sed -i 's/^DNSStubListener=no/DNSStubListener=yes/' "${RESOLVED_CONF}"
        echo "  DNSStubListener restored to yes."
    fi
fi
# Restore resolv.conf symlink if we replaced it
if [ -f /etc/resolv.conf ] && ! [ -L /etc/resolv.conf ]; then
    if grep -q "^nameserver 127.0.0.1" /etc/resolv.conf 2>/dev/null; then
        rm -f /etc/resolv.conf
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        echo "  resolv.conf symlink restored."
    fi
fi
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved
    echo "  systemd-resolved restarted."
elif systemctl list-unit-files systemd-resolved.service &>/dev/null; then
    systemctl enable --now systemd-resolved 2>/dev/null || true
    echo "  systemd-resolved re-enabled."
fi

# ── 6. Remove installed packages ──
echo ""
echo "[6/6] Removing packages installed by MiniFW-AI..."
echo "  The following packages were installed by the installer: dnsmasq nftables"
read -r -p "  Remove them? [y/N] " remove_pkgs
if [[ "${remove_pkgs,,}" == "y" ]]; then
    apt-get remove -y -qq dnsmasq nftables 2>/dev/null || true
    apt-get autoremove -y -qq 2>/dev/null || true
    echo "  Packages removed."
else
    echo "  Skipped package removal."
fi

echo ""
echo "============================================"
echo " MiniFW-AI uninstalled successfully."
echo "============================================"
