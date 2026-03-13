#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi

CONF="/etc/dnsmasq.conf"
LOG="/var/log/dnsmasq.log"
RESOLVED_CONF="/etc/systemd/resolved.conf"

# ── 1. Disable systemd-resolved stub listener (holds port 53) ──
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "[1/4] Disabling systemd-resolved DNS stub listener..."
    if grep -q "^#\?DNSStubListener" "${RESOLVED_CONF}" 2>/dev/null; then
        sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' "${RESOLVED_CONF}"
    else
        echo "DNSStubListener=no" >> "${RESOLVED_CONF}"
    fi
    systemctl restart systemd-resolved

    # Point resolv.conf to localhost (dnsmasq will handle DNS)
    if [ -L /etc/resolv.conf ]; then
        rm /etc/resolv.conf
    fi
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo "  systemd-resolved stub listener disabled, resolv.conf updated."
else
    echo "[1/4] systemd-resolved not active, skipping."
fi

# ── 2. Configure dnsmasq upstream DNS + interface ──
echo "[2/4] Configuring dnsmasq..."

# Auto-detect primary active interface: prefer LAN (en*/eth*), fall back to WiFi (wl*)
detect_iface() {
    local iface
    # First pass: wired (en* or eth*)
    for iface in $(ip -o link show up | awk -F': ' '{print $2}' | grep -E '^(en|eth)'); do
        ip -o addr show dev "$iface" 2>/dev/null | grep -q 'inet ' && echo "$iface" && return
    done
    # Second pass: wireless (wl*)
    for iface in $(ip -o link show up | awk -F': ' '{print $2}' | grep '^wl'); do
        ip -o addr show dev "$iface" 2>/dev/null | grep -q 'inet ' && echo "$iface" && return
    done
}

ACTIVE_IFACE="$(detect_iface)"
if [ -z "${ACTIVE_IFACE}" ]; then
    echo "  WARNING: Could not detect an active network interface; skipping interface config."
else
    echo "  Detected active interface: ${ACTIVE_IFACE}"
    # Replace interface= lines and ensure bind-interfaces is set
    sed -i '/^interface=/d' "${CONF}"
    sed -i '/^bind-interfaces/d' "${CONF}"
    sed -i "1s/^/interface=lo\ninterface=${ACTIVE_IFACE}\nbind-interfaces\n/" "${CONF}"
fi

# Ensure dnsmasq has an upstream DNS server if not already set
if ! grep -q "^server=" "${CONF}" 2>/dev/null; then
    echo "server=8.8.8.8" >> "${CONF}"
    echo "server=8.8.4.4" >> "${CONF}"
    echo "  Added upstream DNS servers (8.8.8.8, 8.8.4.4)."
fi

# ── 3. Enable query logging ──
echo "[3/4] Enabling DNS query logging..."
touch "${LOG}" || true
chmod 640 "${LOG}" || true

grep -q "^log-queries" "${CONF}" 2>/dev/null || echo "log-queries" >> "${CONF}"
grep -q "^log-facility=" "${CONF}" 2>/dev/null || echo "log-facility=${LOG}" >> "${CONF}"

echo "  Logging to ${LOG}"

# ── 4. Restart dnsmasq ──
echo "[4/4] Restarting dnsmasq..."
systemctl restart dnsmasq
systemctl enable dnsmasq

echo ""
echo "Done. dnsmasq is running and logging DNS queries."
echo "Verify: dig google.com @127.0.0.1 && tail -5 ${LOG}"
