#!/bin/bash
# scripts/nuke_and_clean.sh
set -e

echo "☢️  INITIATING DEEP CLEAN..."

# 1. Stop Service
if systemctl is-active --quiet minifw-ai; then
    echo "   Stopping service..."
    sudo systemctl stop minifw-ai
    sudo systemctl disable minifw-ai
fi

# 2. Remove Service File
if [ -f "/etc/systemd/system/minifw-ai.service" ]; then
    echo "   Removing systemd unit..."
    sudo rm /etc/systemd/system/minifw-ai.service
    sudo systemctl daemon-reload
fi

# 3. Destroy Installation Directory
if [ -d "/opt/minifw_ai" ]; then
    echo "   Removing /opt/minifw_ai..."
    sudo rm -rf /opt/minifw_ai
fi

# 4. Remove Sector Lock
if [ -f "/etc/minifw/sector.lock" ]; then
    echo "   Removing sector lock..."
    sudo rm /etc/minifw/sector.lock
fi

echo "✅ System is clean. Ready for install.sh"