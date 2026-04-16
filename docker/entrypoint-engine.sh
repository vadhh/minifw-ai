#!/bin/bash
set -euo pipefail

cd /opt/minifw_ai
mkdir -p logs

# Pre-create dnsmasq.log so collector_dnsmasq.py doesn't spin in its
# "file not found" retry loop waiting for the injector.
touch logs/dnsmasq.log

echo "[ENGINE] Starting MiniFW-AI hospital sector daemon..."
exec python -m minifw_ai
