#!/usr/bin/env bash
set -u

# Colors for scannability
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "🔍 Running MiniFW-AI System Integrity Check..."
echo "-----------------------------------------------"

# 1. Check Systemd Service
if systemctl is-active --quiet minifw-ai; then
    echo -e "[${GREEN}PASS${NC}] Service 'minifw-ai' is running."
else
    echo -e "[${RED}FAIL${NC}] Service 'minifw-ai' is STOPPED or CRASHED."
fi

# 2. Check NFTables Hooks
if nft list set inet filter minifw_block_v4 >/dev/null 2>&1; then
    echo -e "[${GREEN}PASS${NC}] NFTables 'minifw_block_v4' set is active in kernel."
else
    echo -e "[${RED}FAIL${NC}] NFTables set missing. The AI cannot block IPs."
fi

# 3. Check Sector Lock & Environment
if [[ -f "/etc/minifw/sector.lock" ]]; then
    SECTOR=$(grep -oP '(?<="sector": ")[^"]*' /etc/minifw/sector.lock)
    echo -e "[${GREEN}PASS${NC}] Sector Lock found: Active Persona -> ${SECTOR^^}"
else
    echo -e "[${RED}FAIL${NC}] /etc/minifw/sector.lock is missing. Persona unknown."
fi

# 4. Check Virtual Environment
if [[ -x "/opt/minifw_ai/venv/bin/python" ]]; then
    echo -e "[${GREEN}PASS${NC}] Python Virtual Environment is valid."
else
    echo -e "[${RED}FAIL${NC}] Venv is missing or corrupted at /opt/minifw_ai/venv."
fi

# 5. Check Log Output
if [[ -f "/opt/minifw_ai/logs/events.jsonl" ]]; then
    echo -e "[${GREEN}PASS${NC}] Event logs are being generated."
else
    echo -e "[${RED}WARN${NC}] No event logs found. (Normal if no traffic yet)."
fi

echo "-----------------------------------------------"
echo "Check complete."