#!/usr/bin/env bash
set -euo pipefail

# MiniFW-AI Testbed Initialization
# Usage: ./scripts/init_testbed.sh

TEST_ROOT="/tmp/minifw_testbed"
CONFIG_DIR="${TEST_ROOT}/config"
LOG_DIR="${TEST_ROOT}/logs"
SECRETS_DIR="${TEST_ROOT}/secrets"

echo "🚧 Initializing Testbed at ${TEST_ROOT}..."

# 1. Clean previous run
if [[ -d "${TEST_ROOT}" ]]; then
    echo "   Removing old testbed..."
    rm -rf "${TEST_ROOT}"
fi

# 2. Create Structure
mkdir -p "${CONFIG_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${SECRETS_DIR}"

# 3. Mock Sector Lock (Read-Only simulation target)
echo '{"sector": "education", "locked_at": "2024-01-01T00:00:00"}' > "${SECRETS_DIR}/sector.lock"
chmod 444 "${SECRETS_DIR}/sector.lock" # Read-only

# 4. Mock Policy (Read-Write)
cp config/policy.json "${CONFIG_DIR}/policy.json"

# 5. Generate Environment File
cat > "${TEST_ROOT}/.env" <<EOF
MINIFW_SECRET_KEY=test_secret_key_12345
MINIFW_ADMIN_PASSWORD=test_admin_pass
MINIFW_POLICY=${CONFIG_DIR}/policy.json
MINIFW_SECTOR_LOCK=${SECRETS_DIR}/sector.lock
EOF

# 6. Local Testbed Permissions
# Ensure the directory is accessible by the service user if needed
echo "   Setting permissions..."
chmod -R 777 "${TEST_ROOT}"

echo "✅ Testbed initialized."
echo "   To run tests locally:"
echo "   export PYTHONPATH=$(pwd):$(pwd)/app"
echo "   python3 -m pytest testing/"
echo "   "
echo "   Or use the TUI:"
echo "   python3 testing/run_tests_tui.py"
