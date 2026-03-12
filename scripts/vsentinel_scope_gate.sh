#!/usr/bin/env bash
set -e

# VSentinel Scope Gate
# Objective: Ensure the environment is configured for gambling-only deployment.
# This gate runs at install time to verify the GAMBLING_ONLY guard is active.

echo "[VSentinel] Initiating Scope Gate Scan..."

# 1. Environment Check
if [[ "${GAMBLING_ONLY}" != "1" ]]; then
    echo "[VSentinel] CRITICAL: GAMBLING_ONLY environment variable not set to '1'. Aborting."
    exit 1
fi

# 2. Verify GAMBLING_ONLY guard exists in main entry point
MAIN_PY="$(dirname "$0")/../app/minifw_ai/main.py"
if [[ -f "${MAIN_PY}" ]]; then
    if ! grep -q 'GAMBLING_ONLY' "${MAIN_PY}"; then
        echo "[VSentinel] CRITICAL: GAMBLING_ONLY guard missing from main.py!"
        exit 1
    fi
    echo "[VSentinel] GAMBLING_ONLY guard verified in main.py."
else
    echo "[VSentinel] WARNING: main.py not found at ${MAIN_PY}, skipping guard check."
fi

echo "[VSentinel] Scope Gate Passed."
exit 0
