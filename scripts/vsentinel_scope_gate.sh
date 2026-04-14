#!/usr/bin/env bash
set -e

# VSentinel Scope Gate
# Validates that MINIFW_SECTOR is set to a recognised deployment sector
# before installation proceeds.

VALID_SECTORS="hospital education government finance legal establishment"

echo "[VSentinel] Initiating Scope Gate Scan..."

# 1. Sector presence check
if [[ -z "${MINIFW_SECTOR}" ]]; then
    echo "[VSentinel] CRITICAL: MINIFW_SECTOR is not set. Aborting."
    exit 1
fi

# 2. Sector validity check
SECTOR_VALID=0
for s in ${VALID_SECTORS}; do
    if [[ "${MINIFW_SECTOR}" == "${s}" ]]; then
        SECTOR_VALID=1
        break
    fi
done

if [[ "${SECTOR_VALID}" -ne 1 ]]; then
    echo "[VSentinel] CRITICAL: '${MINIFW_SECTOR}' is not a valid sector."
    echo "[VSentinel] Valid sectors: ${VALID_SECTORS}"
    exit 1
fi

echo "[VSentinel] Sector validated: ${MINIFW_SECTOR}"

# 3. Verify sector_lock.py references the sector
SECTOR_LOCK="$(dirname "$0")/../app/minifw_ai/sector_lock.py"
if [[ -f "${SECTOR_LOCK}" ]]; then
    if ! grep -q "${MINIFW_SECTOR}" "${SECTOR_LOCK}"; then
        echo "[VSentinel] WARNING: sector '${MINIFW_SECTOR}' not found in sector_lock.py — verify sector config."
    else
        echo "[VSentinel] sector_lock.py verified for sector: ${MINIFW_SECTOR}"
    fi
else
    echo "[VSentinel] WARNING: sector_lock.py not found at ${SECTOR_LOCK}, skipping config check."
fi

echo "[VSentinel] Scope Gate Passed."
exit 0
