#!/bin/bash
# MiniFW-AI Financial Demo — TLS Teardown
# Removes the demo CA from trust stores. Run after the meeting.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-teardown] $*"; }

log "Removing CA from system trust store..."
if [[ -f /usr/local/share/ca-certificates/minifw-demo-ca.crt ]]; then
    sudo rm -f /usr/local/share/ca-certificates/minifw-demo-ca.crt 2>/dev/null || true
    sudo update-ca-certificates --fresh 2>/dev/null || true
    log "Removed from system trust store."
else
    log "Not in system trust store — skipping."
fi

log "Removing CA from NSS databases..."
if command -v certutil >/dev/null 2>&1; then
    if [[ -d "$HOME/.pki/nssdb" ]]; then
        certutil -D -n "MiniFW Demo CA" -d sql:"$HOME/.pki/nssdb" 2>/dev/null || true
        log "Removed from ~/.pki/nssdb"
    fi
    while IFS= read -r -d '' profile; do
        certutil -D -n "MiniFW Demo CA" -d sql:"$profile" 2>/dev/null || true
        log "Removed from Firefox profile: $profile"
    done < <(find "$HOME/.mozilla/firefox" -name "cert9.db" -exec dirname {} \; 2>/dev/null | tr '\n' '\0')
fi

log "Removing local certs/..."
rm -rf certs/
mkdir -p certs && touch certs/.gitkeep

log "Teardown complete. Demo machine is clean."
