#!/bin/bash
# MiniFW-AI Financial Demo — TLS Setup
# Run once before the first demo. Requires sudo for trust store install.
# Safe to re-run — regenerates certs and re-installs CA.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { echo "[minifw-tls] $*"; }
die()  { echo "[minifw-tls] ERROR: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found — install: sudo apt-get install openssl"

mkdir -p certs
chmod 700 certs

CA_KEY=certs/minifw-ca.key
CA_CRT=certs/minifw-ca.crt
SRV_KEY=certs/server.key
SRV_CSR=certs/server.csr
SRV_CRT=certs/server.crt
EXT_FILE=certs/server.ext

log "Step 1: Generating CA key and certificate..."
openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
openssl req -new -x509 -days 825 \
    -key "$CA_KEY" \
    -out "$CA_CRT" \
    -subj "/CN=MiniFW Demo CA/O=MiniFW-AI/C=ID" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

log "Step 2: Generating server key and CSR..."
openssl genrsa -out "$SRV_KEY" 2048 2>/dev/null
openssl req -new -key "$SRV_KEY" -out "$SRV_CSR" \
    -subj "/CN=localhost/O=MiniFW-AI/C=ID"

cat > "$EXT_FILE" << 'EXT'
[SAN]
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT

log "Step 3: Signing server certificate with CA..."
openssl x509 -req -days 825 \
    -in "$SRV_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SRV_CRT" \
    -extfile "$EXT_FILE" \
    -extensions SAN 2>/dev/null

chmod 600 "$CA_KEY" "$SRV_KEY"
log "Certificates written to certs/"

log "Step 4: Installing CA to system trust store (requires sudo)..."
if [[ -d /usr/local/share/ca-certificates ]]; then
    if sudo cp "$CA_CRT" /usr/local/share/ca-certificates/minifw-demo-ca.crt 2>/dev/null && \
       sudo update-ca-certificates 2>/dev/null; then
        log "System trust store updated."
    else
        log "WARN: Could not install to system trust store (sudo failed or not available)."
        log "      Re-run with sudo if needed: sudo bash setup_tls.sh"
    fi
else
    log "WARN: /usr/local/share/ca-certificates not found — skipping system store."
fi

log "Step 5: Installing CA to NSS databases (Chrome/Firefox)..."
NSS_INSTALLED=false
if command -v certutil >/dev/null 2>&1; then
    # User NSS database
    if [[ -d "$HOME/.pki/nssdb" ]]; then
        certutil -A -n "MiniFW Demo CA" -t "CT,," \
            -i "$CA_CRT" -d sql:"$HOME/.pki/nssdb" 2>/dev/null && NSS_INSTALLED=true
        log "Installed to ~/.pki/nssdb"
    fi
    # Firefox profiles
    while IFS= read -r -d '' profile; do
        certutil -A -n "MiniFW Demo CA" -t "CT,," \
            -i "$CA_CRT" -d sql:"$profile" 2>/dev/null && NSS_INSTALLED=true
        log "Installed to Firefox profile: $profile"
    done < <(find "$HOME/.mozilla/firefox" -name "cert9.db" -exec dirname {} \; 2>/dev/null | tr '\n' '\0')
    if [[ "$NSS_INSTALLED" == "false" ]]; then
        log "WARN: No NSS databases found. Chrome/Firefox may show a cert warning."
        log "      Install libnss3-tools: sudo apt-get install libnss3-tools"
    fi
else
    log "WARN: certutil not found — skipping NSS install."
    log "      Install: sudo apt-get install libnss3-tools"
fi

log ""
log "TLS setup complete."
log "  CA:     $CA_CRT"
log "  Cert:   $SRV_CRT"
log "  Key:    $SRV_KEY"
log ""
log "Now run: bash run_demo.sh"
