#!/bin/bash
# MiniFW-AI Education Demo — TLS Setup
# Generates a local CA + signed certificate for localhost.
# Installs CA in the OS trust store (requires sudo once).
# Run once per demo machine. Re-running is safe (idempotent).
#
# After running: browser opens https://localhost:8443 with green padlock.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CERTS_DIR="docker/certs"
CA_KEY="$CERTS_DIR/minifw-demo-ca.key"
CA_CRT="$CERTS_DIR/minifw-demo-ca.crt"
SERVER_KEY="$CERTS_DIR/server.key"
SERVER_CRT="$CERTS_DIR/server.crt"
SERVER_CSR="$CERTS_DIR/server.csr"
EXT_FILE="$CERTS_DIR/san.ext"

log() { echo "[tls-setup] $*"; }
die() { echo "[tls-setup] ERROR: $*" >&2; exit 1; }

trap 'rm -f "${SERVER_CSR:-}" "${EXT_FILE:-}"' EXIT

command -v openssl >/dev/null 2>&1 || die "openssl not found — install openssl and retry"

mkdir -p "$CERTS_DIR"

# Skip CA generation if CA already exists
if [[ -f "$CA_KEY" && -f "$CA_CRT" ]]; then
    log "CA already exists — skipping CA generation."
else
    log "Generating local CA..."
    openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
    chmod 600 "$CA_KEY"
    openssl req -x509 -new -nodes \
        -key "$CA_KEY" \
        -sha256 -days 3650 \
        -out "$CA_CRT" \
        -subj "/CN=MiniFW Demo CA/O=MiniFW Demo/C=US" 2>/dev/null
    log "CA generated: $CA_CRT"
fi

# Always regenerate server cert (ensures it's signed by current CA)
log "Generating server certificate for localhost..."

openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null
chmod 600 "$SERVER_KEY"

openssl req -new \
    -key "$SERVER_KEY" \
    -out "$SERVER_CSR" \
    -subj "/CN=localhost/O=MiniFW Demo/C=US" 2>/dev/null

cat > "$EXT_FILE" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req \
    -in "$SERVER_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$SERVER_CRT" \
    -days 825 \
    -sha256 \
    -extfile "$EXT_FILE" \
    -extensions v3_req 2>/dev/null

rm -f "$SERVER_CSR" "$EXT_FILE"
log "Server certificate generated: $SERVER_CRT"

# Install CA in OS trust store
log "Installing CA in OS trust store (requires sudo)..."

if [[ "$(uname)" == "Linux" ]]; then
    if command -v update-ca-certificates >/dev/null 2>&1; then
        if sudo cp "$CA_CRT" /usr/local/share/ca-certificates/minifw-demo-ca.crt 2>/dev/null && \
           sudo update-ca-certificates 2>/dev/null; then
            log "CA installed (Linux — update-ca-certificates)."
        else
            log "WARNING: sudo not available. Manual step:"
            log "  sudo cp $(pwd)/$CA_CRT /usr/local/share/ca-certificates/minifw-demo-ca.crt"
            log "  sudo update-ca-certificates"
        fi
    else
        log "WARNING: update-ca-certificates not found."
        log "Manual step: copy $CA_CRT to your system CA store and update it."
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    if sudo security add-trusted-cert \
        -d -r trustRoot \
        -k /Library/Keychains/System.keychain \
        "$CA_CRT" 2>/dev/null; then
        log "CA installed (macOS — Keychain)."
    else
        log "WARNING: sudo not available. Manual step:"
        log "  Open Keychain Access → System → File → Import Items"
        log "  Import: $(pwd)/$CA_CRT  then mark as 'Always Trust'"
    fi
else
    log "Unsupported OS. Manual step:"
    log "  Install $CA_CRT as a trusted root CA in your browser/OS."
fi

log ""
log "TLS setup complete."
log "Run HEALTHCHECK.sh to verify browser trust."
log ""
log "Dashboard will be available at: https://localhost:8447"
log ""
log "NOTE: Firefox uses its own trust store."
log "  To trust the cert in Firefox:"
log "  Preferences → Privacy & Security → View Certificates → Authorities → Import"
log "  Import: $CA_CRT  (check 'Trust this CA to identify websites')"
