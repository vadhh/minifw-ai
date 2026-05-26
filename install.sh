#!/usr/bin/env bash
# MiniFW-AI one-line installer
# Usage: curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
set -euo pipefail

MINIFW_REPO="vadhh/minifw-ai"
MINIFW_GPG_KEY_ID="BDB471E1FB46F58A"
MINIFW_VALID_SECTORS="hospital education government finance legal establishment"
MINIFW_ARCH="amd64"

# ── Helpers ──────────────────────────────────────────────────────────────────
_die()  { echo "[ERROR] $*" >&2; exit 1; }
_warn() { echo "[WARN]  $*" >&2; }
_info() { echo "[INFO]  $*"; }

# ── Pre-flight ────────────────────────────────────────────────────────────────
_check_root() {
    [[ $EUID -eq 0 ]] || _die "Run as root: curl -fsSL ... | sudo bash"
}

_check_os() {
    command -v dpkg &>/dev/null || _die "This installer requires Debian/Ubuntu (dpkg not found)"
    local os_id
    # shellcheck source=/dev/null
    os_id="$(. /etc/os-release 2>/dev/null && echo "${ID:-}")"
    case "${os_id}" in
        ubuntu|debian) ;;
        *) _die "Unsupported OS: '${os_id}'. Ubuntu and Debian are supported." ;;
    esac
}

_check_tools() {
    command -v sha256sum &>/dev/null || _die "sha256sum is required but not found (install coreutils)"
    command -v curl &>/dev/null || _die "curl is required but not found (sudo apt-get install curl)"
    command -v gpg &>/dev/null || _warn "Tool not found: gpg (GPG verification will be skipped)"
}

# ── Sector selection ──────────────────────────────────────────────────────────
_sector_menu() {
    echo ""
    echo "============================================"
    echo " MiniFW-AI Installer"
    echo "============================================"
    echo ""
    echo "Select deployment sector:"
    echo ""
    local i=1
    for s in $MINIFW_VALID_SECTORS; do
        echo "  ${i}) ${s}"
        i=$((i + 1))
    done
    echo ""
}

# Returns the sector name for a numeric choice 1-6, or empty string if invalid.
_sector_for_choice() {
    local choice="$1"
    local i=1
    for s in $MINIFW_VALID_SECTORS; do
        if [[ "$choice" == "$i" ]]; then
            echo "$s"
            return
        fi
        i=$((i + 1))
    done
    echo ""
}

_select_sector() {
    _sector_menu
    local sector=""
    while [[ -z "$sector" ]]; do
        read -rp "Enter number (1-6): " choice
        sector="$(_sector_for_choice "$choice")"
        [[ -z "$sector" ]] && echo "  Invalid choice. Please enter a number between 1 and 6."
    done
    echo "$sector"
}

# ── Version resolution ────────────────────────────────────────────────────────
# Accepts optional override via MINIFW_TAG env var (used in tests).
_resolve_tag() {
    if [[ -n "${MINIFW_TAG:-}" ]]; then
        echo "$MINIFW_TAG"
        return
    fi
    local resp
    resp="$(curl -fsSL "https://api.github.com/repos/${MINIFW_REPO}/releases/latest")"
    local tag
    tag="$(echo "$resp" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "$tag" ]] || _die "Could not determine latest release tag from GitHub API"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || _die "Unexpected tag format from GitHub API: '${tag}'"
    echo "$tag"
}

_version_from_tag() {
    local tag="$1"
    echo "${tag#v}"
}

_deb_name() {
    local version="$1" sector="$2"
    echo "minifw-ai_${version}-${sector}_${MINIFW_ARCH}.deb"
}

_base_url() {
    local tag="$1"
    echo "https://github.com/${MINIFW_REPO}/releases/download/${tag}"
}

# ── Download ──────────────────────────────────────────────────────────────────
_download_assets() {
    local base_url="$1" deb_name="$2" tmpdir="$3"
    _info "Downloading ${deb_name}..."
    curl -fsSL --progress-bar "${base_url}/${deb_name}"        -o "${tmpdir}/${deb_name}"
    curl -fsSL             "${base_url}/${deb_name}.sha256"    -o "${tmpdir}/${deb_name}.sha256"
    curl -fsSL             "${base_url}/${deb_name}.asc"       -o "${tmpdir}/${deb_name}.asc"       2>/dev/null || _warn "No GPG signature asset found"
    curl -fsSL             "${base_url}/minifw-ai-release.asc" -o "${tmpdir}/minifw-ai-release.asc" 2>/dev/null || _warn "No GPG public key asset found"
}

# ── Verification ──────────────────────────────────────────────────────────────
_verify_sha256() {
    local tmpdir="$1" deb_name="$2"
    _info "Verifying SHA-256 checksum..."
    (cd "${tmpdir}" && sha256sum -c "${deb_name}.sha256") \
        || _die "SHA-256 mismatch — download may be corrupted or tampered"
    _info "SHA-256 OK"
}

_verify_gpg() {
    local tmpdir="$1" deb_name="$2"
    local key_file="${tmpdir}/minifw-ai-release.asc"
    local asc_file="${tmpdir}/${deb_name}.asc"
    local deb_file="${tmpdir}/${deb_name}"
    local gpg_home="${tmpdir}/gnupg"

    if [[ ! -f "$key_file" ]] || [[ ! -f "$asc_file" ]]; then
        _warn "GPG assets missing — skipping GPG verification"
        return
    fi
    if ! command -v gpg &>/dev/null; then
        _warn "gpg not found — skipping GPG verification"
        return
    fi

    mkdir -p "${gpg_home}"
    chmod 700 "${gpg_home}"

    if ! gpg --homedir "${gpg_home}" --import "${key_file}" 2>/dev/null; then
        _warn "GPG key import failed — skipping GPG verification"
        return
    fi
    if ! gpg --homedir "${gpg_home}" --list-keys "${MINIFW_GPG_KEY_ID}" &>/dev/null; then
        _warn "Expected GPG key ${MINIFW_GPG_KEY_ID} not found in downloaded key asset — skipping GPG verification"
        return
    fi
    if gpg --homedir "${gpg_home}" --verify "${asc_file}" "${deb_file}" 2>/dev/null; then
        _info "GPG signature OK (key ${MINIFW_GPG_KEY_ID})"
    else
        _warn "GPG signature verification failed — proceeding (SHA-256 passed)"
    fi
}

# ── Install ───────────────────────────────────────────────────────────────────
_install_deb() {
    local tmpdir="$1" deb_name="$2"
    _info "Installing ${deb_name}..."
    if ! dpkg -i "${tmpdir}/${deb_name}"; then
        _info "Resolving missing dependencies..."
        apt-get install -f -y
    fi
    _info "Package installed"
}

# ── Post-install ──────────────────────────────────────────────────────────────
_run_post_install_script() {
    local script_name="$1"
    local path="/opt/minifw_ai/scripts/${script_name}"
    if [[ -x "$path" ]]; then
        _info "Running ${script_name}..."
        bash "$path" || _warn "${script_name} failed — run manually: sudo ${path}"
    else
        _warn "${script_name} not found at ${path} — skipping"
    fi
}

_post_install() {
    _run_post_install_script "enable_dnsmasq_logging.sh"
    _run_post_install_script "install_systemd.sh"
}

# ── Status report ─────────────────────────────────────────────────────────────
_print_summary() {
    local version="$1" sector="$2"
    echo ""
    echo "============================================"
    echo " MiniFW-AI installation complete!"
    echo "============================================"
    echo ""
    printf " Version:  %s\n" "$version"
    printf " Sector:   %s\n" "$sector"
    echo ""
    systemctl status minifw-ai --no-pager --lines=3 2>/dev/null || true
    echo ""
    echo " Admin credentials: /etc/minifw/minifw.env"
    printf " Web panel:         https://%s:8443\n" "$(hostname -f 2>/dev/null || hostname)"
    echo ""
    echo " Verify:"
    echo "   systemctl status minifw-ai --no-pager"
    echo "   systemctl status minifw-ai-web --no-pager"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    _check_root
    _check_os
    _check_tools

    local sector
    sector="$(_select_sector)"
    _info "Sector selected: ${sector}"

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT

    local tag version base_url deb_name
    tag="$(_resolve_tag)"
    version="$(_version_from_tag "$tag")"
    base_url="$(_base_url "$tag")"
    deb_name="$(_deb_name "$version" "$sector")"
    _info "Latest version: ${version} (${tag})"

    _download_assets "$base_url" "$deb_name" "$tmpdir"
    _verify_sha256 "$tmpdir" "$deb_name"
    _verify_gpg "$tmpdir" "$deb_name"
    _install_deb "$tmpdir" "$deb_name"
    _post_install
    _print_summary "$version" "$sector"
}

# Allow sourcing for tests without running main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
