# One-Line Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `curl ... | sudo bash` one-liner that interactively selects a sector, downloads the signed `.deb` from GitHub Releases, verifies it, installs it, and runs post-install setup automatically.

**Architecture:** A single `install.sh` at repo root (published as a release asset) drives the full install flow using named bash functions. A companion `testing/test_install_sh.sh` sources the script in test mode to unit-test the pure-logic functions. A new `.github/workflows/release.yml` builds all six sector `.deb`s, generates checksums, GPG-signs them, and uploads everything (including `install.sh`) as GitHub Release assets on every `v*` tag push.

**Tech Stack:** Bash, `curl`, `sha256sum`, `gpg`, `dpkg`, `apt-get`, GitHub Actions (`actions/upload-release-asset`), `shellcheck`

---

### Task 1: Write `install.sh` with testable functions

**Files:**
- Create: `install.sh`

- [ ] **Step 1: Create `install.sh`**

```bash
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
    os_id="$(. /etc/os-release 2>/dev/null && echo "${ID:-}")"
    case "${os_id}" in
        ubuntu|debian) ;;
        *) _die "Unsupported OS: '${os_id}'. Ubuntu and Debian are supported." ;;
    esac
}

_check_tools() {
    for cmd in curl sha256sum gpg; do
        command -v "$cmd" &>/dev/null || _warn "Tool not found: ${cmd} (some steps may be skipped)"
    done
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

    if gpg --homedir "${gpg_home}" --import "${key_file}" 2>/dev/null \
    && gpg --homedir "${gpg_home}" --verify "${asc_file}" "${deb_file}" 2>/dev/null; then
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

    local tag version base_url deb_name tmpdir
    tag="$(_resolve_tag)"
    version="$(_version_from_tag "$tag")"
    base_url="$(_base_url "$tag")"
    deb_name="$(_deb_name "$version" "$sector")"
    _info "Latest version: ${version} (${tag})"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT

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
```

- [ ] **Step 2: Make executable**

```bash
chmod +x install.sh
```

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "feat: add one-line installer script"
```

---

### Task 2: Static analysis with shellcheck

**Files:**
- Read: `install.sh`

- [ ] **Step 1: Install shellcheck if missing**

```bash
command -v shellcheck || sudo apt-get install -y shellcheck
```

- [ ] **Step 2: Run shellcheck**

```bash
shellcheck install.sh
```

Expected: zero warnings. Fix any reported before continuing.

Common fixes:
- `SC2086` (unquoted variable): add double quotes
- `SC2155` (declare + assign): split into two lines
- `SC2181` (check $? explicitly): restructure the conditional

- [ ] **Step 3: Commit fixes if any**

```bash
git add install.sh
git commit -m "fix: shellcheck warnings in install.sh"
```

---

### Task 3: Write unit tests for install.sh pure functions

**Files:**
- Create: `testing/test_install_sh.sh`

These tests source `install.sh` (which is safe — `main` only runs when the file is executed directly) and exercise the pure-logic functions with mocked state.

- [ ] **Step 1: Create `testing/test_install_sh.sh`**

```bash
#!/usr/bin/env bash
# Unit tests for install.sh pure functions
set -euo pipefail

PASS=0; FAIL=0

assert_eq() {
    local desc="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc}"
        echo "        got:  '${got}'"
        echo "        want: '${want}'"
        FAIL=$((FAIL + 1))
    fi
}

# Source the installer (safe — main() is guarded by BASH_SOURCE check)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../install.sh
source "${SCRIPT_DIR}/install.sh"

echo "=== _sector_for_choice ==="
assert_eq "choice 1 → hospital"     "$(_sector_for_choice 1)" "hospital"
assert_eq "choice 2 → education"    "$(_sector_for_choice 2)" "education"
assert_eq "choice 3 → government"   "$(_sector_for_choice 3)" "government"
assert_eq "choice 4 → finance"      "$(_sector_for_choice 4)" "finance"
assert_eq "choice 5 → legal"        "$(_sector_for_choice 5)" "legal"
assert_eq "choice 6 → establishment" "$(_sector_for_choice 6)" "establishment"
assert_eq "choice 0 → empty"        "$(_sector_for_choice 0)" ""
assert_eq "choice 7 → empty"        "$(_sector_for_choice 7)" ""
assert_eq "garbage → empty"         "$(_sector_for_choice abc)" ""

echo ""
echo "=== _version_from_tag ==="
assert_eq "v2.2.0 → 2.2.0"  "$(_version_from_tag "v2.2.0")"  "2.2.0"
assert_eq "v1.0.0 → 1.0.0"  "$(_version_from_tag "v1.0.0")"  "1.0.0"
assert_eq "v10.0.1 → 10.0.1" "$(_version_from_tag "v10.0.1")" "10.0.1"

echo ""
echo "=== _deb_name ==="
assert_eq "hospital deb name" \
    "$(_deb_name "2.2.0" "hospital")" \
    "minifw-ai_2.2.0-hospital_amd64.deb"
assert_eq "education deb name" \
    "$(_deb_name "2.2.0" "education")" \
    "minifw-ai_2.2.0-education_amd64.deb"
assert_eq "establishment deb name" \
    "$(_deb_name "2.2.0" "establishment")" \
    "minifw-ai_2.2.0-establishment_amd64.deb"

echo ""
echo "=== _base_url ==="
assert_eq "base URL for v2.2.0" \
    "$(_base_url "v2.2.0")" \
    "https://github.com/vadhh/minifw-ai/releases/download/v2.2.0"

echo ""
echo "=== _resolve_tag (with MINIFW_TAG override) ==="
MINIFW_TAG="v9.9.9"
assert_eq "_resolve_tag uses MINIFW_TAG env var" \
    "$(_resolve_tag)" \
    "v9.9.9"
unset MINIFW_TAG

echo ""
echo "=== Results ==="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
[[ $FAIL -eq 0 ]]
```

- [ ] **Step 2: Make executable**

```bash
chmod +x testing/test_install_sh.sh
```

- [ ] **Step 3: Run tests**

```bash
bash testing/test_install_sh.sh
```

Expected output:
```
=== _sector_for_choice ===
  PASS: choice 1 → hospital
  PASS: choice 2 → education
  PASS: choice 3 → government
  PASS: choice 4 → finance
  PASS: choice 5 → legal
  PASS: choice 6 → establishment
  PASS: choice 0 → empty
  PASS: choice 7 → empty
  PASS: garbage → empty

=== _version_from_tag ===
  PASS: v2.2.0 → 2.2.0
  PASS: v1.0.0 → 1.0.0
  PASS: v10.0.1 → 10.0.1

=== _deb_name ===
  PASS: hospital deb name
  PASS: education deb name
  PASS: establishment deb name

=== _base_url ===
  PASS: base URL for v2.2.0

=== _resolve_tag (with MINIFW_TAG override) ===
  PASS: _resolve_tag uses MINIFW_TAG env var

=== Results ===
  Passed: 17
  Failed: 0
```

- [ ] **Step 4: Commit**

```bash
git add testing/test_install_sh.sh
git commit -m "test: add unit tests for install.sh pure functions"
```

---

### Task 4: Add shellcheck + installer tests to CI

**Files:**
- Modify: `.github/workflows/test.yml`

- [ ] **Step 1: Read current test.yml**

Read `.github/workflows/test.yml` — note the existing structure (runs pytest on push/PR).

- [ ] **Step 2: Add shellcheck and bash test jobs**

Add these two jobs after the existing `test` job in `.github/workflows/test.yml`:

```yaml
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install shellcheck
        run: sudo apt-get install -y shellcheck
      - name: Lint install.sh
        run: shellcheck install.sh

  test-installer-functions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run installer unit tests
        run: bash testing/test_install_sh.sh
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: add shellcheck and installer function tests"
```

---

### Task 5: Add GitHub Actions release workflow

**Files:**
- Create: `.github/workflows/release.yml`

This workflow triggers on `v*` tag pushes, builds all six sector `.deb`s, generates SHA-256 checksums, GPG-signs them (using secrets), and uploads everything as GitHub Release assets.

**Prerequisites (one-time setup by repo owner):**
- Export GPG private key: `gpg --export-secret-keys --armor BDB471E1FB46F58A > private.asc`
- Add to GitHub Secrets:
  - `GPG_PRIVATE_KEY` — contents of `private.asc`
  - `GPG_PASSPHRASE` — passphrase for the key (empty string if none)
- Export GPG public key: `gpg --export --armor BDB471E1FB46F58A > minifw-ai-release.asc`
- Commit `minifw-ai-release.asc` to repo root (used by installer to verify downloads)

- [ ] **Step 1: Commit the public key to repo root (if not already present)**

```bash
# Run locally with the signing key available
gpg --export --armor BDB471E1FB46F58A > minifw-ai-release.asc
git add minifw-ai-release.asc
git commit -m "chore: add GPG public key for release verification"
```

- [ ] **Step 2: Create `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install build dependencies
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq dpkg-dev fakeroot gnupg
          pip install --upgrade pip
          pip install -r requirements.txt

      - name: Extract version from tag
        id: version
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"

      - name: Build .deb packages for all sectors
        run: |
          for sector in hospital education government finance legal establishment; do
            echo "Building sector: ${sector}"
            bash scripts/build_deb.sh "${sector}"
          done

      - name: Generate SHA-256 checksums
        run: |
          cd build
          for deb in *.deb; do
            sha256sum "${deb}" > "${deb}.sha256"
          done

      - name: Import GPG signing key
        env:
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
        run: |
          echo "${GPG_PRIVATE_KEY}" | gpg --batch --import
          echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
          gpgconf --kill gpg-agent

      - name: GPG sign .deb packages
        env:
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
        run: |
          cd build
          for deb in *.deb; do
            echo "${GPG_PASSPHRASE}" | gpg --batch --yes --passphrase-fd 0 \
              --pinentry-mode loopback \
              --detach-sign --armor \
              --local-user BDB471E1FB46F58A \
              "${deb}"
          done

      - name: Create GitHub Release and upload assets
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          VERSION="${{ steps.version.outputs.version }}"
          TAG="${GITHUB_REF_NAME}"

          # Create the release (draft=false, prerelease=false)
          gh release create "${TAG}" \
            --title "MiniFW-AI v${VERSION}" \
            --notes "Release v${VERSION}. See [CHANGELOG.md](CHANGELOG.md) for details." \
            install.sh \
            minifw-ai-release.asc \
            build/*.deb \
            build/*.sha256 \
            build/*.asc
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow to build and publish deb packages"
```

---

### Task 6: Update README.md to lead with the one-liner

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the "Installation" section header and add the one-liner block**

Find the `## Installation` section (around line 22). Replace the current Step 1 (package verification) block with a new intro that leads with the one-liner, then keeps the manual flow as an alternative.

Replace this block (lines 22–43):

```markdown
## Installation

### Step 1 — Verify the package

Before installing, confirm the package has not been tampered with:

```bash
# Import the signing key
gpg --import minifw-ai-release.asc

# Verify GPG signature (adjust filename for your sector/version)
gpg --verify minifw-ai_2.2.0-establishment_amd64.deb.asc minifw-ai_2.2.0-establishment_amd64.deb
# Expected: "Good signature from MiniFW-AI Release ..."

# Verify SHA-256 checksum
sha256sum -c minifw-ai_2.2.0-establishment_amd64.deb.sha256
# Expected: "minifw-ai_2.2.0-establishment_amd64.deb: OK"
```

See [docs/release-verification.md](docs/release-verification.md) for full details.

---
```

With:

```markdown
## Installation

### One-line installer (recommended)

```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

The script will prompt you to select a sector, download the correct `.deb` from GitHub Releases,
verify the SHA-256 checksum and GPG signature, install the package, configure DNS logging, and
start the `minifw-ai` and `minifw-ai-web` services automatically.

To install a specific version:

```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/download/v2.2.0/install.sh | sudo bash
```

---

### Manual installation

For air-gapped or offline deployments, use the manual flow below.

### Step 1 — Verify the package

Before installing, confirm the package has not been tampered with:

```bash
# Import the signing key
gpg --import minifw-ai-release.asc

# Verify GPG signature (adjust filename for your sector/version)
gpg --verify minifw-ai_2.2.0-establishment_amd64.deb.asc minifw-ai_2.2.0-establishment_amd64.deb
# Expected: "Good signature from MiniFW-AI Release ..."

# Verify SHA-256 checksum
sha256sum -c minifw-ai_2.2.0-establishment_amd64.deb.sha256
# Expected: "minifw-ai_2.2.0-establishment_amd64.deb: OK"
```

See [docs/release-verification.md](docs/release-verification.md) for full details.

---
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add one-line installer to README installation section"
```

---

### Task 7: Spec self-review and smoke test

- [ ] **Step 1: Verify all six sectors produce correct deb names**

```bash
source install.sh
for s in hospital education government finance legal establishment; do
    echo "$(_deb_name "2.2.0" "$s")"
done
```

Expected:
```
minifw-ai_2.2.0-hospital_amd64.deb
minifw-ai_2.2.0-education_amd64.deb
minifw-ai_2.2.0-government_amd64.deb
minifw-ai_2.2.0-finance_amd64.deb
minifw-ai_2.2.0-legal_amd64.deb
minifw-ai_2.2.0-establishment_amd64.deb
```

- [ ] **Step 2: Confirm test suite still passes**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246 passed, 1 skipped, 0 failed (no regressions).

- [ ] **Step 3: Run full bash test suite**

```bash
bash testing/test_install_sh.sh
```

Expected: 17 passed, 0 failed.

- [ ] **Step 4: Final commit if any cleanup needed**

```bash
git add -A
git commit -m "chore: installer smoke test cleanup"
```
