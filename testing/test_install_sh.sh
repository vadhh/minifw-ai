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
