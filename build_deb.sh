#!/usr/bin/env bash
# Wrapper — delegates to scripts/build_deb.sh which contains the full implementation.
exec "$(dirname "$0")/scripts/build_deb.sh" "$@"
