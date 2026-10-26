---
title: Canonical privileged one-line installer command
author: St4rdhoom
date: 2026-10-26
branch: fix/dns-helper-lf
touches:
  - DEVELOPER.md
  - README.md
  - pyproject.toml
  - scripts/build_deb.sh
  - scripts/enable_dnsmasq_logging.sh
  - testing/test_install_sh.sh
---

## Decided
The documented GitHub installer one-liner remains `curl -fsSL URL | sudo bash`; the pipe feeds the installer script on stdin and preserves the intended privileged execution path.

## Tried and ruled out
`sudo bash <(curl ...)` is not a reliable substitute because process substitution does not preserve the intended stdin flow through sudo.

## Watch out
The current trail lexical check can misread the valid pipe as `sudo bash curl`; explain this documented contract in the PR or commit rationale.
