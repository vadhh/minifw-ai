---
title: Supported installer pipeline and trail lexical check
author: St4rdhoom
date: 2026-10-26
branch: main
touches:
  - ".github/workflows/release.yml"
  - README.md
  - build_usb.sh
  - install.sh
  - pyproject.toml
  - scripts/build_deb.sh
  - scripts/enable_dnsmasq_logging.sh
  - testing/test_install_sh.sh
  - ".DS_Store"
  - ".gemini/settings.json"
---

## Decided
The public installer command `curl -fsSL URL | sudo bash` is the supported pipeline and is intentionally used in README.md; Bash process substitution (`sudo bash <(curl ...)`) is the unsupported form.
## Tried and ruled out
Changing the supported pipeline to avoid the words `sudo bash curl` would break the intended privileged stdin flow and conflict with the existing installer guidance.
## Watch out
`trail check` currently flags README.md because its lexical matcher sees `sudo bash` and `curl` in one command; the adjacent pipe operator makes this the valid form. Keep future checks aware of the distinction.
