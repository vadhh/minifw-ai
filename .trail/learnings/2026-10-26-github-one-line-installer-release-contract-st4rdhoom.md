---
title: GitHub one-line installer release contract
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
The GitHub one-line installer release must build all six sector packages with the version parsed from the release tag and validate package metadata plus runtime assets before upload.
DNS logging remains optional. Its helper must check dnsmasq and required config files before changing host resolver state, then report a clean skip when prerequisites are absent.
## Tried and ruled out
Using `sudo bash <(curl ...)` is a poor fit for this installer because Bash process substitution consumes its stdin; document the curl-to-sudo-bash pipe instead.
A native `.deb` is not an offline install because postinst downloads Python dependencies from PyPI.
## Watch out
GitHub latest remains v2.2.8 until a corrected tagged release is published. Do not call the one-line flow live or verified on a clean host before that release is tested.
