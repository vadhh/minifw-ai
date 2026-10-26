---
title: Installer pipeline versus process substitution
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
The supported README one-liner pipes the downloaded installer script into privileged Bash. This works because sector selection reads from `/dev/tty`, leaving the pipe for script input. Keep the process-substitution command out of the documentation.
## Tried and ruled out
Trail conflict matching treats the words `sudo bash` in the supported pipeline as the same pattern as the rejected process-substitution form; the full command and its stdin behavior distinguish them.
## Watch out
The repo check may produce a lexical false positive when both command forms are mentioned in one learning. Verify the exact README code block before changing the supported pipeline.
