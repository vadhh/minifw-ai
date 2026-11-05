---
title: Sendable assessment ZIPs contain prebuilt sector Debian installers
author: St4rdhoom
date: 2026-10-30
branch: main
touches:
  - README.md
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - pyproject.toml
  - requirements.txt
  - scripts/build_deb.sh
  - ".DS_Store"
  - ".serena/.gitignore"
  - ".serena/project.yml"
---

## Decided
For the CEO handoff the user requires two ZIPs containing already built Debian installers, not source kits requiring recipient builds. Created dist/production-assessment/minifw-ai-education-v2.2.9-installer.zip and minifw-ai-financial-v2.2.9-installer.zip, each with its sector .deb, checksum, INSTALL.md, ASSESSMENT.md, LICENSING.md and BUILD_MANIFEST.json. Recipients install on Ubuntu 22.04 / Debian 12 amd64 without building; APT/PyPI internet access remains required.

## Tried and ruled out
Docker is unavailable but is unnecessary to package this Python application. Installed native Homebrew dpkg and gnu-sed, then ran the existing scripts/build_deb.sh against each refreshed clean source kit. A temporary PATH shim selected gsed as sed and invoked real dpkg-deb with --root-owner-group -Zxz. No application code or maintainer script was rewritten. Source kits normalize shell and service CRLF to Linux LF, preserving original working files.

## Watch out
The successful build host was macOS, not Linux. Real dpkg-deb inspected and extracted both packages, metadata identified amd64 and sector versions, every payload member had root UID/GID, sector environments/policies matched, all conffiles existed and scripts passed Bash syntax checks. ZIP and extracted payload hashes were verified. Do not equate packaging checks with Linux install, browser, performance or routed-packet enforcement tests; those remain pending. Both packages share Debian name minifw-ai and should be assessed on separate gateways/snapshots. The older source-only learning describes the initial handoff and is superseded by these installable ZIPs for sending to the CEO.
