---
title: Ongoing verification is restricted to exact v2.2.10 lab packages
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
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
On 2 November the user explicitly restricted ongoing verification to v2.2.10. Test only the corrected 2.2.10-education and 2.2.10-finance packages in their separate minifw-monday QEMU guests. Before each run, check the installed dpkg version, selected Debian package name/version/architecture/SHA256, and byte-for-byte installed application/model/edition-policy files. The accepted C3 package hashes remain in dist/monday-corrections/SHA256SUMS; no rebuild is needed just to verify them.

## Tried and ruled out
Old packages and historical audit observations must not be included as new v2.2.10 acceptance results. Packaging identity and service startup alone do not establish working protection. Fresh verification uses actual namespace forwarding, kernel counters, controlled deny/flow decisions, failed client connections, expiry/manual recovery and duplicate/restart checks. Keep the synthetic model and unsupported feature claims separate.

## Watch out
Use only the authorized isolated guests, never install on the host's operational services or a client network. Save new evidence separately from previous runs. Copy only whitelisted public logs/JSON/nft snapshots, not TLS private keys or installer secrets. Report bypasses as observed allowed outcomes and retain all limitations; do not infer production readiness.
