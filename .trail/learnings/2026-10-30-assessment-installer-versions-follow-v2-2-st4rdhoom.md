---
title: Assessment installer versions follow v2.2.10
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
The user corrected the CEO handoff version: use v2.2.10 (the existing local release tag), not stale 2.2.9 metadata. Updated pyproject.toml version and scripts/build_deb.sh default to 2.2.10, rebuilt both source kits and both prebuilt installer ZIPs, and verified real Debian Version fields 2.2.10-education and 2.2.10-finance with fresh checksums. Send dist/production-assessment/minifw-ai-education-v2.2.10-installer.zip and minifw-ai-financial-v2.2.10-installer.zip; earlier 2.2.9 artifacts are superseded.

## Tried and ruled out
Renaming the ZIPs alone is insufficient: rebuild the Debian control metadata, documentation, manifests and checksums. Select exact-version source archives when multiple versions coexist in the artifact folder.

## Watch out
The current working branch and v2.2.10 tag diverge. These ZIPs remain explicitly documented working-tree assessment snapshots, including licensing additions and the branch's corrected DNS policy paths; they are not byte-identical tagged release artifacts. Packaging and extracted payload checks passed; Linux installation and live enforcement were not tested.
