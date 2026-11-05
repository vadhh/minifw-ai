---
title: CEO assessment kits use native Linux source packaging
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
Education and Financial assessment ZIPs are generated with python3 scripts/build_assessment_zips.py into dist/production-assessment. They are explicitly source deployment assessments for native amd64 Linux gateways, using the existing scripts/build_deb.sh; they contain no prebuilt Debian installers. Each kit includes its selected policy, runtime modules/assets, model, feeds, helper scripts, public licensing keyring, assessment guide, exact file manifest, included working-tree changes and SHA-256 checksums.

## Tried and ruled out
This Mac has no dpkg-deb and Docker cannot connect to a daemon, so a Linux package build, installation and live packet enforcement cannot be claimed. Existing shell helpers have CRLF line endings that bash -n rejects; normalize shell scripts and systemd units inside the kits without modifying the original helpers. Do not include databases, logs, backups, private signing keys, environments or agent state.

## Watch out
The Financial builder sector is finance and its mode is minifw_financial; Education is education/minifw_school. Both Debian packages use the same minifw-ai package name, so assess on separate gateways/snapshots. Verify the extracted kit checksums and all literal build inputs. Linux installation and routed-traffic acceptance remain pending. trail check currently flags README.md:37 even though its existing curl-to-sudo-bash pipeline matches the stored recommended installer flow; the checker misreads the learning's quoted forbidden pattern. This task does not change README.md or installer flow. Existing CRLF additions in requirements.txt and pyproject.toml also trigger git diff --check; do not rewrite unrelated working-tree edits during packaging.
