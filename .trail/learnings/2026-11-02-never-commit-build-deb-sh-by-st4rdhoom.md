---
title: Never commit build_deb.sh by zero-context partial patches
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
cost: { minutes: 21, tokens: 184775 }
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
scripts/build_deb.sh carries three uncommitted user edits (default version 2.2.10, license key copy, web-unit sector/product sed). To commit our own changes, write the working-tree file minus exactly those three edits into the index (git hash-object -w + git update-index --cacheinfo), then check that `git diff scripts/build_deb.sh` shows only the three user edits.

## Tried and ruled out
`git diff -U0` with hunk filtering, then `git apply --cached --unidiff-zero`: with no context, hunks land at wrong offsets once the file has many edits. In 885ccf43/715114ab this dropped the postinst permission block and moved `rm -rf /var/lib/minifw-ai` out of the purge branch. Repaired in cc51f0e9.

## Watch out
Source kits are built from the working tree, not from git, so lab results can pass while the committed file is wrong. After any partial staging, compare `git show HEAD:<file>` with the working tree minus the declared user edits. Python read_text/write_text also converts CRLF files (app/database.py, app/minifw_ai/state_manager.py) to LF; edit those in binary mode.
