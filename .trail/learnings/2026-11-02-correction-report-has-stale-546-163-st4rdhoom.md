---
title: Correction report has stale 546/163 counts beside final 566/166
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
cost: { minutes: 1, tokens: 71274 }
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
docs/2026-11-02_correction-minifwai-report.md is the single status report. Final C9 evidence (`N`) shows 566 Debian tests and 166 installed files per edition (docs/evidence/2026-11-02-v2210-features/README.md). The 546-test (`U`) and 163-file figures belong to the earlier C3 run and the 11:33 verification run.

## Tried and ruled out
Flipping "pending"/"in progress" matrix rows to Verified without a pointer to evidence. Another agent (outside Claude sessions) is verifying those rows, so wait for its confirmed list.

## Watch out
The U legend (L70), the "final 546 pass" line (L182) and "163 payload files" (L8) read as current but are historical. Label them, don't overwrite them: the report keeps failed and earlier runs immutable.
