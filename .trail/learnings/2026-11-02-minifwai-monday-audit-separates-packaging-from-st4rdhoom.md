---
title: MiniFWAI Monday audit separates packaging from verified corrections
author: St4rdhoom
date: 2026-11-02
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
The 2 November readiness review distinguishes existing packaging/documentation from Monday corrective work. At main e6b62a9df65261bba2cfc10618af7d552f016817, dist/production-assessment contains v2.2.10 source kits but only v2.2.9 prebuilt installer ZIPs. Independent hashing verified both v2.2.10 source manifests and 196 listed payload hashes in each older Debian package. The shared engine/parser/enforcement remain unchanged from the base. See docs/2026-11-02_readiness-minifwai-report.md and docs/evidence/2026-11-02-readiness/.

## Tried and ruled out
Packaging integrity, service labels, old v2.2.0 sales/demo reports and helper-level tests do not establish current routed enforcement or real-world accuracy. A reproducible offline unittest run has 13 passing controls and 9 failing requirement probes: four original-tuple/protocol cases, no-DNS evaluation, two correlation cases, Financial DMZ selection and Education apex filtering. The bundled model loads and infers on a fixture; its metadata explicitly identifies synthetic training data. This is not measured-feature acceptance.

trail check returned six conflicts against existing release workflow/README lines. The workflow has no diff against HEAD; the README's only local change is a licensing-doc link. Its installer already uses the correct curl-to-sudo-bash pipe. Existing build instructions and older host/tool observations should not be treated as new audit changes. The report records these diagnostics and explains the scope; the check remains failed and no commit was made. The earlier statement that this Mac lacks dpkg-deb is superseded by independently running the installed Homebrew dpkg-deb for read-only metadata/payload inspection. This does not change the absence of Linux runtime verification.

## Watch out
Keep Financial and Education minifw-ai packages on separate isolated gateways/snapshots; never use operational ARCHANGEL/client systems for this acceptance work. Current telemetry counts snapshots as estimated 1500-byte packets, collectors block each other, and empty DNS iterations skip scoring. Correct inputs/scheduling/identity rather than compensate with thresholds. Live packet block/recovery, edition legitimate traffic, bypass tests and representative model validation remain unverified. Audit probes mock enforcement; engine DEMO_MODE=1 alone does not prevent later nft calls. Preserve before/after evidence before rerunning scripts with --save, which overwrites their logs. No production corrections were made by the status audit.
