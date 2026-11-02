---
title: Observed readiness and private restore need real lab evidence
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
cost: { minutes: 16, tokens: 32976 }
touches:
  - README.md
  - app/minifw_ai/main.py
  - app/web/routers/admin.py
  - app/web/routers/health.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - docs/2026-11-02_correction-minifwai-report.md
  - pyproject.toml
  - requirements.txt
  - scripts/backup.sh
---

## Decided
Continue only separate v2.2.10 Financial/Education lab VMs. Add sandboxed, unprivileged Chromium acceptance with decoded video frames, labelled benign measurements, a real OpenVPN coverage probe, observed runtime health and private quiesced same-edition backup/restore. Keep packet14 synthetic and shadow-only; controlled lab labels are not representative institutional data.

## Tried and ruled out
A static HTTP health response and successful service start do not verify protection. Health needs the same engine process/boot, progressing decisions, recent configured sources and independent kernel-rule proof. Quiet or missing sources are unverified, not proof of failure or readiness. Kernel probes must not block decisions. Path.open does not accept opener: the initial Debian regression failed; private NamedTemporaryFile publication plus a real publisher test corrects this.

## Watch out
Dashboard remains root and retains NET_ADMIN for existing unblock operations despite systemd restrictions. Backup files contain secrets and stay root-only in the VM; validate archive paths, hashes and edition before stopping services. Restore covers configuration/database/model/secrets/base units, not package code or dynamic quarantine persistence. OpenVPN/DoH/DoT/direct-IP/IPv6 gaps must remain explicit when observed. Provider/browser restrictions need actual rendered status; blocked provider pages are not accepted protection.
