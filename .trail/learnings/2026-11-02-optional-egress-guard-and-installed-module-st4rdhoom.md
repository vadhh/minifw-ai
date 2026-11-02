---
title: Optional egress guard and installed-module fixture scope
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
cost: { minutes: 25, tokens: 32976 }
touches:
  - README.md
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - docs/2026-11-02_correction-minifwai-report.md
  - pyproject.toml
  - requirements.txt
  - scripts/build_deb.sh
  - testing/lab_extended_acceptance.py
  - ".DS_Store"
---

## Decided
The optional egress guard redirects client-interface IPv4 UDP/TCP DNS to the local resolver, blocks TCP/UDP port 853 and optionally denies all forwarded IPv6. It is disabled by default, replaces only its owned table atomically, and requires explicit removal when disabled. Arbitrary HTTPS DoH/direct-IP traffic remain allowed. A port or protocol pattern is not all-VPN detection.

## Tried and ruled out
The first extended C10 runs invoked an installed module from the controller without PYTHONPATH and failed before guard application. Fix only the fixture invocation to use PYTHONPATH=/opt/minifw_ai/app, as documented for the actual manual command. Keep both failure logs; do not change package telemetry/thresholds in response.

## Watch out
Keep C9 artifacts/evidence separate from the continuation candidates. Browser TLS bypass is confined to the self-signed fictional destination; public provider browser tests validate certificates. Backup archives contain credentials and must never be exported. Representative AI validation still requires real authorized labelled metadata; nine repeated benign lab fixtures are only controls.
