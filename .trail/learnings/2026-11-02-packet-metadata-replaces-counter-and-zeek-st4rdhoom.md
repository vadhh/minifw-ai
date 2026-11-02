---
title: Packet metadata replaces counter and Zeek flow state
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/main.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - docs/2026-11-02_correction-minifwai-report.md
  - docs/v2210-metadata-controls.md
  - pyproject.toml
  - requirements.txt
  - scripts/build_deb.sh
---

## Decided
When MINIFW_PACKET_INTERFACE is selected, packet metadata replaces both conntrack flow collection and Zeek enrichment. DNS remains independent. The packet source supplies its own visible TLS metadata; normal conntrack/DNS/Zeek mode remains unchanged.

## Tried and ruled out
Merging a Zeek-created FlowStats object with later captured packets can retain unavailable timing flags or mix sources. A separate merged-source state machine adds unnecessary ambiguity; source exclusivity is the smaller verified correction. A Financial policy test requires only the packet source when DNS is explicitly disabled.

## Watch out
This is not live Zeek acceptance or intra-site/midstream attribution. Preserve the packet14 shadow-only safety gate after its known-benign classification failure. Strict inline TLS prevention, other VPN protocols and bypass prevention remain unverified.
