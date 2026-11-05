---
title: Fresh lab gateways require active conntrack hooks and accounting
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_dnsmasq.py
  - app/minifw_ai/collector_flow.py
  - app/minifw_ai/enforce.py
  - app/minifw_ai/utils/mlp_engine.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - pyproject.toml
  - requirements.txt
---

## Decided
The Monday lab found that loading nf_conntrack alone did not activate tracking hooks: actual routed HTTPS succeeded while conntrack -L returned zero flows. Install a nonterminal nft ct state new counter rule and enable nf_conntrack_acct during firewall initialization. Regression tests cover new and legacy chains. Source-port identities use tuples to avoid IPv6 colon collisions. Confirmed deny domains immediately isolate client forwarded IPv4, as approved by the user; do not change thresholds.

## Tried and ruled out
Successful packaging, service startup and modprobe were insufficient evidence. A controlled UDP probe returned zero entries before an nft ct expression and a measured entry afterward. The failed routed acceptance run is retained. Fictional Financial and Education acceptance targets are created inside the VM namespaces at the user's request; they do not validate real institutions or external learning platforms.

## Watch out
Run packages only in separate minifw-monday QEMU overlays. Never alter the operational services on the sydeco host. Counter accounting applies to new tracked connections; old entries may lack counters. Conntrack cannot supply packet timing, so full timing-dependent model inference remains unavailable. Export logs and nft evidence, never generated TLS private keys, session tokens or installer secrets.
