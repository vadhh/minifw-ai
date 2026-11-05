---
title: Packet mode skips ambiguous initial intra-site attribution
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_packets.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - docs/v2210-metadata-controls.md
  - pyproject.toml
  - requirements.txt
  - scripts/build_deb.sh
  - testing/test_packet_metadata.py
---

## Decided
For the optional v2.2.10 packet source, never guess the client when the first observed packet has both endpoints inside configured client subnets. Skip that ambiguous flow until explicit SYN/conntrack direction correlation is integrated. The verified lab path has one unambiguous client endpoint and a separate server subnet. Connection metadata still uses the complete client/source-port/destination/destination-port/protocol tuple.

## Tried and ruled out
First-observed direction is not proof of original direction for intra-site or midstream traffic. Adding packet visibility must not undo the Monday original-tuple/correlation corrections. Reduced coverage is documented rather than silently attributing a server's replies to a client.

## Watch out
Only v2.2.10 isolated lab VMs. Intra-site and restart/midstream packet attribution remain outside verified coverage. Conntrack counter mode is unchanged. Keep the synthetic packet model shadow-only, and retain reactive TLS/WireGuard scope and general IPv6/DNS-bypass limitations.
