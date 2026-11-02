---
title: DoH blocking is address-list only; lab test-source packer misses new feed files
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
cost: { minutes: 12, tokens: 50085 }
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
C12 blocks DoH by dropping client TCP/UDP 443 to the dedicated public resolver addresses in config/feeds/doh_resolvers.txt, inside the opt-in egress guard (nftables, so it blocks before any data passes). Entries go through ipaddress.ip_address, so the nft rule only ever receives single addresses. MINIFW_EGRESS_DOH_LIST / --doh-list selects another file; an empty value disables the list.

## Tried and ruled out
Shared CDN hostnames (cloudflare-dns.com, Firefox TRR edges) are deliberately not listed: blocking those IPs would also block unrelated sites. Reactive SNI-based isolation was not used, because it acts only after the handshake.

## Watch out
Unlisted, self-hosted and CDN-fronted DoH and direct-IP traffic still pass. The Codex-era test-source packer (/private/tmp/package_minifw_test_source.py) builds from an old kit list; any new non-Python repo file a test reads (for example config/feeds/*.txt) must be added to its patterns, or the VM suite fails even though the .deb has the file.
