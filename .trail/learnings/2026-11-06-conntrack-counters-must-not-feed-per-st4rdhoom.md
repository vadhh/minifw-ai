---
title: Conntrack counters must not feed per-flow packet-rate gates; restart snapshot is pre-existing
author: St4rdhoom
date: 2026-11-06
branch: fix/monday-core-20261102
cost: { minutes: 98, tokens: 553568 }
touches:
  - ".DS_Store"
  - ".serena/.gitignore"
  - ".serena/project.yml"
  - docs/.DS_Store
  - docs/2026-11-06_financial-delivery-0930.md
  - uv.lock
  - docs/delivery/2026-11-06-financial-v2.2.13/recovery-procedure.md
  - docs/delivery/2026-11-06-financial-v2.2.13/release-notes.md
  - docs/delivery/2026-11-06-financial-v2.2.13/setup-guide.md
  - docs/evidence/2026-11-06-financial/c21/README.md
---

## Decided
- pps_saturation (>200 pkts/s on one flow) runs only when flow.packet_timing_available (packet sensor), like the burst/small-packet/timing gates (C22, 50058d10). On conntrack counters (accounting is switched on by enforce.py at start) one ordinary download or stream over ~2.3 Mbit/s exceeded it and isolated the client for 24 h; floods that open a new connection per packet never reach it there.
- The conntrack collector marks samples from its first poll `initial`; FlowTracker sets `pre_existing` on those flows: not new, not port-scan ports (C21, a9c87e93). Fixes re-blocks after restart / dashboard Apply.
- Connection-rate AI wording is "about 37-40 new connections a minute" (5 s polls make the 60 s window cover ~62 s; 37/min isolated 1 of 3 in 300 s runs, 38/min always).

## Tried and ruled out
- A time-based warm-up for the restart snapshot: `conntrack -L` can take up to 10 s, so a late first poll would still count. Poll-index marking is used instead.
- Lowering the AI cut to 30/min (management Option B): it would also isolate a benign 2-second poller (count 31).

## Watch out
- Lab bulk tests need NIC offloads off (ethtool tso/gso/gro off on the veths): with offloads on, conntrack counts coalesced super-packets and the pps bug hides. A real virtio NIC (Education VM, scp) still tripped it.
- Deleting a block on a running engine does not stick while it still tracks the client's flows (re-added within 1-5 s); fix cause, restart, then delete.
- docs/2026-11-06_financial-delivery-0930.md holds a leaked licence ID with its deployment ID: never commit it (public repo).
- Education 2.2.11 still has the pps_saturation false block until it gets a build from 50058d10.
