---
title: Monday core uses measured connection observations and approved deny isolation
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_dnsmasq.py
  - app/minifw_ai/collector_flow.py
  - app/minifw_ai/collector_zeek.py
  - app/minifw_ai/enforce.py
  - app/minifw_ai/events.py
  - app/minifw_ai/feeds.py
  - app/minifw_ai/main.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
---

## Decided
Monday's shared correction uses ConntrackFlow with the original client/destination five-tuple and separate original/reply counters. Repeated snapshots add no packets or bytes; initial snapshots establish a baseline, counter resets start a new baseline, and rate intervals use collection-time monotonic timestamps rather than decision-queue timing. The CLI requests extended output. Packet timing/size distributions are unavailable from conntrack, so the existing 24-feature MLP is explicitly disabled for those observations, not fed invented features.

DNS, Zeek and flow readers run independently with bounded per-source queues and a single fair decision consumer. Flow evaluation no longer depends on DNS events. Query-only DNS supports frequency and standalone domain decisions but does not label unrelated flows. Zeek enrichment uses client/source-port/destination/destination-port identity. Financial/Education deny-domain matches now immediately isolate the client's forwarded IPv4 traffic, explicitly approved by the user on 2 November. Wildcard deny zones include their apex; bare deny entries cover subdomains. Most-specific subnet matching selects the Financial DMZ; destination IP/ASN checks use the destination, and Financial blocked-ASN config receives the actual feed.

## Tried and ruled out
Do not count conntrack polls as 1500-byte packets, flow frequency, packet interarrival or subsecond bursts. Do not apply one client's latest SNI to all connections. Do not tune thresholds to hide telemetry errors. Generic and numbered model reasons both retain model attribution. Rule detections and disabled model observations must not be exported as successful model inference. Kernel membership checks suppress duplicate block events and avoid refreshing an existing block's expiry.

## Watch out
The native nftables action still isolates client-source forwarded IPv4 only; IPv6 and local INPUT/OUTPUT are outside that enforcement scope. SafeSearch resolver enforcement and Financial TLS minimum-version enforcement remain unimplemented. Provider-domain matching is not VPN tunnel detection; country/asset/JA3/API rules still need their actual data sources. Broad unit success is not real traffic acceptance or real-world model accuracy. Preserve failed tests and actual packet/nftables/recovery evidence separately for each edition.

trail check flags existing release-workflow/README wording against older packaging/host learnings. Those workflow lines are unchanged and the README already uses the supported curl-to-sudo-bash pipe. The older statement that this Mac lacks dpkg-deb was superseded by direct package inspection. These pre-existing wording matches do not justify reverting the core corrections; retain their diagnostics and explanation in the correction commit/report. The earlier audit learning describes the pre-correction state, not these subsequent fixes.
