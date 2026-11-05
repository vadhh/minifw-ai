---
title: Packet capture readiness needs new decisions and memory-only pipes
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_packets.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - pyproject.toml
  - requirements.txt
  - scripts/build_deb.sh
  - testing/lab_gateway_acceptance.py
  - testing/test_packet_metadata.py
---

## Decided
The first C5 feature lab runs loaded packet14 but missed traffic while tshark was still starting. Readiness must be a new observed packet decision after each service start, never a fixed delay or a stale prior event. dumpcap now writes PCAP only to stdout and tshark reads stdin; the pipe stays in memory and avoids tshark's default temporary on-disk capture. A controlled UDP probe captured three real observations with zero drops and no capture file.

## Tried and ruled out
Direct tshark -i creates a temporary PCAP by default, even when only -T fields output is requested. Merely starting the service and sleeping 1.5 seconds does not prove the sensor is ready. Both failed C5 inference runs are retained and do not count as feature acceptance.

## Watch out
Restrict to v2.2.10 lab VMs. Capture is local and does not decrypt TLS; only whitelisted metadata is output. stderr retains capture/drop information. A metadata sensor adds startup and response latency; TLS enforcement is reactive after visible ServerHello, not an inline handshake guarantee. Rebuild and verify exact new hashes before rerunning both live feature suites. Keep failed evidence and never export TLS/WireGuard private keys or raw PCAP.
