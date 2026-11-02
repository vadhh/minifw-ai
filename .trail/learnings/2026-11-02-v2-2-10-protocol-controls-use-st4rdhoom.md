---
title: v2.2.10 protocol controls use measured packet metadata and a separate model
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_flow.py
  - app/minifw_ai/events.py
  - app/minifw_ai/main.py
  - app/minifw_ai/state_manager.py
  - app/minifw_ai/utils/mlp_engine.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - config/modes/minifw_financial/policy.json
---

## Decided
v2.2.10 adds an opt-in client-interface tshark metadata reader. Capture timestamps and lengths feed a distinct packet14-v1 model; conntrack snapshots still never supply timing. The new experimental model is trained on 2,000 synthetic examples with sklearn 1.5.2, with no real sector accuracy claim. Keep packet14 exports separate from legacy24 training records. Per-second packet gates wait for a complete measured second; detection thresholds are unchanged. Explicit AI disable overrides persisted state; valid packet telemetry can sustain AI health without DNS.

TLS version policy uses the ServerHello selected version and TLS 1.3 supported_version, not ClientHello proposals or the legacy record version. Enforcement responds after visible metadata and isolates forwarded client IPv4; it does not decrypt TLS or promise to prevent the initial handshake. WireGuard detection correlates initiation, response and transport indices/lengths. It is a protocol pattern, not cryptographic authentication, all-VPN detection or provider-domain matching. Default VPN action is monitor; blocking is an explicit policy option tested only in lab.

SafeSearch generates validated dnsmasq exact-host CNAME overrides for Google's forced-search, Bing strict and YouTube restrict endpoints. Preserve accounts.google.com and do not alias youtube.com, per provider instructions. DNS overrides do not close encrypted/alternate DNS, direct IP or general IPv6 bypasses. Re-resolve endpoint IPs when provider addresses change.

## Tried and ruled out
Do not feed unknown TLS/JA3/DNS inputs as invented zeros into the existing 24-feature model. Do not mistake TLS 1.3 legacy 0x0303 for TLS 1.2. A UDP port alone does not establish a VPN tunnel. Short initial TLS bursts cannot establish a one-second packet-rate gate. A model inference bool must use the public Python bool contract, not leak numpy.bool_. Keep the failed regression and all live failures.

## Watch out
Only v2.2.10, only separate minifw-monday QEMU overlays. The host rebooted externally during work; restore only the two lab guests, never operational host services. New features require live tests against rebuilt exact-hash packages before verified status. Preserve original C3 accepted artifacts. No raw PCAP, payload, TLS keys, WireGuard private keys or installer secrets in exported evidence. Review capture overhead, sensor loss and representative model validation before deployment.
