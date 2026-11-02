---
title: Measured inference is separate from model quality; packet14 stays shadow-only
author: St4rdhoom
date: 2026-11-02
branch: fix/monday-core-20261102
touches:
  - README.md
  - app/minifw_ai/collector_packets.py
  - app/minifw_ai/events.py
  - app/minifw_ai/main.py
  - app/minifw_ai/state_manager.py
  - app/web/routers/admin.py
  - app/web/templates/admin/partials/sidebar.html
  - build_usb.sh
  - pyproject.toml
  - requirements.txt
---

## Decided
Keep the new packet14-v1 synthetic model in shadow-only mode. C6 live inference on known legitimate local HTTP produced threat probability approximately 0.99999. This is a failed benign classification control, not evidence of real-world accuracy. Inference/measurement success and classification quality are separate results. Record raw probabilities/features and zero enforcement contribution for packet14; TLS/WireGuard rules enforce independently. Existing scoring thresholds/weights are unchanged.

Run tshark decoding as the unprivileged nobody account, clear supplementary groups, and provide a minimal environment that excludes application secrets and key-log variables. dumpcap retains only its capture role; data flows in a memory pipe. Explicit AI disable/invalid flags must not be overridden by saved state or telemetry health.

## Tried and ruled out
Do not market a high synthetic-model probability as a detected threat when the client traffic is a benign fixture. Do not let this unvalidated model amplify blocking. C6 packet inference and functional sandbox acceptance passed; the export-readiness fixture initially raced the asynchronous export and was corrected to await an actual file. Keep the failure. A standalone real UDP probe confirmed unprivileged decoding, measured observations and zero reported drops.

## Watch out
Only v2.2.10 in separate lab VMs. Shadow mode does not validate model quality. Need representative labeled data and independent holdouts before changing scoring behavior. Capture helper/engine/dashboard privilege and sensor-loss/load behavior still need operational review. SafeSearch scope is exact configured DNS aliases, TLS control is reactive after ServerHello, and WireGuard detection is a pattern with bounded coverage, never all-VPN protection.
