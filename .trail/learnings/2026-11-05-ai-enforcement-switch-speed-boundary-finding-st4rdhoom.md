---
title: "AI enforcement switch, speed-boundary finding and C19 baseline gap checks"
author: St4rdhoom
date: 2026-11-05
branch: fix/monday-core-20261102
cost: { minutes: 46, tokens: 307417 }
touches:
  - README.md
  - app/minifw_ai/enforce.py
  - app/minifw_ai/main.py
  - app/web/routers/admin.py
  - app/web/templates/admin/base.html
  - app/web/templates/admin/partials/sidebar.html
  - app/web/templates/admin/policy.html
  - build_usb.sh
  - pyproject.toml
  - requirements.txt
---

## Decided
- Off-by-default AI enforcement switch (docs/evidence/2026-11-05-ai-decision/switch/ai-enforcement-switch.patch, not in any candidate). packet14 models score only when MINIFW_AI_ENFORCE_MODEL_SHA256 equals the sha256 of the exact unpickled model bytes. Otherwise shadow_only. 634 tests passed on both lab VMs.
- Lab mechanism test (lab_ai_switch.py) used a test-only DummyClassifier always-threat model, a lab policy copy with block threshold 30, and a 95-ai-switch-test.conf drop-in. It showed AI-caused kernel isolation with approval; shadow without approval or with a mismatched one; and baseline continuing (port_scan still isolates) with a corrupt or missing model.
- A realistic-pace corpus was built: 4 scripted users, 2 tool-speed and 2 slow guessers, one IP each. Labels come from the actors' own logs, joined to flows.jsonl by (client_ip, src_port, ±5 s): 99% matched. The shipped packet14 model flags 802/805 normal connections. Per-client connections to one server in 60 s separates guessing above roughly 30/min per address. Slow guessing (one every 4-8 s) is not separable at the gateway.
- Fresh C19 install passes in both editions. An invalid policy applied via apply_saved_policy gives a TimeoutError message and a crash loop; existing blocks are kept and the engine auto-recovers 2-2.5 s after the fix.
## Tried and ruled out
- Morning corpus (lab_thursday.py): normal and attack sessions run at the same machine pace, and normal sessions include byte-identical failed logins. Do not train on it.
- Repeated near-identical response sizes do not separate slow guessers: users repeat page sizes more than attackers.
- Observing the dashboard warning on a fresh guest: inconclusive. With no dnsmasq, the DNS source is never seen, so /health/ is 503 not_ready before any fault.
## Watch out
- The rate threshold of 30-40 was chosen in-sample on 8 scripted users and an HTTP/1.0 lab server. It is not validated, and NAT or shared IPs will break it.
- Baseline C19 does not isolate tool-speed same-port guessing.
- The packet collector logs an ERROR traceback when the engine stops normally (tshark exit 0).
- The jump host drops SSH sessions. Launch long lab runs with systemd-run on the VM. scp debs under unique names: /var/tmp on the Financial VM holds an older C16 deb under the same filename. Remote tar globs expand in the home directory unless run under sudo sh -c 'cd dir && ...'.
