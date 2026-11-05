---
title: "AI enforcement blocker is a feature-visibility problem, not model choice"
author: St4rdhoom
date: 2026-11-05
branch: fix/monday-core-20261102
cost: { minutes: 4, tokens: 78767 }
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
The 5 Nov model results show no discrimination: RF flagged 32/60 benign and 32/60 attack; the retrained MLP flagged 75% benign vs 43% attack, worse than chance. Five-packet TLS prefix features (packet14-v1) cannot see password guessing, which happens after the handshake. Better labels alone will not fix this. Brute force shows up in per-client time windows (connection rate to one destination, repeated similar short sessions). Either add window features or limit AI scope to threats a prefix shows (scans, beaconing, tunnels, TLS fingerprints). For lab labels, use the attack tool's own per-attempt timestamps; the lab owns the IPs, so the join is exact.
Recommended Friday option to management: ship the baseline with AI in shadow mode plus a dated qualification plan. Alert-only AI is not viable at a 53-100% false-positive rate.
## Tried and ruled out
Do not treat "retrain or swap the algorithm" as the fix; the information is not in the features. Do not raise mlp_weight, lift the packet14 shadow lock, or stage an AI-caused block and call it qualification.
## Watch out
The MLP is only an amplifier. score_and_decide adds at most mlp_weight=30 points (main.py ~L724), and block thresholds are 60-85, so the AI can never isolate a client alone. "N/60 benign flagged" is not N isolations, and a model that flags everything just lowers every threshold by 30. Confirm whether management's "AI participates in enforcement" means escalation. Define the 90% recall per attack episode within a time bound, and the false-isolation budget per benign client per day; a false block lasts 24h (ip_timeout_seconds 86400). Zero false positives in n flows supports only FP <= 3/n at 95%: 60 flows shows <=5% at best, <=1% needs >=300 clean flows, <=0.1% about 3,000.
