# MiniFW-AI — AI enforcement decision note for the 14:00 review

Thursday 5 November 2026 · Standalone Financial and Education · v2.2.10 C19 · All times WIB

**Financial: HOLD. Education: HOLD for AI enforcement.** Retraining today cannot clear the AI blocker; the inputs have to change first. This note sets out why and asks management for three decisions. The baseline gates already reported as passing (firewall corrections, installation, signed lab licences, dashboard application) are not affected.

Today's lab work (section 4):

- **closed five open baseline checks** for a Friday baseline release: fresh C19 installation, model-file failure, invalid policy, the operator warning during that outage, and vendor-signed licence activation on a fresh installation;
- **proved the AI-to-kernel enforcement mechanism** behind an off-by-default switch, using a test-only model;
- **showed where the speed boundary lies,** using exact labels: password guessing faster than roughly 30 attempts per minute per address is observable at the gateway; slower guessing is not.

F1/F2 and normal-use runs were not repeated on the fresh guests. They passed on the upgraded lab VMs with byte-identical C19 packages, and the fresh guests passed installation, licence and dashboard checks. This scope decision was taken on 5 November.

## 1. Why retraining today cannot fix the model results

**The detection point cannot see the attack.** The model scores the first five packets of each TLS connection. Those packets are the handshake. The guessed password travels later, encrypted, so a guessing connection and a legitimate login look the same at the point where the model decides. No algorithm can learn a difference that the input does not contain.

**The lab corpus makes the classes identical by construction.** Both editions' generated sessions were checked request by request (`docs/evidence/2026-11-05-delivery/*/runs/*/corpus-manifest.json`):

| Property | Normal session | Attack session |
| --- | --- | --- |
| Requests | 30 | 30 |
| Pace | Same script, same pace: 30 requests in 0.8–2.6 s, each normal/attack pair within 0.1 s | Same |
| Failed logins (`POST /login` → 401, 40-byte response) | 6 of 30 | 30 of 30 |

- Every normal session contains six failed logins that are byte-for-byte the same on the wire as a guess.
- Both classes run at machine speed; no person sends 30 requests in under three seconds.
- Pace increases with the session index: training sessions take about 0.8–1.4 s and test sessions about 2.6 s. The held-out test set is therefore not distributed like the training data.

The 60/60, 45/60 and 32/60 results therefore measure artefacts of the generated sessions, not model quality. The Random Forest flagged 32/60 in both classes, and the retrained MLP flagged normal flows more often (75%) than attack flows (43%). These are the results expected when the input carries no usable signal.

## 2. How AI enforcement works in the product today

- **AI escalates; it never isolates on its own.** The AI score adds at most 30 points (`mlp_weight` 30). Block thresholds are 60–85 depending on segment. A client is isolated only when rule evidence (feeds, burst, ASN, deny-IP) has already brought it within 30 points of the block line.
- **The current model format is locked to shadow in code** (`app/minifw_ai/main.py:723`). Allowing any packet model to enforce requires a code change and a new candidate, even after a model qualifies. Today's off-by-default switch (section 4) is that code change, kept out of Friday's build.
- **An AI-assisted block lasts 24 hours**, the same as any other block (`ip_timeout_seconds` 86400). One false isolation disconnects a user for a full day.

## 3. Decisions requested

**D1 — Friday scope (one decision per edition)**

| Option | What ships Friday | Assessment |
| --- | --- | --- |
| **A (recommended)** | Baseline protection (C19 as built; today's fresh-install, model-failure and invalid-policy checks passed without changes) with AI in shadow mode. AI enforcement follows in a separate dated release. | Everything shipped has passed lab acceptance. The AI promise is deferred, not weakened. |
| B | Baseline with AI producing alerts but no isolation. | Not viable at the measured false-positive rates (53–100% of normal flows). Operators would be flooded with false alerts. |
| C | Hold Friday until AI qualifies. | No date can be given today. It depends on the feature redesign and an approved normal-traffic corpus. |

**D2 — What "AI participates in enforcement" means.** Is it enough for the AI to escalate clients that rules already flag (the current design)? Or must the AI be able to isolate a client on its own? Independent AI isolation needs much higher precision and a different design; it is not achievable this week.

**D3 — Acceptance metrics.** The 90% target needs a scope, a unit and a matching false-isolation limit. Proposed for discussion:

- **Threat scope:** which attacks the 90% applies to. Today's check shows that guessing faster than roughly 30 attempts per minute per address is observable at the gateway and slower guessing is not (section 4).
- **Recall per attack, not per connection:** at least 90% of attack episodes detected within an agreed time (for example 60 seconds). An isolation firewall only has to catch an attacker once.
- **False isolation per normal client per day,** with an agreed numeric cap. Each false isolation costs a user 24 hours of access.
- **Evidence size follows the cap.** With zero false isolations in *n* normal flows, the false-positive rate can only be shown to be at most 3/*n* (95% confidence):

| Claimed false-positive rate | Minimum clean normal flows needed |
| --- | --- |
| ≤ 5% | 60 (today's test set) |
| ≤ 1% | 300 |
| ≤ 0.1% | 3,000 |

## 4. Results from today's lab work (executed 09:40–11:00 WIB)

All results below are new lab executions in both editions. Raw results are in `docs/evidence/2026-11-05-ai-decision/`.

**Baseline release gaps on C19 (affects option A):**

| Check | Education | Financial |
| --- | --- | --- |
| Fresh C19 installation on a clean Debian 12 guest: package hash, clean `dpkg --verify`, root-owned code denied to `lab`/`minifw-web`, mandatory password change, dashboard pages, SQLite integrity | Pass | Pass |
| Model file corrupt: engine runs on baseline rules, zero AI inferences, ordinary requests succeed, port-scan control still isolates | Pass | Pass |
| Model file missing: same outcome as corrupt | Pass | Pass |
| Invalid (truncated) policy applied through the dashboard's apply path: apply reports "Engine restart could not be verified"; engine restarts in a loop; existing kernel blocks stay in place; engine recovers automatically 2–2.5 s after the file is corrected | Pass, with the limitation below | Pass, with the limitation below |
| Operator warning during that outage on a configured lab gateway (live DNS and flow sources; Zeek stand-in for Financial): `/health/` 200 and banner hidden → 503 and Chromium-observed warning at 1280 and 390 px → 200 and banner cleared after correction | Pass (recovered in 5.1 s) | Pass (recovered in 6.3 s) |
| Vendor-signed lab licence (key `minifw-vendor-2026`, signed on the lab host where the key is kept; 30-day expiry) activated through the dashboard of each fresh installation: status valid, tampered copy rejected (HTTP 400), still valid after a dashboard restart, `dpkg --verify` still clean | Pass | Pass |

Limitation: while the policy is invalid the engine is not processing traffic. Existing blocks hold, but new traffic is forwarded with no new detection until an administrator corrects the file. The warning text mentions log storage, which points the operator the wrong way when the actual cause is a broken policy; this is worth a wording follow-up. On a fresh install with no DNS source configured, `/health/` reports not ready and the warning shows until the gateway is configured. The dashboard writes policy with a JSON serialiser, so this state comes from a damaged or hand-edited file rather than from normal dashboard use. The licences are lab licences for the disposable fresh guests, not a customer activation.

**AI enforcement switch (not in Friday's build):** a code change replacing the hard-coded shadow lock. Packet models stay shadow-only unless a root-only service environment setting (`MINIFW_AI_ENFORCE_MODEL_SHA256`, intended for `/etc/minifw/minifw.env`; tested through a systemd drop-in) names the SHA-256 of the exact model file loaded. Default behaviour is identical to C19. The full regression suite passed on both lab VMs (634 tests: C19's 630 plus 4 new). The lab mechanism test used a **test-only model that labels every connection a threat**, and a lab policy copy with the block threshold lowered to 30:

| Mechanism check (both editions) | Result |
| --- | --- |
| Switch off (no approval) | 161 inferences per edition, all shadow-only, score 0, 16/16 requests allowed |
| Approved exact model | AI score 30 → block decision → client added to the kernel block set → routed traffic blocked |
| Approval names a different model (replacement or rollback) | Shadow-only again, no isolation |
| Corrupt or missing model, approval present | Engine keeps running on baseline rules; port-scan isolation still works |

This proves the path from model output to kernel action and its safety switches. It says nothing about detection quality: the test model is deliberately useless as a detector.

**Realistic-pace lab corpus and feasibility check (10:00–10:15).** C19 ran in shadow mode on both editions while eight lab actors used the fictional sandbox concurrently, each from its own address:

- four scripted users browsing at human pace (reading time between visits, occasional typos, one forgetful user with three failed logins);
- two tool-speed password guessers (about 8 guesses per second, 60 guesses each);
- two slow guessers (one guess every 4–8 seconds, 20 guesses each).

Every connection is labelled from the actor's own log. 1,125 of 1,135 connections (99%) were matched to the gateway's own flow record by client address and port, so the labels apply at the actual detection point.

| Finding (both editions combined) | Result |
| --- | --- |
| Shipped packet model, per connection | Flags 802/805 normal connections and 320/320 attack connections. **Must not be enabled.** |
| Baseline C19 against tool-speed guessing | No isolation. The current gates do not cover repeated connections to the same port. |
| Per-client connection count to one server in 60 s, threshold 30–40 (chosen on this same data; not validated) | In this run: catches 4/4 tool-speed guessers within 4.0–5.4 s; flags 0/8 users |
| Same feature against slow guessing | Catches 0/4 at any threshold that spares users. Users reach 24–26 connections per minute; slow guessers reach 11–12. |
| Repeated near-identical connections | Does not separate: users repeat identical page sizes more often than slow guessers |

What this means:

- **This is a speed boundary, not proof of detection.** A per-client rate feature catches guessing faster than about 30 attempts per minute per address and misses anything slower. The gap between users (26 per minute) and tool-speed guessers (60 per minute) partly reflects the pacing chosen for this lab script, so "4/4 caught, 0/8 flagged" describes this run only. It is not held-out evidence.
- **Guessing above that speed is observable at the gateway,** through a per-client time-window feature rather than the current five-packet connection features. A model or rule built on that feature is a realistic next step, and must be validated on data it was not tuned on.
- **Guessing below that speed is not observable at this detection point.** Its connections look like a person logging in. Catching it needs a different data source, such as authentication-failure logs from the protected application, or TLS inspection. A 90% recall target for "password guessing" is therefore achievable here only if it is limited to fast guessing, or if a new data source is added.
- **Shared addresses will break the margin.** Clients behind NAT or a shared proxy combine many people into one address. A field threshold needs real per-site traffic before it is trusted.
- **The real sample is 8 scripted users,** not 805 independent connections. Scripted users and an HTTP/1.0 lab server (one connection per request) are approximations, not observed people.

**Not done today:** retraining or tuning on the current corpus, reusing the inspected test set as fresh evidence, or lifting the shadow lock in Friday's build.

## 5. Path to AI enforcement after Friday

1. **Agree the threat scope** (D3): guessing faster than about 30 per minute per address is in reach at the gateway; slower guessing needs an authentication-log or TLS-inspection source.
2. **Build per-client time-window features** in the engine, the inputs the feasibility check shows carry signal.
3. **Collect normal traffic from real sites,** including addresses shared through NAT or a proxy, sized to the agreed false-isolation cap.
4. **Train and freeze a model** on a new train/validation/test split, with exact per-connection labels from attacker logs. Today's corpus shows that this labelling method works (99% of connections matched at the gateway).
5. **Build a new candidate** that includes today's enforcement switch, approving only the qualified model's hash.
6. **Repeat AI-enforcing acceptance in each edition:** normal use, F1/F2, disable/failure/rollback, installation, licence and save/apply.

The switch and the failure handling are done and tested. What remains is features, real normal traffic and model qualification. A date can be estimated once D2 and D3 are decided and a site for normal-traffic collection is agreed.
