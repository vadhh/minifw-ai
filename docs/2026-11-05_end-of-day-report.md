# MiniFW-AI end-of-day report — Thursday 5 November 2026

Standalone Financial and Education · v2.2.10 C19 baseline · v2.2.11 C20 (AI enforcement; AI and regression lab tests passed) · All times WIB · Status at 16:45

This report covers the work after the morning execution report (`docs/2026-11-05_daily-work-report.md`), from 09:40 to 16:45.

**Status at 16:45**

- **Financial and Education:** the C19 baseline passed every lab gate. Financial also passed a partial independent check.
- **AI enforcement:** management accepted D2 and D3 this afternoon. C20 (v2.2.11) lets the AI isolate a client on its own for one pattern: fast password guessing. In practice that means 39 or more connections to one server within 60 s, about 40 attempts a minute.
- **Decision, Financial:** C20 passed the AI and regression tests in the lab. Most baseline gates have also been rerun on 2.2.11 and passed. Friday delivery depends on a fresh install of 2.2.11 and the sector workflows (section 5), and on an independent test of C20.
- **Decision, Education:** the same conditions. No Education candidate has been independently tested yet.

**C20 at 16:45:**

- **Model:** trained, frozen, and passed a held-out test written in advance:
  - 0 of 12 users isolated;
  - 6 of 6 guessers attempting 60 or more times a minute isolated within 60 s.
- **Packages:** built reproducibly for both editions. The debs, the exact source (`source.tar.gz`, `69161b18…`) and `SHA256SUMS` are in `dist/v2211-c20-candidates/`.
- **AI scenarios and regression:** passed on both editions. That covers the upgrade from C19, 645 regression tests, AI isolation with approval, shadow mode without approval, model failure, and restart. Save → Apply, deny-domain, licence and F1 were also rerun on 2.2.11 and passed. A fresh install and the sector workflows remain (section 5).
- **Still needed:** an independent test of C20, and the site-setup and release steps in section 5.

## 1. Work completed today

| Time | Work | Result |
| --- | --- | --- |
| 09:40–11:00 | Closed the open baseline checks on C19 in both editions (`docs/evidence/2026-11-05-ai-decision/`) | All passed: fresh install on clean Debian 12, missing and corrupt model, invalid policy with automatic recovery, the operator warning during the outage (seen in Chromium; recovery in 5.1 s Education, 6.3 s Financial), and vendor-signed licence activation on a fresh install. |
| 09:40–11:00 | Built and tested an off-by-default AI enforcement switch (approval by exact model-file SHA-256) | 634 regression tests passed on both lab VMs. Lab test: the AI caused a kernel block only when the exact model was approved. Mismatched approval and missing or corrupt models stayed safe. |
| 10:00–10:15 | Ran a realistic-pace lab corpus (8 actors per edition, labels from each actor's own log, 99% matched to gateway flows) | The shipped model flags 802 of 805 normal connections, so it must not be enabled. A per-client connection rate separates fast guessers (more than about 30 a minute) from users in this run. Slow guessing is not observable at the gateway. |
| By 14:00 | AI decision note for the 14:00 review (`docs/2026-11-05_ai-decision-note.md`) | Explained why retraining on the morning corpus could not work, and set out decisions D1–D3. |
| 11:09–11:22 | Pushed the branch: C19 source `f04977ed`, reports and evidence `04ca6594`, team learnings `dbad8cfc` | `fix/monday-core-20261102` is on GitHub. |
| 11:11–14:35 | Independent test by Ilham (issue #7), Financial C19 from a collaborator-only draft release | Signed off with limited scope; see section 2. Issue closed. |
| 12:35 | Deleted the disposable fresh-guest disk images | They held a lab admin password and activated lab licences. |
| 15:30–16:45 | C20 build started after D2 and D3 were accepted | See section 3. |

## 2. Independent test (issue #7)

| Item | Result |
| --- | --- |
| Installer hash, clean install, first-login password change | Confirmed independently on `minifw-ilham-financial` (13:19–13:28) |
| Licence activation, tampered copy rejected, survives restart | Confirmed independently. The signature was checked against the packaged public key. |
| Dashboard runs unprivileged; Save → Apply | Confirmed independently |
| Isolation and expiry | Not confirmed independently. The `nft` output in the report is identical, to the millisecond (`expires 14s972ms`), to this morning's Education evidence file. |
| Normal Financial use, upgrade from C18, fault handling | No independent evidence. These items rest on the team's lab runs with the same package. |

The sign-off on issue #7 states this scope. Ilham's first "PASS 7/7" comment (11:38) was posted before his test guest existed (13:19).

**Licence incident.**

- Ilham's 13:30 comment contained a complete signed lab licence on a public repository. It is valid for Financial until 5 November 2027.
- The comment was deleted at about 14:18 and reposted without the licence.
- The licence is tied only to the deployment ID file, and the product cannot revoke a licence. Treat licence `6f74f3eb…` as leaked.
- Ilham signed it himself with the vendor key on sydeco-desktop. The key never left that host, but who may sign licences needs a decision.

## 3. AI enforcement: C20 (v2.2.11)

**Decisions (accepted this afternoon).**

- **D2:** the AI may isolate a client on its own, for one narrow pattern.
- **D3:** the 90% recall target applies to fast password guessing only, about 30 or more attempts a minute from one address to one server (management's wording; the frozen model's cut-off is 39 in 60 s).
- **Version:** C20 is 2.2.11.

**Design.**

- **Feature:** `client-window-v1` counts new connections from one client to one server and port within 60 seconds. It uses counts only, because the default conntrack source gives 5-second poll times.
- **Model:** a logistic model stored as JSON, with no pickle. Its block probability was fixed at 0.9 before training.

It isolates on its own only when all of these hold:

- root-only configuration (`MINIFW_AI_ENFORCE_MODEL_SHA256`) names the exact model file;
- the client's segment is listed in the policy;
- the client is not exempt;
- the client address is IPv4.

| Edition | Segments where the AI may isolate | Not in scope |
| --- | --- | --- |
| Financial | internal, guest, default | DMZ and trading |
| Education | student, staff, guest, default | admin |

- **AI-only blocks:** last 15 minutes, not the 24 hours used for rule blocks.
- **After an engine restart:** the first 10 seconds are ignored, so the restart snapshot doesn't look like a burst of new connections.

**Model (frozen at 15:41, before any held-out data existed).**

- File: `models/client_window_v1.json`, SHA-256 `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee`.
- Inputs: trained on this morning's corpus, 805 normal and 240 fast-guesser connections.
- Fit: a logistic regression with coefficient 0.166 and intercept −4.25.
- It isolates at **39 or more connections to one server in 60 seconds**. The manifest (`docs/evidence/2026-11-05-ai-window/model/manifest.json`) records the input hashes and the held-out acceptance rule, both written before testing.
- **Note on scope:** the effective boundary is about 40 attempts a minute, not 30. A guesser at 30–38 a minute is scored but not isolated. The 0.9 cut was fixed in advance and was not tuned to move it.

| Training data | Users isolated | Fast guessers caught | Slow guessers (out of scope) |
| --- | --- | --- | --- |
| Education | 0 of 4 (highest count 24) | 2 of 2, within 5.2 s | 0 of 2 |
| Financial | 0 of 4 (highest count 26) | 2 of 2, within 5.1 s | 0 of 2 |

These training results are not evidence of quality. The held-out test is below.

**Engine change** (`app/minifw_ai/client_window.py`, `main.py`, `events.py`, both `policy.json` files, `build_deb.sh`, dashboard event feed):

- **What is counted:** only TCP connections. DNS queries to the gateway resolver would otherwise look like a burst.
- **Where the AI decides:** after all rule layers, and only when the rules left the client unblocked.
- **What events record:** every event shows the AI's count, probability and mode (not run, shadow only or enforcing).
- **Credit for blocks:** an AI-caused block is credited to "AI Engine (client window)" in events, audit and the dashboard feed. The feed previously showed "Policy Engine" for every block.
- **Tests:** 15 new unit and engine-loop tests. They cover approval, a mismatched approval, a missing or corrupt model, segment and exempt scoping, one connection counted once across collectors, the 15-minute timeout, and Save keeping the new policy block. 187 targeted tests pass locally. The full suite runs on the lab VMs, because the local environment lacks yara.

**Held-out test: PASS** under the rule written before testing (`docs/evidence/2026-11-05-ai-window/heldout-eval/evaluation.txt`).

The corpus was new and collected after the model was frozen (15:42–15:53):

- **Settings:** new seeds and new addresses, using the shipped conntrack collector (5-second polls) instead of the packet sensor.
- **Actors, both editions:** 12 scripted users, 4 guessers at about 9 attempts a second, 2 guessers at 1 a second, 4 slow guessers, and 2 benign automated pollers making 1 request a second.
- **Baseline C19:** isolated none of them.

| Held-out, both editions | Result |
| --- | --- |
| Users (12) | **0 isolated.** Highest count 24, below the cut-off of 39; highest probability 0.43. |
| Fast guessers, about 9 a second (4) | **4 of 4 isolated**, within 5.1 s of the gateway first seeing them |
| Guessers at 1 a second (2) | **2 of 2 isolated**, at about 35 s |
| Slow guessers, one every 4–8 s (4, out of scope) | 0 of 4. Expected; not observable at this point. |
| Benign poller, 1 request a second (2) | **Flagged.** Predicted beforehand: it looks like a guesser at the same rate. This is why each site must exempt servers and pollers. |
| Management SSH client (unlabelled) | Not flagged |

How the held-out data was read:

- The shipped conntrack collector never writes short connections to `flows.jsonl`, but the engine logs an event the first time it sees each connection. That first sighting is also when C20 counts the connection.
- `scripts/events_to_flows.py` turns each connection's first flow event into one flow record. The frozen evaluator then ran unchanged, and its hash check passed.
- 93% of actor connections were matched to a gateway record. Unmatched connections still count toward each client's total, as they do at runtime.
- Times are measured from when the gateway first saw the connection, which can be up to 5 seconds after the attempt.

**C20 build and lab acceptance (16:00–16:10), both editions** (`docs/evidence/2026-11-05-ai-window/build/`, `acceptance/<edition>/`)

| Check | Education | Financial |
| --- | --- | --- |
| Build from an exported, hashed source tarball (`69161b18…`) on both Debian VMs | Byte-identical on both VMs: `dae8ee0c…262d` | Byte-identical on both VMs: `ec3c1c21…3300` |
| Upgrade C19 → 2.2.11: `dpkg --verify` clean, model installed with the right hash, services active | Pass | Pass |
| Regression suite on the VM | 645 passed, 0 failed | 645 passed, 0 failed |
| No approval: guesser at count 297 with probability 1.0 stays shadow-only; nobody isolated | Pass | Pass |
| Shipped Financial policy (lab clients are in the DMZ, outside AI scope): no isolation | n/a | Pass |
| Exact model approved: guesser isolated at count 39 (p 0.902). Reason `ai_window_rate`, owner "AI Engine (client window)", kernel element `timeout 15m`, guesser traffic then blocked; concurrent users not isolated | Pass (student segment, shipped policy) | Pass (lab policy copy adding DMZ to scope) |
| Approval names a different model: shadow only | Pass | Pass |
| Model corrupt or missing, approval present: engine keeps running, AI not run, baseline port-scan control still isolates | Pass | Pass |
| Engine restart with 60 open connections: none counted, no isolation | Pass | Pass |

In every scenario, DNS telemetry was kept alive and the engine stayed in AI-enhanced protection. Both Monday lab VMs now run 2.2.11, not C19.

## 4. Limits of what is claimed

- All AI evidence comes from a fictional lab sandbox with scripted users. There is no field false-isolation figure.
- A legitimate automated client that opens one connection a second to a server (monitoring, polling, batch jobs) looks the same as a guesser at that rate. Before enforcement is enabled, each site must list its servers, proxies and shared NAT addresses in `exempt`, or keep them in segments outside AI scope.
- Guessing slower than about 30 attempts a minute is not caught. That needs an authentication-log source.
- Clients behind a shared NAT address are counted as one client.
- The AI runs only while the gateway is in AI-enhanced protection, which needs a healthy DNS log. Without it, the gateway falls back to baseline rules and the AI does not enforce.
- Evidence size: 12 held-out scripted users, 4 per edition in training. That is enough to show the mechanism and the margin in this lab (highest user count 24 against a cut-off of 39). It is not a field false-isolation rate.

## 5. Remaining for a Friday delivery

1. **Finish rerunning the baseline gates on 2.2.11.** C20 changed the engine's block path, the install script, both policies and the dashboard feed.
   - **Rerun at 16:16–16:18, passed in both editions** (`docs/evidence/2026-11-05-ai-window/baseline-gates/`):
     - Save → Apply through the authenticated dashboard changed kernel enforcement (timeout 86400 → 11).
     - A deny-domain query isolated the client, and routed HTTP went from 200 to blocked.
     - The existing licence re-uploaded as valid; a tampered copy was rejected with HTTP 400.
     - The labelled corpus (8 captures, 240 requests) ran with no isolation.
     - F1 port-scan isolation worked, and routed traffic was blocked.
     - The scripts ran unchanged except for two in-memory changes: the harness version check accepted 2.2.11, and the expected package hashes were set to C20's. Test names in the output still say C18/C19.
   - **Still to rerun:** a fresh install of 2.2.11 on a clean guest (the install script changed), and the separate normal sector workflows.
2. **Independent test of C20 in both editions.** Education has had no independent test at all. Use the 2.2.11 debs and `SHA256SUMS` from `dist/v2211-c20-candidates/`, shared through a collaborator-only draft as for C19. Require raw evidence captured on the tester's own guest.
3. **Site setup before enabling the AI (handoff checklist):**
   - fill in `segment_subnets` for the real network;
   - list servers, monitoring pollers, proxies and shared NAT addresses in `ai_enforcement.exempt`;
   - confirm the DNS log is flowing (the AI runs only in AI-enhanced protection);
   - then set `MINIFW_AI_ENFORCE_MODEL_SHA256=d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` in `/etc/minifw/minifw.env`.

   A few days in shadow mode first is recommended, to see which site clients would have been flagged.
4. **Upgrade gaps to close:**
   - A site whose policy was changed through the dashboard keeps its old policy on upgrade. It then has no `ai_enforcement` block, so the AI never isolates; this is safe, but nothing tells the operator.
   - Upgraded sites also don't get the commented approval lines in `minifw.env`.
   - Fix either in the install script or with a written handoff step.
5. **Small product follow-ups:**
   - `ai_window_mode = enforcing` means the model is approved, not that this particular client can be isolated, which could mislead an operator.
   - AI blocks, like all blocks, apply only to traffic routed through the gateway. Guessing against the gateway's own services is detected but not dropped.
   - The existing port-scan rule can re-block a client after an engine restart, from connection-tracking entries left by an earlier scan. This was seen twice in the lab: a 1-day block on a lab address, removed by hand. The new AI ignores that restart snapshot; the port-scan rule doesn't yet.
6. **Lab harness fixes:** `testing/lab_gateway_acceptance.py` still checks for version 2.2.10, and the lab fixture `testing/lesson.webm` is missing from git.
7. **Release:** commit the C20 source and today's evidence, open a PR to `main`, create a signed tag `v2.2.11`, and publish release notes with the limits in section 4. Delete the C19 test draft.
8. **Licensing:**
   - sign customer licences per deployment ID on sydeco-desktop;
   - add licence revocation;
   - decide who may use the vendor key.
