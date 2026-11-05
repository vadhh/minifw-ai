# MiniFW-AI execution report — Thursday 5 November 2026

Afridho · Standalone Financial and Education · v2.2.10 C18 baseline / C19 operator-warning candidate · All management checkpoints WIB

**Financial: HOLD. Education: HOLD. AI qualification is not complete.** Management confirmed a target of at least 90% malicious recall and that AI must participate in enforcement. Today's measurements do not justify enabling any tested model. Friday 6 November remains the requested finishing date, but a deliverable with accepted AI enforcement is currently blocked. This report records work executed this morning; it does not claim that the scheduled 14:00 review or 17:00 submission meeting has occurred.

## Work completed against today's instructions

| Assigned gate | Executed work and result | Assessment |
| --- | --- | --- |
| 09:30 — traceable C18 handoff | Rechecked the existing C18 handoff: 418 regular files, 404 checksum entries, 468 declared source files and all 381 payload files per installer. Recorded repository, branch, commit and dirty-worktree inventory. | Artifact consistency checked directly in this session. Wednesday's traffic results remain historical results; they were not inferred from hashes. |
| 10:00 — dataset, labels and 14-feature pilot | Downloaded and checksum-verified the selected HIKARI PCAP, ground-truth archive and labelled CSV. Audited 290,207 packets / 15,032 streams. Extracted 2,942 eligible five-packet prefixes, but accepted zero HIKARI labels because the required time/protocol identity could not be established. Documented all 14 features and verified generated-corpus features against independent calculations. | Extraction/provenance work completed; public-data training gate BLOCKED. The earlier research recommendation required correction after inspecting actual archive contents. |
| Create normal traffic where none exists | Created 16 complete, labelled lab capture sessions with 480 measured request flows across both editions; fixed capture buffering before accepting them. Added separate fictional payment, transfer, statement, role-access, lesson, search and media workflows, with new normal-traffic captures. | New lab corpus available. It is not real institution traffic or accepted production representativeness. |
| 13:00 — MLP / small RF comparison if data checks pass | Ran a diagnostic comparison on generated sessions: 240 training, 120 validation and 120 held-out test flows. Recorded confusion matrices, counts, model identities, latency, CPU and process memory. | No accepted public-data comparison. Lab session-tag results are diagnostic: the first five TLS packets generally precede the password-guessing activity used to label an attack session. |
| 14:00 — model qualification | No tested model qualifies. The shipped model flagged every benign test flow. The retrained MLP and RF also produced high benign false-positive fractions. | HOLD established early; formal management review remains scheduled. Shadow mode retained. No model-caused kernel-action acceptance claimed. |
| 16:00 — useful baseline checks | Installed C18 on two clean Debian guests; verified ownership, denied writes by both non-root accounts, SQLite integrity, mandatory initial password change and authenticated pages. Built C19, upgraded both existing lab guests with preservation checks, and repeated licence, dashboard, normal-use and bounded F1/F2 checks. | Reported passes below are newly executed lab results. Fresh C18 checks do not constitute a fresh C19 or future model-candidate installation pass. |
| 17:00 — separate decisions and evidence | This DOCX report, detailed acceptance DOCX, source, installers, manifests and raw evidence are provided in the C19 handoff. | Financial HOLD; Education HOLD. No sale-readiness percentage or unsupported completion claim. |

## Model result and the remaining blocker

The table below uses the held-out generated test sessions: 60 benign flows and 60 attack-session flows, evenly divided between editions. Threshold 0.5 and model specifications were fixed; the test set was not used to tune them.

| Model | Benign flows flagged | Attack-session flows flagged | Decision |
| --- | --- | --- | --- |
| Unchanged shipped MLP | 60/60 (100%) | 60/60 (100%) | Reject for isolation. High apparent recall comes with every normal flow flagged. |
| Locally retrained small MLP | 45/60 (75%) | 26/60 (43.3%) | Does not qualify. |
| Small Random Forest | 32/60 (53.3%) | 32/60 (53.3%) | Does not qualify. |

These are flow-level predictions against fixture session tags, not measured client-isolation rates, accepted attack-onset recall or production false-positive estimates. A TLS handshake prefix does not establish that a later password guess has already occurred. Both the feature observation point and label timing need a defensible protocol before production qualification. Choosing a different algorithm alone did not close this gap.

Management's 90% malicious-recall target is recorded. A maximum acceptable false client-isolation rate has not yet been agreed. Zero unintended isolation remains required for the declared normal-workflow acceptance fixtures; a measured field budget and broader coverage decision remain open. No new model was installed into either edition and no shadow lock was bypassed.

The HIKARI pilot also corrected a concrete research assumption: `ground-truth.zip` contains six anonymised PCAPs, not the expected label table. The separate labelled CSV contains 555,278 rows, but no absolute start timestamp or transport-protocol column. Of 15,032 observed pilot streams, 5,466 had a unique endpoint-quadruple candidate and 9,566 had multiple candidates. All unique candidates carried a benign label, which further prevents this pilot serving as the assumed balanced attack corpus. Candidate matches were not accepted as ground truth; an attack-named file was not labelled wholly malicious. Exact counts and limitations are retained.

## Baseline corrections and acceptance

**F1 follow-up:** both C18 editions still detected the controlled distinct-port scan through the remaining port-scan gate, added the client to the kernel block set and blocked routed HTTP. C19 separately passed 300/300 independently scheduled ordinary HTTP requests per edition at five per second with no unintended isolation. This does not establish protection against every same-port flood or encrypted application abuse.

**F2 and operator visibility:** C19 passed the combined load → full event/flow volume → renewed deny sequence in both editions. The full filesystem remained at zero free bytes, deny blocking persisted beyond the older block's expiry, 30 further legitimate HTTP requests succeeded, and the same engine PID remained with zero automatic restarts. Health returned 503 while recording was unavailable. A small shared dashboard warning now makes unavailable protection/recording checks visible. Chromium verified the warning at 1280×900 and 390×844; it cleared after logging resumed and health returned 200. Records lost during the fault were not recovered. This is not an audit-volume, full-root-filesystem or database-failure acceptance claim.

**Dashboard application:** C18's measured sampled restart-observation intervals were 2.915 seconds for Education and 2.979 seconds for Financial; request responses took 2.822 and 2.837 seconds. These include probe/health-publication cadence and are not exact packet-loss measurements. Existing kernel blocks remained and sampled HTTP requests succeeded. A stopped apply watcher caused HTTP 503 without stopping the engine; restoring the watcher and clearing the pending lab request allowed a successful retry. This was a bounded dispatch-failure test requiring administrator repair, not a demonstration that every invalid-policy restart recovers automatically. On C19, actual authenticated Save → Apply again changed kernel enforcement without a client command-line restart.

**Installation and licence:** clean C18 installs passed in both editions, including password-change onboarding. C18→C19 upgrades preserved administrator rows, policy, licence bytes, deployment identity and environment. Root ownership and actual denied append attempts passed for both unprivileged accounts. Actual vendor-signed licences for the existing lab deployment IDs again activated through C19's dashboard, rejected tampering and survived web restart. New clean-guest signed activation and real customer activation were not claimed.

**Normal use and regressions:** both C19 editions completed the fictional sandbox's login, account API, payment, transfer, overdraft rejection, statement download, role checks, lesson/search and media/range checks. The staff and ordinary client used one lab source address; this is not segmentation or external application acceptance. All 630 regression tests passed on each C19 VM. Their ten existing warnings are retained; regression totals do not override the AI gate.

## Candidate identity and reproducibility

C19 changes one product file from C18: the shared administrator-page template adds a warning when health checks are unavailable. It does not change the engine, model, installer logic, firewall rules or policy-application mechanism. Native builds on the two existing guests matched using `SOURCE_DATE_EPOCH=1793836800`. All 468 source files and 381 payload files per installer were checked against the source declaration and exact packaging transformations.

| Artifact | SHA-256 |
| --- | --- |
| C19 Education installer | `8b11399b266492927576590ee1a21c108c028a469d1f6fde8d96e040f74a1c6d` |
| C19 Financial installer | `ead9c4a376c4680c8cfdbbf97e303e8a8361a4bad47ae3a48094c12db8819744` |

The source checksum and complete manifests accompany the handoff. Repository base commit remains `e59ace4b228d3c6f14c32473fd8c462c9a84db1a`, branch `fix/monday-core-20261102`; the worktree contains uncommitted work, so the commit alone does not identify either candidate. Archived source hashes and declared inputs do.

Failed preflights and harness runs remain in the evidence: wrong old-package path rejected before execution; buffered captures; mismatched lab health paths; a Python browser-API assertion; and initial failure to follow mandatory password-change onboarding. Initial builds without a fixed epoch are retained. The dashboard feed fixture reordered entries; semantic equality was checked and exact original formatting restored. Both upgraded lab packages ended with clean `dpkg --verify`, stopped engine/web services and no temporary network namespaces.

## Remaining Thursday work and Friday finishing decision

Afridho must escalate the AI blocker now and present it at the planned 14:00 review. Establish attack-onset labels and observable threat categories for the actual online feature window; resolve the public-label join or select a separately verified labelled capture source. Expand the new normal corpus with approved edition-specific workflows and an independent environment. Agree the false-isolation budget. Retraining must use a new frozen split protocol; the inspected sessions cannot be presented as a new pristine test set after further tuning.

For a newly qualified model only, create a distinct candidate and prove model output → policy decision → kernel action on a threat otherwise allowed. Repeat normal-use, F1/F2 with AI actually enforcing, model disable/failure/rollback, installation, signed licence and save/apply checks in each edition. Today's deterministic or shadow-only passes cannot substitute for those tests.

| Friday checkpoint WIB | Required finishing work |
| --- | --- |
| 09:00 | Review Thursday's exact candidate and evidence. Proceed with release finishing only if AI qualification and affected acceptance gates have passed. Otherwise retain HOLD and issue the unresolved blocker and revised estimate. |
| 12:00 | For a qualified final candidate: verify fresh installation/upgrade, signed customer or explicitly labelled lab activation, dashboard application/recovery and approved normal workflows per edition. |
| 15:00 | Freeze exact source, model, installer hashes and final reports; independently check the assembled handoff and document operator instructions and limitations. |
| 17:00 | Issue separate Financial and Education delivery decisions. No release with unsafe isolation, lost protection or an unaccepted AI promise. |

Friday is a finishing target, not evidence that model engineering will finish by then. At this checkpoint, AI participation remains unmet and release remains blocked for both editions.

See the accompanying [technical acceptance report](2026-11-05_acceptance-minifwai-report.docx) and [evidence index](evidence/2026-11-05-delivery/README.md). The handoff includes Word reports, source, installers and raw selected evidence for review. No independent external reviewer is claimed to have reproduced these lab results.
