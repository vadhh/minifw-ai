# MiniFW-AI execution plan — Thursday 5 November 2026

Prepared 4 November · All times WIB · Technical owner: Afridho

## Objective and current decision

Produce a defensible delivery decision for standalone Financial and Education, each assessed separately. AI must participate in enforcement. Both editions remain HOLD until a qualified model demonstrates actual enforcement and normal use remains acceptable. Friday 6 November is the delivery target, conditional on the gates below. This plan has not been executed.

Use the C18 v2.2.10 source/packages and recorded SHA-256 identities in the revised 4 November daily report as the baseline. Work in separate disposable lab guests. Preserve existing evidence and isolate any model/integration changes in a new traceable candidate. VPN expansion and ARCHANGEL device binding remain excluded.

## Schedule and required outputs

| Checkpoint WIB | Owner | Work | Required evidence / decision |
| --- | --- | --- | --- |
| 08:30 | Afridho | Verify C18 artifacts, guest snapshots, reproduction drivers and training/runtime versions. Management confirms false-isolation criteria and authorised normal-workflow data. | Baseline hashes, environment manifest, split plan and written criteria. Missing inputs are escalated immediately; no assumed approval. |
| 10:00 | Afridho | Acquire the pinned HIKARI pilot and ground truth; verify checksums, label joins and production packet14 extraction at online decision prefixes. | Download/provenance manifest; matched, ambiguous, unmatched, ineligible and per-class counts; extractor parity check. Stop model qualification if labels or features cannot be established. |
| 11:00 | Afridho; management supplies approved inputs | Expand to multiple labelled captures, select supplementary IoT-23 captures and obtain normal workflows for both editions. Freeze capture/session holdouts before fitting. | Labelled corpus inventory, role of every capture, temporal label rules and edition coverage. Missing normal data means sector qualification remains blocked. |
| 13:00 | Afridho | Train the existing small MLP and a small Random Forest on identical measured features and splits. Fit preprocessing on training data only; retain required scaler metadata. | Reproducible commands/seeds, hashes, model/scaler metadata, separate validation/untouched-test results, false-isolation counts, threat recall and resource measurements. Record failed experiments. |
| 14:00 | Afridho; management reviews decision | Decide whether a model meets the agreed quality and coverage criteria. If it does, prepare the smallest reviewed integration permitting packet14 AI contribution in isolated guests. | Written proceed/hold decision. No threshold tuning on the final test set; no schema relabelling to bypass shadow mode. Insufficient evidence retains HOLD. |
| 15:30 | Afridho | For a qualified candidate only, prove model-caused kernel action and run legitimate/threat, F1 and combined F2/recovery tests in both editions. | Correlated model score, policy decision, nft update and routed result; every legitimate request outcome; stable engine under full logs; recovery, AI disable/rollback and model-failure checks. |
| 16:30 | Afridho | Finish fresh installation and upgrade checks on the final candidate, signed-licence activation, dashboard save/apply and normal client workflows for each edition. | Exact installed identities, preservation checks, activation status, usable apply procedure and per-edition client results. If no qualified candidate exists, C18 checks are labelled baseline only. |
| 17:00 | Afridho | Submit report, evidence and separate Financial/Education delivery decisions. Identify any Friday work that remains. | DOCX report; hashes; source/model provenance; passed, failed, blocked and unrun gates; reproducible evidence archive; justified Friday plan. |

These are checkpoint deadlines, not guaranteed training or acceptance completion times. If downloads, lab capacity or data preparation overrun, report the impact at the next checkpoint and revise the remaining schedule. Do not compress independent validation to preserve a date.

## Data and model execution details

Start with HIKARI publisher record 6463389, version 1.4.0: the 271.1 MB Monday_2021-04-12_0611.pcap and 97.3 MB ground-truth archive provide a roughly 368.4 MB join/extraction pilot. This pair is not a balanced training corpus. The record also contains 2022 additions; keep years, labels and filenames explicit. Record publisher checksum verification and compute SHA-256 locally before extraction.

Use only verified labelled flows. Match protocol, endpoint tuple, direction and time; exclude uncertain or unmatched labels instead of assuming benign. Do not label an entire attack-named capture malicious. Train on feature prefixes available when the live engine scores, not completed-flow statistics; exclude prefixes with unresolved attack-onset timing.

Keep every flow and all its prefixes in one split. Reserve entire independent captures/sessions; separate dates or environments where possible. Prior captures used during development cannot serve as pristine unseen tests. Fit scaling, resampling and tuning solely on training/validation partitions. Record the schema, feature order, class mapping and exact scikit-learn version required by the current loader. Do not load downloaded third-party pickle files into the root engine.

Compare Random Forest and MLP using one fixed dataset protocol. Select using agreed false client-isolation limits, attack-family recall, time to action, coverage and CPU/memory/latency results. Report denominators and uncertainty; zero errors in a small or correlated sample does not establish a safe production rate. If either class or an edition's normal workflows are missing, do not claim its acceptance.

## Enforcement and client-use acceptance

- Demonstrate a labelled threat for which deterministic rules would allow the traffic, then show that model contribution causes a real kernel block. Retain the model hash, eligible features, score, decision reason, nft state and routed probe outcome. A high score or dashboard message alone is insufficient.
- Repeat the ordinary five-new-connections-per-second fixture with all 300 attempts independently scheduled and every success, timeout or interruption recorded. Require all 300 legitimate HTTP outcomes to succeed without unintended isolation in each edition, then exercise the broader agreed normal workflows.
- Repeat load → full event/flow log volume → deny → sustained block beyond the older block's expiry → recovery. Verify that decisions reach nftables, the engine does not restart unexpectedly, ordinary traffic remains usable and health discloses unavailable logging/export. Include model inference during the fault.
- Demonstrate AI disable/rollback and missing/corrupt/incompatible model behavior against the intended policy. Confirm the resulting protection state is visible and deterministic enforcement remains functional.
- On the exact final candidate, check fresh install plus upgrade preservation of data, administrator, policy and original signed licence. Verify ownership/write protection, actual signed activation and dashboard Save → Apply saved changes without client command-line intervention. Retain any expected detection pause in the operator instructions.

## Escalation and Friday decision

By 08:30, management must either confirm measurable quality criteria and approved normal-traffic inputs or receive an explicit blocker. At 10:00 escalate unresolved ground-truth/extraction problems. At 14:00, if no model qualifies, keep shadow mode, retain HOLD and finish independent baseline installation/client-use work. Any recurrence of F1 or F2 immediately blocks that candidate; regression counts do not override those failures.

Friday delivery requires the final candidate to pass model-quality, actual AI-enforcement, installation, licence, dashboard application and normal-use gates for the edition concerned. If an artifact changes after testing, identify the change and rerun affected gates. A passed Financial result cannot stand in for Education, or vice versa. Otherwise submit the remaining blockers and a revised delivery estimate with evidence; do not defer unsafe isolation or loss of protection as minor limitations.

## Evidence and handoff

Use separate evidence directories per edition and candidate. Retain source/model hashes, dataset provenance and licence attribution, extraction/training commands, split manifest, raw metrics, model-to-kernel traces, request outcomes and recovery records. Public handoffs exclude private keys, credentials and sensitive client data. Deliver the final report as DOCX and include it in the handoff archive with a checksum manifest.

Basis: the revised [4 November daily report](2026-11-04_daily-work-report.docx), [technical acceptance report](2026-11-04_acceptance-minifwai-report.docx) and [model/dataset research report](2026-11-04_model-dataset-research-report.docx). The latter records primary publisher URLs and reuse limitations. This plan adds no new claim of tests passed, model accuracy or release readiness.
