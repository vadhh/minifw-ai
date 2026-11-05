# Tuesday delivery tasks — standalone v2.2.10

Production release: **HOLD**. Tuesday C16 results are in the [acceptance report](2026-11-03_acceptance-minifwai-report.md).
Fresh installation, upgrade and ownership checks passed in both editions; repeated
legitimate HTTP failed the default connection hard gate in both. The combined
load/log-failure result also remains unresolved. Target: Financial and Education delivery this week,
with a controlled pilot recommendation only after the gates below pass. ARCHANGEL
integration and VPN-server/device-binding work are outside this assignment.
Owner: Afridho; management accepts scope and final delivery. Estimates below are
planning allowances, not measured completion times.

| Priority | Task and allowance | Required evidence | Current status |
| --- | --- | --- | --- |
| P0, today | Source and evidence handoff, 1 hour | Full commit, seven existing tracked changes, explicit additional inputs, source/package hashes, raw results and limitations | Started: [source identity](evidence/2026-11-03-delivery/source-identity.json), [patch](evidence/2026-11-03-delivery/release-inputs.patch), [Monday consolidated report](2026-11-02_correction-minifwai-report.md), [C15 raw evidence index](evidence/2026-11-02-v2210-c15/README.md). Nothing sent externally. |
| P0, today | Privileged input ownership, 1.5 hours | Both editions: fresh installation and upgrade; root-owned code/venv/models/helpers and protected ancestors; dashboard/image user write attempts fail | C16 passes Linux checks, fresh and C13 upgrade, in both editions. |
| P0, today | Reproducible packaging, 1 hour | Clean checkout plus declared overlay produces inspected source-equivalent packages for both editions | C16: identical hashes from independent builds on both VMs; source and payload verification pass. Legacy install_systemd.sh refuses execution. |
| P0, today | Financial upgrade and Education rerun, 1.5 hours | Existing policy, database integrity, admin and licence retained; service readiness; installed package identity; dashboard policy change produces engine action | Both C13→C16 migrations pass; licence-fixture bytes preserved, signed activation unqualified. Dashboard save changes actual nft timeout and routed result after restart. |
| P1, Wednesday | Core acceptance, 2 hours | Separate edition results: measured collection, independent/degraded collectors, policy, actual blocking, legitimate traffic and recovery | Historical C15 results available; changed candidate requires affected reruns. |
| P1, today if P0 complete | Bounded load and isolated disk/log failure, 1 hour | Duration, offered/measured load, resource samples, failures and recovery | Executed in both: 60-second traffic control fails; isolated full-log test blocks and recovers after restart, but combined load/fault fails. See F1/F2 in acceptance report. |
| P1, Thursday | Delivery instructions and demonstration, 2 hours | Installation/configuration, limits, recovery procedure and repeatable client demo | Pending. |
| P0, Friday | Final installation and handoff, 1 hour | Both installers, checksums, source identity, acceptance matrix and pilot/correction/HOLD decision | Pending; final source must include these corrections explicitly. |

## Today's acceptance status

The paragraphs below record the initial task triage. The acceptance report linked
above supersedes their pending statuses with actual C16 results. Remaining owners:
Afridho for F1/F2 correction and affected reruns; management for contractual AI
scope and release acceptance. No external management message has been sent.

**Implemented and verified locally:** permission-mode hardening on disposable
fixtures, rejection of linked application code without modifying its target,
ordering before installed Python execution; six existing package/dashboard
regressions pass. [Commands and raw output](evidence/2026-11-03-delivery/local-checks.log).
These tests mock chown and do not prove Linux ownership or runtime enforcement.

**Implemented, evidence pending:** root ownership repair of the application root,
code, models, YARA rules, scripts, config and existing venv before Python/pip;
removal of group/other write permissions on these inputs. The existing later
postinst grants only the intended dashboard configuration access. Normal venv
interpreter links remain supported. The old service installer exits before changes.

**Failed or incomplete:** fresh/upgrade acceptance of this correction in both
editions, clean source build, Financial migration, load/log-failure acceptance,
management handoff and real model quality. Ownership repair does not authenticate
previously writable venv contents; suspected tampering requires trusted rebuild.
Check privileged environment files, unit files, external interpreters and their
ancestors on the actual gateways before closing the ownership task.

**Outside this week's added scope:** broad VPN detection, expanded DoH coverage,
VPN access/device registration and new features. Retain existing limitations;
do not advertise universal blocking. A documented contractual core requirement
can still be a blocker. AI remains shadow-only with zero enforcement weight.
Management must confirm whether advisory AI satisfies the delivery promise.

## AI dataset specification

No approved dataset is assumed. Each record needs edition, pseudonymous session
and environment identifiers, time/window, collection source, original five-tuple
with pseudonymous addresses, protocol, measured directional packets/bytes and
available timing fields, missing-feature flags, and relevant policy context.
Keep unavailable conntrack packet distributions missing rather than inventing them.
Labels must distinguish benign, controlled threat and unknown, with label reason,
reviewer, provenance, collection permission and collection date. Exclude credentials,
payloads and direct personal identifiers; pseudonymise consistently and specify
access/retention. Split by institution/session/time to prevent leakage. Evaluate
each edition with confusion matrices, false-positive/negative rates, precision,
recall, sample counts, class balance, inference latency and actual policy impact.
Dataset preparation does not delay deterministic firewall corrections.
