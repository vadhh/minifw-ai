# Tuesday work report

**3 November 2026 · Standalone MiniFW-AI Financial and Education v2.2.10 · Candidate C16**

**Tuesday technical work and reporting: complete. Production release: HOLD.**

The priority ownership correction, reproducible packaging and separate installation/
upgrade checks have been completed. Both editions passed their regression and core
routed checks. Acceptance testing also exposed two unresolved issues: legitimate
repeated HTTP traffic was blocked, and enforcement failed in the combined
load-then-log-failure sequence. C16 is an assessment candidate, not an approved
production or pilot release. The management handoff is prepared locally; it has
not been sent externally.

## Assignment and scope

Assignment owner: Afridho. The work concerns the two standalone editions only,
tested on separate isolated QEMU guests. No operational client system or
ARCHANGEL-integrated product was changed. Broad VPN detection, expanded DoH
coverage, VPN-server/device authentication and new features were excluded.

The source, installers, consolidated correction report and raw evidence are now
available in one [management handoff package](../dist/minifwai-standalone-v2.2.10-C16-management-handoff.tar.gz).
This report accompanies that existing package; it was created after the archive
and is not inside it. Historical C15 material is clearly separated from C16.

## Implemented and verified

| Tuesday requirement | Education | Financial | Evidence |
| --- | --- | --- | --- |
| Correct privileged-code ownership | Pass, fresh install and upgrade | Pass, fresh install and upgrade | E1 |
| Build from recorded source | Identical independent builds | Identical independent builds | E2 |
| Fresh package installation | Pass | Pass | E1 |
| C13→C16 upgrade | Pass | Pass | E1 |
| Preserve database, admin and existing policy | Pass | Pass | E1 |
| Preserve licence-file bytes | Pass, lab fixture | Pass, lab fixture | E1 |
| Regression suite | 619 passed; 10 warnings | 619 passed; 10 warnings | E3 |
| Core routed enforcement and recovery | Pass within lab scope | Pass within lab scope | E4 |
| Operational health, backup/restore and dashboard privileges | Pass within lab scope | Pass within lab scope | E5 |
| Dashboard save reaches engine enforcement | Pass after explicit restart | Pass after explicit restart | E6 |

The installer repairs ownership before invoking installed Python. Actual checks
as the image user `debian` and dashboard user `minifw-web` confirmed that protected
code, models, scripts and virtual-environment inputs were not writable. Intended
dashboard policy/feed access remains available. The legacy service installer now
exits as unsupported for this release.

The source uses Git base `e59ace4b228d3c6f14c32473fd8c462c9a84db1a`,
13 declared overlay inputs and recorded LF normalization. All seven pre-existing
tracked changes were preserved and explicitly included or excluded. The source
manifest covers 463 files; all 378 payload files per package were checked.
Independent native builds on both VMs produced identical package hashes. No new
commit or push was made; the complete candidate source and patch are supplied.

## Failed or incomplete

**F1 — legitimate repeated HTTP traffic was blocked in both editions.**

| Edition | Offered load | Measured duration | Successful requests | Failed requests |
| --- | --- | --- | --- | --- |
| Education | 5 new HTTP connections/s | 61.280 seconds | 202 | 10 |
| Financial | 5 new HTTP connections/s | 61.487 seconds | 203 | 10 |

Both clients were isolated. E7 records `flow_frequency` and
`hard_threat_gate_override`; source inspection identifies the shared default of
200 new connections per 60 seconds. This was a deterministic hard-gate decision,
not AI classification. The fixture enabled the optional packet sensor and used a
15-second lab block timeout. This short run is not long-term or institutional
capacity qualification.

**F2 — enforcement continuity after load and log failure remains unresolved.**
In both combined runs, the subsequent deny query produced no kernel block and
HTTP continued while the 64-KiB event-log filesystem was full. Separate disk-only
runs, with an explicitly empty block set, did block the deny traffic despite
ENOSPC errors. They measured zero free bytes and a zero-byte event log; dashboard
login returned HTTP 200 and health returned 503. Removing the fault and explicitly
restarting restored legitimate HTTP. E8 retains both outcomes. The independent
pass does not erase the combined failure; its root cause is not yet established.

## Implemented, evidence pending

Real signed-licence activation has not been qualified; migration proved preservation
of a labelled licence fixture only. Fresh installation used existing Debian VMs
with cached dependencies, not pristine operating systems. Representative external
institution traffic and broader storage-failure behavior remain unqualified.
Ownership repair does not authenticate potentially tampered dependency contents.

AI remains shadow-only with zero model enforcement contribution. No approved
validation dataset is assumed. A dataset specification covering fields, labels,
anonymisation, provenance and metrics is included in the Tuesday task record.
Management still needs to confirm whether advisory-only AI meets the delivery promise.

## Next actions and recommendation

| Priority | Owner | Action | Closure evidence |
| --- | --- | --- | --- |
| P0 | Afridho | Correct legitimate-traffic behavior under the shared connection hard gate | Same bounded traffic probe and threat controls pass in both editions |
| P0 | Afridho | Investigate and correct the combined load/log-failure outcome | Repeatable fault sequence, actual deny block, dashboard/resource observations and recovery |
| P0 | Afridho | Build and identify the corrected candidate | New hashes, declared source and affected regression/runtime reruns |
| Before release | Management / Afridho | Resolve AI contractual scope and signed-licence acceptance | Recorded scope decision and activation evidence |

Keep feature scope frozen and production on **HOLD**. Continue focused corrections
toward this week's delivery. A completion estimate for F1/F2 requires the corrected
rule behavior and fault cause; no unsupported date is promised. The current handoff
is ready for review, not permission to deploy.

## Evidence and artifact index

Evidence paths below are relative to `docs/evidence/2026-11-03-delivery/` and exist
separately under both `education/` and `financial/` unless stated otherwise.

| ID | Raw evidence | Finding and next step |
| --- | --- | --- |
| E1 | `minifw-c16-install-upgrade.log` | Ownership/migration verified; retain signed-activation qualification separately |
| E2 | Root `candidate-source-identity.json`, `release-inputs-final.patch`, `artifact-verification.log`, `build-reproducibility.log` | Build identity verified; use hashes rather than version labels |
| E3 | `minifw-c16-tests-final.log` and `.xml` | 619 regression passes per edition; does not override failed traffic acceptance |
| E4 | `minifw-c16-core.log` and corresponding `runs/` results/nft snapshots | Controlled routed enforcement/recovery; retain stated coverage limits |
| E5 | `minifw-c16-operational.log` | Health, restore and least privilege; broader qualification remains open |
| E6 | `minifw-c16-propagation.log` | Authenticated timeout change 11→13 seconds, kernel entry and routed block after restart |
| E7 | `minifw-c16-bounded-fault.log`, `runs/` events and resource samples | F1: legitimate traffic → shared hard gate → client isolation → correct and rerun |
| E8 | `minifw-c16-bounded-fault.log`, `minifw-c16-disk-only.log`, `runs/` journals/results | F2: load → full event-log filesystem → missing deny block; isolate cause and rerun |

Earlier failures and test-harness corrections are retained. Private credentials,
keys, databases and state backups remain protected on the lab guests. Both guest
services were stopped, temporary networking removed and package fixture
configuration restored; final package verification was clean.

**C16 Education SHA256:** `aae5a64cf65bc5facf30308294ee28b5b74c20cbacc2cbf2c75f342ef638a189`

**C16 Financial SHA256:** `55d36aa58575d6705efa419afd766d21173013311cddff35ed09459cb5c3afa3`

**Management handoff SHA256:** `cedca86d2b4776744e854aaebda1e5cf94a69c348a312a6d9cb2ab4433d2ef09`

Detailed acceptance: [Tuesday acceptance report](2026-11-03_acceptance-minifwai-report.md).
Task status and dataset specification: [Tuesday task record](2026-11-03_delivery-tasks.md).
Raw results: [Tuesday evidence index](evidence/2026-11-03-delivery/README.md).
