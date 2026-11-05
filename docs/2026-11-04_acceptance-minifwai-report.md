# Wednesday standalone v2.2.10 acceptance

**Financial: HOLD. Education: HOLD.** C18 corrects F1 and the reproduced F2 expiry
defect, and passes the affected lab gates in both editions. Actual vendor-signed
licence activation and dashboard save/apply reach acceptance. Management has now
confirmed that AI must participate in enforcement. C18's packet model remains
shadow-only because its existing classification evidence is inadequate; therefore
the promised product is not accepted for delivery.

## Scope and baseline

Work was authorized for standalone Financial and Education in their existing,
separate `minifw-monday-financial` and `minifw-monday-education` QEMU guests. No
operational host/client installation, VPN expansion or ARCHANGEL device-binding
change was made. Work began around 13:11 WIB; morning schedule deadlines are not
retroactively marked met.

The existing [C16 handoff](../dist/minifwai-standalone-v2.2.10-C16-management-handoff.tar.gz)
is available and its SHA256 independently matches
`cedca86d2b4776744e854aaebda1e5cf94a69c348a312a6d9cb2ab4433d2ef09`.
Its 463 source files and all 378 payload files per edition were checked against
the declared source and unit transformations. The C16 base commit remains
`e59ace4b228d3c6f14c32473fd8c462c9a84db1a`; pre-existing workspace changes were preserved.

C18 has [468 declared source/fixture files](evidence/2026-11-04-delivery/candidate-source-identity.json).
Its parent source hash and explicit Wednesday inputs identify every difference.
Both editions remain v2.2.10: distinguish candidates by hashes, never the version
string alone. Native builds on both guests produced the same per-edition hashes.
All 381 payload files per package match source or the exact edition unit transformation.

| Artifact | SHA256 |
| --- | --- |
| C18 source | `a17cc8c6138d2dfc734877096aec4212ffd52269d3679c92689380ce47c133f7` |
| Education installer | `b180e835a9769ca9ca6de2f0932dd72f190a8a1fd2c13fe392d929353ad18843` |
| Financial installer | `6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f` |

Packages and complete source are in [the C18 candidate directory](../dist/v2210-c18-candidates/).
The final source adds the existing media fixture and complete provenance metadata;
production payload inputs are identical to those used in both native builds.

## F1: legitimate traffic

The automatic client-isolation gate based solely on 200 new connections per minute
has been removed from shared production behavior. No lab threshold was raised.
Connection counts remain available to the Financial advisory rule. Explicit deny,
port-scan and existing measured packet gates remain. High connection count alone
is no longer advertised as a sufficient threat signal; this does not establish
protection against every same-port connection flood.

The original driver issued requests sequentially. Each blocked request could spend
two seconds waiting, delaying later attempts; its `offered_rate_rps=5` described a
target, not an independently maintained offered rate. The original 212–213 outcomes
therefore do not represent 300 completed attempts. Exact per-request timeouts were
not recorded then and cannot be reconstructed retrospectively. Wednesday's retained
C16 reproduction similarly produced 200 successes and 9 failures in 61.116 seconds.

The new driver independently schedules 300 attempts at 0.2-second intervals and
retains scheduled, actual start, finish and outcome for every request. The last
request is scheduled at 59.8 seconds, explaining the measured completion time.

| C18 result | Education | Financial |
| --- | --- | --- |
| Scheduled / attempted / completed | 300 / 300 / 300 | 300 / 300 / 300 |
| HTTP 200 / failures | 300 / 0 | 300 / 0 |
| Completion time | 59.803 s | 59.803 s |
| Client isolated | No | No |
| Verdict | Pass, bounded fixture | Pass, bounded fixture |

This is not prolonged load or representative institution capacity qualification.

## F2: where protection stopped

The original C16 combined load → full-log → deny failure reproduced on Wednesday.
Instrumentation shows that the deny query was read and consumed, its feed match
was true, and scoring returned `block` with `deny_domain_client_ipv4_isolation`.
The nft membership check found the older F1 block and returned `False`, so the
engine skipped the update. That old block expired shortly afterward. The later
kernel/HTTP probe found an empty set and successful forwarding.

Separate checks on both guests reproduce the same failure **without disk failure**:
a three-second old block is nearly expired when a fresh deny requests 15 seconds.
C16 skips renewal and protection disappears after the old expiry. C18 renews the
explicit deny and protection remains. Thus the full filesystem was coincident with
this reproduced failure; the evidence does not show that ENOSPC stopped its decision.

C18 renews explicit denied DNS/SNI matches using one atomic nft delete/add
transaction. If the old entry expires during that transaction, it retries a normal
add. Other duplicate detections retain their existing no-refresh behavior. Renewals
are logged as block decisions. Repeated explicit denied traffic can extend isolation;
this is an intentional behavior change.

A stronger follow-up found another storage defect before final acceptance. C17
passed event-log-only failure, but its periodic flow export was outside the
exception handler. Both new unit probes failed before the fix; an actual C17
Education run against a shared full event/flow-log filesystem changed engine PID
and recorded one automatic restart. That failed run is retained. C18 catches
flow-export OSError, reports the unavailable export, and continues enforcement;
it does not print a false export-success message.

After C18's legitimate-load test, each guest receives a real full 64-KiB shared
event/flow-log filesystem. The engine is restarted into that fault as in the original test.
Thirty additional legitimate HTTP requests must complete while both writes fail,
and engine PID must remain unchanged with zero automatic restarts. Then a
two-second old block is deliberately seeded; a fresh deny must replace its expiry.
Four seconds later both guests still have the block and forwarded HTTP fails.
Free bytes, event-log bytes and flow-log bytes are all zero, while services report no automatic
restarts. Login remains HTTP 200; readiness is correctly HTTP 503. Removing the
fault and explicitly restoring/restarting the normal engine produces HTTP 200 again.

This closes the reproduced expiry defect and the shared-volume continuity gate.
Event logging and flow export remain unavailable during ENOSPC. Root-disk, database-disk,
uninterrupted fault injection without a restart, and every other write
failure are not accepted by this result.

## Installation, licence and dashboard

| Gate | Education | Financial | Evidence |
| --- | --- | --- | --- |
| Regression suite | 630 pass, 10 warnings | 630 pass, 10 warnings | `minifw-c18-tests.log` and XML |
| C16→C17→C18 upgrades | Pass | Pass | `minifw-c17-install.log` and `minifw-c18-install.log` |
| SQLite integrity, exact user rows, policy, original licence, deployment ID and secret environment | Preserved | Preserved | Before/after digests in upgrade logs; private backups retained |
| Root-owned non-writable executable inputs | 17,017 files | 17,019 files | Actual denied append-open attempts as `lab` and `minifw-web` |
| Core deny/scan, repeated deny renewal, restart, expiry and manual recovery | Pass | Pass | `minifw-c18-core.log`, corresponding events/nft snapshots |
| Full shared-log volume, engine continuity, deny renewal and recovery | Pass | Pass | `minifw-c18-bounded-fault.log` |
| Actual vendor-signed licence upload and persistence | Pass | Pass | `minifw-c18-dashboard.log`; tampered upload rejected HTTP 400 |
| Dashboard save→explicit apply→new engine→kernel block | Pass | Pass | Same logs: configured timeout 11 seconds in actual nft element; routed HTTP fails |
| Rendered apply control and keyboard activation | Pass | Shared template; API tested | Desktop/mobile Education screenshots and `browser-check.json` |

Licences were signed on the Sydeco PC with the existing `minifw-vendor-2026` key.
Its public key matches the packaged keyring. The private key never left that PC.
These are actual vendor signatures bound to the two isolated lab deployments,
not a byte-preservation fixture or production customer activation. Both display
valid status after a web restart, with expiry on 4 November 2027.

There was no existing safe apply control. C18 provides an administrator-only
**Policy Configuration → Apply saved changes** button. Save policy and allow/deny
list edits, open Policy Configuration, then apply. Applying briefly pauses new
detections while the engine restarts; existing kernel blocks remain. The non-root
dashboard creates a fixed request marker; a root-owned systemd path/service pair
can only restart `minifw-ai.service`. The response requires a new engine PID and
current kernel-rule evidence. Pending, unauthorized, cross-origin and unverified
requests produce errors. No live reload was introduced and the dashboard gained
no shell/nft capability. The lab setup selected collector paths before the saves;
the change was then applied through the authenticated endpoint, with no root CLI
restart after the save. Chromium keyboard activation also succeeded.

Fresh C18 OS installation and a new C13→C18 migration were not repeated. Tuesday's
C16 fresh/C13 migration evidence remains historical. This run verifies the actual
C16→C17→C18 upgrades using cached dependencies on the existing Debian guests.

## AI release blocker

Management's Wednesday instruction is explicit: **AI must participate in enforcement**.
Shadow-only behavior therefore fails that delivery requirement for both editions.
No mode flag was changed to imply acceptance. The unchanged packet14 model's prior
public-data evaluation classified 139 of 155 scored benign flows as malicious;
the prior mixed capture also misclassified 36 of 39 scored benign flows. These are
reviewed historical results, not newly reproduced AI accuracy measurements today.
They justify neither enabling blocking nor an accuracy promise. YARA and deterministic
rules do not substitute for the requested trained-model enforcement requirement.

Closure needs an approved replacement model or labelled Financial/Education data,
independent holdouts by session/institution/time, acceptable benign/threat results,
then actual model-driven enforcement and recovery in both editions. The existing
[dataset specification](2026-11-03_delivery-tasks.md#ai-dataset-specification) applies.
The location of an approved model/dataset was requested during this work and remains
unresolved at report preparation. Owner: Afridho with management/data owners.

## Evidence → finding → path

Evidence records are indexed by [the summary](evidence/2026-11-04-delivery/acceptance-summary.json)
and protected by the evidence directory's `SHA256SUMS`. Raw files remain authoritative.

| Evidence ID | Observation / source |
| --- | --- |
| E1 | `baseline-archive.json`, `artifact-verification.log`, source identity and both `minifw-c18-package-hashes.log` files |
| E2 | Education `minifw-wednesday-c16-diagnosis.log`, `minifw-wednesday-c16-decision-trace.log`: original combined failure and consumed deny→block→skipped nft update |
| E3 | Both `minifw-c18-expiry-causality.log` files: C16 fails and C18 passes without storage failure; earlier C17 checks remain |
| E4 | Both `minifw-c18-bounded-fault.log` files and run directories: 300/300 HTTP, full-log block beyond old expiry, recovery |
| E5 | Both `minifw-c18-dashboard.log` files: actual signature activation, tamper rejection and dashboard→kernel propagation |
| E6 | Both regression XML/logs, upgrade logs and core routed results |
| E7 | `policy-desktop.png`, `policy-mobile.png`, `browser-check.json`: rendered and keyboard-usable apply action |

F1, validated and corrected in bounded acceptance: connection volume alone caused
legitimate isolation. Evidence: E2, E4, plus the shared gate diff. Path: repeated
ordinary HTTP → count threshold → previous hard block; C18 evaluates the retained
threat controls and all 300 requests pass. Residual: wider legitimate traffic untested.

F2a, validated and corrected for explicit denies: existing membership suppressed a
new deny's required lifetime. Evidence: E2, E3, E4 and `enforce.ipset_add`. Path:
old block almost expired → new deny decision → old duplicate suppression → old expiry
→ allowed forwarding; C18 atomically renews the explicit deny before that expiry.
Residual: only the stated storage fault and controlled timing are qualified.

F2b, validated and corrected for shared-log writes: an unhandled flow-export
OSError interrupted the engine. Evidence: local-full-volume-before/after logs,
Education 'minifw-c17-full-volume-before.log', and both final C18 shared-volume
results (E4). Path: periodic flow export → ENOSPC on write/close → prior engine
exit/restart; C18 catches the write error and processes the later deny with the
same engine PID. Residual: the root/database filesystem remains unqualified.

Reproduction requires the authorized isolated guest names and cached lab tools.
Use the guarded drivers in [the evidence directory](evidence/2026-11-04-delivery/README.md)
with that guest's edition, its exact C18 package, and the extracted source root.
`lab_block_expiry.py` runs without arguments on either guest. Locally, run
`python3 docs/evidence/2026-11-04-delivery/verify_artifacts.py` from the handoff root
to check provenance and both packages; `dpkg-deb` and the bundled C16 parent source
are required.

Initial C17 traffic runs failed to start their HTTP fixture because the C16 source
export omitted `testing/lesson.webm`. The existing fixture was retrieved, hashed and
included in the final C18 source; the initial failures remain. Local Mac route tests
could not import missing `passlib`; the full Linux suites ran all 630 tests without
skips. Early test/verifier harness corrections are not counted as product acceptance.

Final state: fixture policy/feeds restored, `dpkg --verify` clean, services stopped,
temporary namespaces removed. The apply path remains enabled for next boot. Private
installer logs, keys and original state backups are excluded from the handoff.
