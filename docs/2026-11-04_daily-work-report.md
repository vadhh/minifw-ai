# MiniFW-AI daily work report — 4 November 2026

**Afridho · Standalone Financial and Education · v2.2.10 candidate C18**

**Delivery decision: HOLD for Financial; HOLD for Education.** F1 and the reproduced
F2 expiry defect are corrected and their affected acceptance gates pass in both
editions. Actual vendor-signed licence activation and a usable dashboard save/apply
procedure also pass. Management confirmed today that AI must participate in
enforcement. C18's packet model remains shadow-only because the available validation
does not support safe blocking, so the product promise is still unmet.

The [management handoff](../dist/minifwai-standalone-v2.2.10-C18-management-handoff.tar.gz)
contains the source, both installers, raw public evidence, reproduction drivers and
reports. Its checksum is in the adjacent `.sha256` file. The existing
[C16 handoff](../dist/minifwai-standalone-v2.2.10-C16-management-handoff.tar.gz) is also
available; its checksum was independently verified today.

This revised daily report adds the subsequent model/dataset research and Thursday
execution plan. The dated report supplement contains the updated Word reports;
the existing C18 source, installers and acceptance archive retain their identities.

## Wednesday programme

| Planned deadline WIB | Item | Actual outcome |
| --- | --- | --- |
| 09:00 | Supply C16 handoff and establish baseline | Completed during this session: matching archive checksum, 463 source files and 378 payload files per edition checked. The morning deadline is not claimed met. |
| 11:00 | Diagnose exact combined F2 sequence | Reproduced on C16. Traces show a valid deny decision whose nft update was skipped because an older block still existed; that older block then expired. |
| 13:00 | Correct F1/F2 | Shared connection-count-only isolation removed. Explicit denies now atomically renew older blocks; failed flow exports no longer interrupt the engine. No test-only threshold increase. |
| 15:00 | Build and repeat affected gates | C18 independently reproduced on both VMs. 630 regressions pass per VM; 300/300 HTTP succeeds per edition; full-log deny renewal, routed threat blocks and recovery pass. |
| 16:00 | Signed licence and policy application | Actual vendor signatures issued with the existing Sydeco PC key; dashboard upload, tamper rejection and persistence pass. Save→Apply saved changes→engine restart→kernel action passes in both editions. |
| 17:00 | Candidate and separate delivery decisions | C18 and evidence prepared. Both editions remain HOLD because required AI enforcement is unaccepted. |

Execution evidence begins around 13:11 WIB. This table reports completed work,
not retroactive compliance with scheduled morning deadlines. Scope remained the
two isolated standalone editions. VPN expansion and ARCHANGEL device binding were
excluded; operational host/client installations were not changed.

## What changed and what passed

**F1:** ordinary repeated HTTP no longer isolates a client solely because it opens
200 connections within a minute. Scan, explicit deny and existing measured packet
gates remain. The new test schedules all 300 requests independently of response
timeouts and records every outcome. Education and Financial each completed 300
HTTP 200 responses, with zero failures or isolation, in about 59.803 seconds.
This is a one-minute controlled fixture, not an institution capacity claim.

The old driver was sequential: each timeout delayed later attempts. Its advertised
five-per-second target therefore did not produce 300 attempts. Tuesday's 212–213
recorded outcomes cannot be broken down into exact timeout/interruption timings
because those per-request details were not captured. Today's driver closes that
measurement gap; it does not invent missing Tuesday evidence.

**F2:** the reproduced defect was block expiry handling, not a lost deny decision.
Both guests reproduce C16's failure without disk failure when a newer deny meets
an almost-expired existing block. C18 renews an explicit deny atomically and passes.
The stronger shared-volume probe then found an unhandled flow-export write:
C17's engine restarted when that write failed. The failure is retained; C18 guards
that write and adds two regression cases.
Under the final combined load/full-log test, each edition still blocks HTTP four seconds
after a deliberately seeded two-second older block, despite zero free bytes on
the isolated event-log filesystem. Removing the fault and restarting normally
restores legitimate HTTP. Thirty additional HTTP requests complete on the full event/flow volume, with
the same engine PID and no automatic restarts. Logging/export remain unavailable
during the fault and health
correctly reports 503. Other disk/database failures remain outside this result.

**Upgrade and ownership:** C16→C17 and C17→C18 preserve SQLite integrity, exact user rows,
policy, original licence bytes, deployment ID and the secret environment. Root
ownership/write protections pass for 17,017 Education and 17,019 Financial executable
inputs, with actual denied append-open attempts as both the lab user and non-root
dashboard account. This was an upgrade on existing Debian guests with cached
dependencies; a pristine C18 OS install was not claimed.

**Licence:** the existing vendor keyring matches the packaged keyring. Signed files
were issued for the two actual lab deployment IDs on the Sydeco PC; the private
key stayed there. Both dashboard uploads show valid status through 4 November
2027, survive a web restart, and reject tampering without replacing the valid
licence. This is real-signature lab activation, not production customer activation.

**Dashboard:** save policy/list changes, then open **Policy Configuration → Apply
saved changes**. The explicit apply restarts the engine, briefly pausing new
detections while existing kernel blocks remain. The non-root dashboard gains no
shell or nft capability. The authenticated save/apply tests change the actual
kernel timeout to 11 seconds and block routed HTTP in both editions, with no root
restart after the save. Chromium also verifies the shared control and keyboard
activation at desktop and mobile widths. Live reload was not added.

Initial C17 lab traffic runs could not start their HTTP fixture because the older
source export omitted a media file. That existing fixture is now hashed and
included in the source; the failed runs remain in the evidence. Passing runs do
not replace or erase those records.

## Remaining delivery blocker and Thursday/Friday plan

The AI delivery decision is settled: **AI must participate in enforcement**.
Engineering acceptance remains open. The unchanged packet model's prior public
evaluation labelled 139 of 155 scored benign flows malicious. These reviewed
historical results are not a fresh model-quality measurement and do not justify
turning on blocking. Deterministic firewall success does not close this gate.

The completed [model/dataset research report](2026-11-04_model-dataset-research-report.docx)
recommends comparing a locally trained small Random Forest with the existing MLP
using MiniFW's exact measured packet14 features. Start with HIKARI-2021, publisher
record version 1.4.0, and selected IoT-23 captures. Both publisher records identify
CC BY 4.0. Retain attribution and provenance; UNSW-NB15 requires author agreement
for commercial use and is excluded pending that agreement. Published CESNET and
Kitsune implementations are not verified drop-in packet14 threat models. Publisher
links, terms and technical limitations are documented in the research report.

This is a research recommendation, not a validated replacement. No new dataset
replay, training, installation or AI enforcement acceptance was performed. Matching
packet captures to ground truth and obtaining representative normal Financial and
Education workflows remain prerequisites. Public IoT/web benchmarks alone cannot
establish safe client isolation. Completed-flow CSV statistics cannot substitute
for features available at the actual online decision time.

The [Thursday execution plan](2026-11-05_execution-plan.docx) assigns Afridho the
technical work and identifies management decisions on the false-isolation budget
and approved normal-traffic inputs. By 10:00 WIB establish the label/extractor
pilot; by 13:00 produce independent-holdout model results if the data gates pass;
at 14:00 decide whether any model qualifies for isolated enforcement testing.
If qualified, demonstrate actual model-caused kernel action and repeat F1/F2 with
AI active in both editions. Separately complete final installation, signed-licence,
dashboard apply and client-use checks on the exact candidate tested. By 17:00 issue
separate Financial and Education decisions with passed, failed and unrun gates.

The schedule is a set of checkpoints, not a promise that model qualification can
finish in one day. If data, quality criteria or validation are insufficient,
escalate at the affected checkpoint and continue independent installation checks
on C18 as baseline evidence. Do not claim that those baseline checks cover a later
model-bearing candidate, or convert prior C16 installation results into C18 acceptance.

Friday 6 November remains the delivery target, conditional on AI enforcement
acceptance and final client-use gates. If a validated model and evidence are not
available, escalate the unmet product requirement promptly and retain HOLD for
each edition separately. No unsupported completion date is promised.

## Artifact identity and review

| C18 artifact | SHA256 |
| --- | --- |
| Education | `b180e835a9769ca9ca6de2f0932dd72f190a8a1fd2c13fe392d929353ad18843` |
| Financial | `6e4f812567e87ffb6c8b26e7bbd4d5bc797055e7dfcbf5ab759e4fcc8289e08f` |
| Source | `a17cc8c6138d2dfc734877096aec4212ffd52269d3679c92689380ce47c133f7` |

See [the technical acceptance report](2026-11-04_acceptance-minifwai-report.md)
and [evidence index](evidence/2026-11-04-delivery/README.md) for exact source provenance,
root-cause traces, raw request outcomes, both independent builds, installation
checks, tests and limitations. SHA256 establishes fixity, not publisher identity.
Lab services are stopped and temporary networking is cleaned. Private keys,
credentials, databases and private backups are excluded from the public handoff.
