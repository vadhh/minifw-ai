# MiniFW-AI technical acceptance — 5 November 2026

Standalone Financial / Education · C18 baseline and C19 warning candidate · Financial HOLD / Education HOLD

## Conclusion and scope

Today's executed artifact checks, clean C18 installation checks and C19 bounded lab acceptance improve the evidence available for review. C19 adds an operator-visible health warning, reproduces packages on two guests, preserves upgrade state and passes deterministic enforcement, logging-recovery, signed-lab-licence and dashboard-application checks. No tested AI model qualifies for enforcement. A 90% malicious-recall target is confirmed; a field false-isolation budget and accepted representative corpus remain open. No model-caused kernel action or AI-active F1/F2 acceptance is claimed. Friday release is blocked unless those gates are closed on an exact final candidate.

Authorised targets were the existing isolated `minifw-monday-education` and `minifw-monday-financial` QEMU guests, plus two new clean `minifw-thursday-*` Debian guests. The Sydeco host supplied virtualisation only; its operational MiniFW services were not changed. VPN expansion and all ARCHANGEL work were excluded. Public PCAPs were decoded offline, never replayed onto a network. New traffic used only fictional namespace services.

## Source and package identity

Repository: `/Users/st4rdhoom/minifw-ai`. Branch: `fix/monday-core-20261102`. Base commit: `e59ace4b228d3c6f14c32473fd8c462c9a84db1a`. The worktree is dirty; `session-baseline.json` and `workspace-status.txt` record the initial state. The commit does not describe the full candidate. C19 derives from C18's immutable source archive, replacing only `app/web/templates/admin/base.html`; the source manifest declares every file and the parent source hash.

The original C18 handoff checksum again matched `d0e5e28f941c01556241b3d98aceb23eebe5e588bebbd03ad0b10a2a4940909b`. Its 418 regular files, 404 checksum entries, 468 source-file declarations and all 381 payload files per edition were checked. This establishes artifact consistency, not a new traffic-test pass or publisher authentication.

| Artifact | SHA-256 |
| --- | --- |
| C19 source.tar.gz | `ea5c70590a255f7c946acb49a287ca556b7a39c1fb0769eee332a28eb8af40be` |
| C19 minifw-ai_2.2.10-education_amd64.deb | `8b11399b266492927576590ee1a21c108c028a469d1f6fde8d96e040f74a1c6d` |
| C19 minifw-ai_2.2.10-finance_amd64.deb | `ead9c4a376c4680c8cfdbbf97e303e8a8361a4bad47ae3a48094c12db8819744` |

C19's two independent native builds matched after setting `SOURCE_DATE_EPOCH=1793836800`. First builds without that environment setting differed; their logs remain. Source/payload verification checks every file hash, undeclared changes, per-edition systemd transformations and archive root ownership. The engine and shipped packet model are unchanged from C18. A new model would require a separately identified candidate and affected acceptance, rather than inheriting these passes.

## Public dataset pilot

Publisher: HIKARI record 6463389, version 1.4.0, [pinned record](https://zenodo.org/records/6463389). The publisher record identifies CC BY 4.0; retain attribution, licence link and descriptions of transformations. This is not a legal review of all downstream data rights.

| Publisher file | Bytes | Publisher MD5 | Local SHA-256 |
| --- | --- | --- | --- |
| BRUTEFORCE_XML/pcap/Monday_2021-04-12_0611.pcap | 271,079,071 | `ec97d152f8e8582dd093873d40e8c9b4` | `c2d16c3a3b17f4e2f6ce82c6dbc952af9f67ac1e864e12a02e8731a274fc7ab1` |
| ground-truth.zip | 97,345,155 | `a940cca16c3f1051e0de30f22bb843de` | `4005ec39ba2d3a26e224312957191fe00f43423c3f0dd41e72ec7f7441aa8e25` |
| ALLFLOWMETER_HIKARI2021.csv.zip | 68,403,081 | `d7d9e277fe4a66cb00764d7f91a810dd` | `ba09d35269566fd2f269871043b24e7d8e372bc4a47e9c2027729e5ff2e660e0` |

Acquisition used the recorded publisher MD5 and exact byte counts, plus new local SHA-256 values. Actual archive inspection corrected the previous research assumption: `ground-truth.zip` contains six anonymised PCAPs. It contains neither a CSV label table nor a matching Monday 12 April ground-truth file. The separately downloaded labelled CSV has 555,278 rows, including 517,582 publisher label-0 and 37,696 label-1 rows. Its columns include endpoint addresses/ports, UID, duration, traffic category and label, but no absolute start timestamp or transport protocol.

The pilot decoded 290,207 packet rows and observed 15,032 TCP/UDP streams. There were 5,466 unique endpoint-quadruple candidates and 9,566 ambiguous candidates; zero streams lacked such a candidate. All unique candidates carried `Benign / 0`. Of all streams, 2,942 yielded an eligible five-packet prefix and 12,090 did not. These counts do not establish time-specific label matches or a useful attack/benign corpus. Accepted HIKARI labels: **0**; accepted HIKARI training flows: **0**. No HIKARI model was trained.

A quadruple candidate is not an accepted five-tuple/time join. Direction, protocol, tuple reuse, capture/session identity and attack-onset timing remain unresolved. No label was guessed from a PCAP filename or projected across every flow in an attack capture. The pilot's first-packet direction is used only to inspect feature extraction; it is not accepted as publisher client identity. Source data remain in the lab; the handoff contains provenance, checksums, commands and aggregate diagnostics rather than the 437 MB publisher downloads.

## All 14 live features and availability

Source definitions: `app/minifw_ai/collector_flow.py`, especially `FlowStats` and `build_packet_features_14`; parsing/direction: `collector_packets.py`; model eligibility: `utils/mlp_engine.py`. Sizes use original captured frame length, including headers, rather than TLS application payload or a completed-flow CSV estimate. Only observations already received contribute. A positive measured duration and at least five packets are required by this experiment's scoring rule.

| Feature in model order | Definition at current prefix | Earliest measurement |
| --- | --- | --- |
| duration_sec | Last observed packet time minus first observed packet time | Two distinct timestamps |
| pkt_count_total | Observed packet count in both directions | First packet |
| bytes_total | Sum of observed inbound and outbound frame lengths | First packet |
| bytes_per_sec | bytes_total / positive duration | Two distinct timestamps |
| pkts_per_sec | pkt_count_total / positive duration | Two distinct timestamps |
| avg_pkt_size | Mean of retained observed frame sizes | First packet |
| pkt_size_std | Population standard deviation of retained sizes; zero for fewer than two | Two packets for variation |
| inbound_outbound_ratio | Inbound bytes / (outbound bytes + 1), with production direction rules | First direction-resolved packet |
| max_burst_pkts_1s | Largest count in retained anchored one-second windows or the current window | First packet; partial current window included |
| max_burst_bytes_1s | Largest byte sum in the same anchored windows | First packet; partial current window included |
| interarrival_mean_ms | Mean of observed successive packet gaps in milliseconds | Second packet |
| interarrival_std_ms | Population deviation of gaps; zero with fewer than two gaps | Third packet for variation |
| interarrival_p95_ms | Sorted gap at index int(0.95 × gap count), capped by the last index | Second packet |
| small_pkt_ratio | Fraction of retained frame sizes strictly below 120 bytes | First packet |

Size history is bounded to 1,000 values, interarrival history to 500 gaps and burst history to 60 completed anchored windows plus the current window. Cumulative byte/packet counters have different retention semantics. Anchored windows are not a mathematically rolling one-second maximum. All five-packet test vectors were compared against independently calculated NumPy statistics for all 14 values; exact counts and hash-identified captures are in `model-comparison.json`.

Five TLS packets often describe only the handshake. Availability of a numerical feature vector does not establish availability of evidence of application-level password guessing. The experiment's attack-session labels must not be represented as proof that an attack had begun at that prefix. No future completed-flow feature was used, but projecting future activity into a prefix target is a separate label-timing limitation.

## Generated corpus and comparison protocol

No real customer corpus was supplied. As requested, a new controlled lab corpus was created in each edition: four benign and four password-guessing sessions, 30 TLS request flows per capture. Sixteen complete captures yield 480 eligible five-packet vectors. The benign mix includes ordinary web, lesson, search, media and a permitted failed login. Attack sessions contain repeated wrong-password attempts against the same fictional TLS endpoint.

Entire generated sessions 0–1 were training (240 flows), session 2 validation (120), and session 3 test (120); no flow prefixes cross split boundaries. Both editions share the fictional service/network implementation. This is a held-out session experiment, not independent-environment or institution validation. Initial buffered captures were incomplete, including one empty PCAP; they and their preliminary model outputs remain but were excluded from the corrected comparison. Immediate tcpdump delivery and a drain interval produced 30 eligible flows for all 30 requests in every accepted capture. Decoder errors and denominator mismatches fail the corrected script.

The retrained MLP uses layers (32,16), at most 300 iterations, random seed 20261105. The RF uses 64 trees, maximum depth 6, minimum leaf size 5, balanced class weights, one worker and the same seed. Scaling is fit on training rows only. The shipped MLP is evaluated unchanged with its own scaler. Threshold 0.5 and model settings were not tuned on the test data. The validation/test manifests and all source commands are retained. Experimental joblib bundles were not installed or represented as production-compatible qualified models.

The following are diagnostic confusion counts against session tags, **not accepted attack-onset recall or production false-isolation rates**. TN/FP count benign fixture flows; FN/TP count attack-session flows.

| Model | Edition | TN | FP | FN | TP | Benign flag fraction | Attack-session flag fraction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| shipped_MLP | education | 0 | 30 | 0 | 30 | 100.0% | 100.0% |
| shipped_MLP | financial | 0 | 30 | 0 | 30 | 100.0% | 100.0% |
| shipped_MLP | all | 0 | 60 | 0 | 60 | 100.0% | 100.0% |
| trained_MLP | education | 8 | 22 | 14 | 16 | 73.3% | 53.3% |
| trained_MLP | financial | 7 | 23 | 20 | 10 | 76.7% | 33.3% |
| trained_MLP | all | 15 | 45 | 34 | 26 | 75.0% | 43.3% |
| small_RF | education | 14 | 16 | 17 | 13 | 53.3% | 43.3% |
| small_RF | financial | 14 | 16 | 11 | 19 | 53.3% | 63.3% |
| small_RF | all | 28 | 32 | 28 | 32 | 53.3% | 53.3% |

| Model | Fit wall seconds | Fit CPU seconds | Inference mean / p95 ms | Process peak RSS KiB | Artifact bytes |
| --- | --- | --- | --- | --- | --- |
| shipped_MLP | 0.000035 | 0.000031 | 1.507 / 2.124 | 155,880 | 32,059 |
| trained_MLP | 0.149316 | 0.149341 | 1.398 / 1.459 | 155,880 | 33,515 |
| small_RF | 0.106245 | 0.097466 | 5.648 / 6.012 | 155,880 | 171,083 |

Latency measures a single vector through the scaler and predict_proba, including DataFrame selection. It excludes collection, queueing, decision processing and kernel-action latency. RSS is the process high-water mark reached by that point, including interpreter/library/data memory; it is not isolated model memory. The shipped MLP has no new training, so its near-zero fit CPU time is not a training-cost result. These measurements establish no appliance throughput or capacity guarantee.

Additional, separately captured normal workflows on C19 exercise successful login, account API, payments, transfers, rejected invalid operations, statement download, student/staff authorisation, lesson/search and media/range delivery. All succeeded without client isolation while AI remained shadow-only. Staff and ordinary roles shared the same lab source address. These fixtures provide a starting corpus, not permission to claim production-sector representativeness, physical browser playback or validated network segmentation.

## Baseline enforcement, storage and visibility

C18's new scan follow-up in each edition produced `port_scan` and `hard_threat_gate_override`, real block-set membership and denied routed HTTP. Count-only isolation remains removed. This checks a distinct-port abuse pattern; same-port flood and encrypted credential-abuse coverage are not established.

The final C19 fault runs are `education/runs/minifw-monday-education-20261105T020433Z/` and `financial/runs/minifw-monday-financial-20261105T020432Z/`. Each independently scheduled 300 HTTP requests at five per second and recorded every outcome. All 300 succeeded with no unintended isolation. After filling the dedicated 64-KiB event/flow tmpfs, 30 additional legitimate requests completed; PID remained stable and NRestarts remained zero. A new explicit deny renewed a seeded two-second older block; the kernel block was still present four seconds later and routed HTTP failed. Free space was zero and event/flow files could not accept records.

The shared administrator-page warning is C19's only product change. It polls existing `/health/`, shows unavailable protection/recording checks on non-ready responses or network failure, and hides the warning only on a successful ready response. It neither performs policy reload nor grants dashboard privileges. The warning explains that new detections and reliable event recording are unconfirmed and directs the operator to check storage/contact the administrator. It does not assert a specific cause from a generic readiness failure.

During the actual full-volume probe, health returned 503 and authenticated Chromium showed the warning in both editions at desktop and mobile widths. After fault removal and an explicit restart to the normal log path, new event records were written, flow output was present, health returned 200 and the warning disappeared. Screenshots, request outcomes, nft state and recording-resumption timestamps are retained. Observed final event timestamps were 09:06:25.319 WIB (Education) and 09:06:22.871 WIB (Financial); these are observed post-recovery records, not a claimed exact instant at which reliable recording first resumed.

Records lost during the fault are absent; no backfill is claimed. The audit log itself was not placed on the full volume. Neither full root/database failure nor every storage failure mode was tested. Chromium screenshots/viewport assertions do not constitute physical-device or screen-reader acceptance. The UI detector found no mechanical findings; warning rendering was visually inspected at the recorded sizes.

## Application, licence and installation

C18's sampled old-to-new-engine observation intervals were 2.915 seconds (Education) and 2.979 seconds (Financial). Apply HTTP response times were 2.822 and 2.837 seconds. Existing kernel blocks remained; sampled routed HTTP continued. These intervals include probe and health publication cadence and do not certify a lossless detection restart. A deliberately stopped apply watcher produced 503 with the old engine still running; administrator restoration of the watcher and removal of the pending lab marker allowed retry 200. Invalid-policy restart failure and automatic recovery from it remain untested.

On C19, the authenticated dashboard saved the deny domain and timeout, requested Apply, restarted the engine and produced an actual 11-second kernel element and denied routed HTTP. Collector paths were configured by lab root before the save; no root restart followed the save. Original policy bytes were restored. Dashboard add/delete normalised the feed's ordering; equality of all feed tokens was checked before restoring original formatting. Both upgraded packages then had clean dpkg verification.

Actual vendor-signed licences for the two existing lab deployment IDs were uploaded again on C19. Both returned valid status, tampered uploads returned 400 without replacing the licence, and valid status survived a web restart. These are real signatures from the existing vendor keyring and explicitly labelled lab customers. No private key was copied to the guests or exported. No fresh-guest signed activation or production-customer activation is claimed.

Two new clean Debian guests were created from base SHA-256 `b1b018dc1046fb21815f6cfe4b67ac1d56bc841e19c4ba2c16073031386ad774`. Before installation, application directory, database and environment file were absent. Each installed its exact C18 edition successfully with newly resolved dependencies, clean dpkg verification, SQLite integrity, one administrator, mandatory password change/re-login and authenticated policy/licence pages. Executable inputs were root-owned and not group/world writable: 16,410 files for Education and 16,412 for Financial. Append-open attempts by both lab and minifw-web were denied. Secret-bearing installation output and replacement passwords remain private in the guest. Cloud-init reports an error because copied boot instructions tried to disable absent MiniFW units; the clean-app preconditions and subsequent installation checks are independent of that boot command result.

These are fresh **C18** checks, not fresh C19 or future-model acceptance. The existing guests separately passed C18→C19 preservation of exact administrator rows, policy, licence bytes, installation ID and environment. Protected-file counts were 17,017 and 17,019, with both unprivileged write probes denied. Differences from clean guests include existing lab dependencies. All 630 tests passed on each C19 guest in about 26 seconds, with ten retained existing warnings including legacy model/scikit-learn-version warnings. No regression count overrides failed model quality.

## Evidence → finding → delivery path

| Evidence ID | Finding supported | Review path |
| --- | --- | --- |
| E01 — session-baseline.json, c18-archive-verification.json | Archived candidates are identifiable despite the dirty worktree | Verify source and package manifests before reproducing tests |
| E02 — hikari-download-manifest.json, hikari-pilot-result.json | Acquisition/extraction succeeded; time/protocol/onset labels are unresolved | Exclude HIKARI training until an independently checked join is available |
| E03 — per-edition corpus manifests and PCAPs | New fictional traffic exists with retained outcomes and capture identities | Review class definitions, timing, completeness and limits |
| E04 — model-comparison.json, prefixes.json, compare_lab_models.py | Feature parity holds; session-tag predictions do not qualify any model | Keep shadow mode; establish valid labels and a new frozen qualification protocol |
| E05 — C18 corpus/scan results.json and nft snapshots | Remaining distinct-port scan control still blocks | Do not infer every flood/abuse pattern is covered |
| E06 — fresh-education.json, fresh-financial.json, fresh-guest-manifest.json | Clean C18 installation/onboarding checks passed | Keep separate from C19 and future-model installation acceptance |
| E07 — c19-upgrade.log and final-state.json per edition | State/write protections preserved; fixture cleanup verified | Review hashes and exact installed candidate |
| E08 — final C19 fault results, bounded-load.json, nft snapshots | Bounded F1/F2 deterministic enforcement and recovery passed | Repeat with actual AI enforcement on any qualifying later candidate |
| E09 — operator-browser screenshots and JSON | Fault warning appears and clears on observed recovery | Retain audit/full-disk and accessibility limitations |
| E10 — c19-dashboard.log | Signed lab licence and authenticated save/apply reach the engine/kernel | Verify final deployment separately from laboratory identities |
| E11 — c19-tests.xml/log per edition | 630 regressions passed per guest | Read warnings and do not substitute them for acceptance gates |
| E12 — c19-source-identity.json and artifact-verification.log | One declared product-file change and source/payload consistency | Freeze hashes before any delivery decision |

No model qualified, so model-caused kernel action, AI-enforcing F1/F2, and model-failure/disable/rollback acceptance on a new model candidate remain **unrun**. Financial and Education are separately HOLD. This is a failed/blocked release path, not an accepted AI product.

## Reproduction and handoff

Run `python3 docs/evidence/2026-11-05-delivery/verify_artifacts.py` from the extracted project root with dpkg-deb available. The archive includes both C19 artifacts and parent C18 source needed for verification. Exact build commands use the archived source and `SOURCE_DATE_EPOCH=1793836800`, followed by `bash scripts/build_deb.sh education` and `bash scripts/build_deb.sh finance`. Do not build from the dirty workspace and assume it is the tested candidate.

For offline analysis, `acquire_hikari.py` performs checksum-checked downloads into an unprivileged temporary directory. `hikari_pilot.py` audits candidates without accepting labels. `compare_lab_models.py` takes writable copies of the two generated corpus directories, imports the installed production extractor using `PYTHONPATH=/opt/minifw_ai/app`, and uses the trusted installed shipped model. It requires the scikit-learn version recorded in the results, NumPy/pandas, and tshark. It fails if splits lack either class, capture hashes/counts differ, decoding fails or independent feature calculations disagree. It does not establish trustworthy attack-onset labels or load third-party downloaded pickle files.

Guarded root drivers require the named isolated QEMU guests, the archived source tree and exact edition package. `lab_fault_visibility.py` additionally expects the original Wednesday fault driver copied to `/var/tmp/lab_c18_fault_original.py` and `browser_health_check.py` staged in `/var/tmp/`. Lab-only tools include dnsmasq, conntrack, nftables, tshark/dumpcap, tcpdump, Chromium and Playwright. Signed-licence tests require already issued, deployment-matching lab licences; private signing keys are neither included nor needed by the reproduction driver. The fresh-install verifier is for the initial password-change state on a new guest, not an idempotent customer-state operation.

Failed runs remain under each edition's logs/runs. Incomplete acquisition, health-path mismatches and a mistaken Python API call were harness errors; they were corrected and rerun without changing product thresholds. The final filtered export includes only selected fictional traffic, results, logs and screenshots. Private keys, passwords, browser sessions, installer secret output, databases and private backups are excluded. Hashes establish fixity, not external independent reproduction.

The management handoff includes this DOCX, the daily DOCX, prior Word reports, source, both installers, raw selected evidence and checksum manifests. Existing C18's complete handoff is supplied separately for historical review. The remaining Thursday and conditional Friday finishing programme is in the daily report; no approval or successful future checkpoint is inferred from elapsed time or the delivery target.
