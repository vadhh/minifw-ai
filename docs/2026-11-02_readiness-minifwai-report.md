# MiniFWAI Monday correction status — 2 November 2026

This is a repository and artifact audit, not production acceptance or a completed 17:00 submission. **Packaging and operational documentation have been prepared; the shared critical corrections have not been implemented in this checkout.** The current requirement probes produce **13 passes and 9 failures**, with no errors or skips. Neither edition has verified live enforcement, recovery or legitimate-traffic acceptance evidence for v2.2.10.

No package was installed and no operational ARCHANGEL system or client network was accessed. The engine probe uses temporary files, mocked telemetry/state control, and a mocked enforcement function. It does not demonstrate packet blocking. Application code, policy thresholds and existing tests were left unchanged. The additions from this audit are this report and its evidence scripts/logs.

## Baseline and existing work

- Repository: `https://github.com/vadhh/minifw-ai`.
- Branch: `main`.
- Exact starting/current commit: `e6b62a9df65261bba2cfc10618af7d552f016817` (C0). The latest commit is the 26 October DNS-log-path correction, not a Monday core correction.
- Baseline log timestamp: `2026-11-02T01:59:17.635673+00:00`, **08:59:17 WIB**. This establishes workstation provenance before 09:00; it does not establish a Linux laboratory before that deadline.
- Starting tracked modifications: `README.md`, `app/web/routers/admin.py`, `app/web/templates/admin/partials/sidebar.html`, `build_usb.sh`, `pyproject.toml`, `requirements.txt`, `scripts/build_deb.sh`. Git reports 7 files, 60 insertions and 40 deletions. These changes concern packaging/versioning, licensing/UI and USB feed inclusion, not the shared collector/parser corrections.
- Starting untracked product work includes licensing implementation/templates/keyring/tool, assessment builder, `docs/deployment-assessment.md`, `docs/licensing.md`, `docs/technical-reference.md` and `uv.lock`. Agent/tool configuration and local metadata are also untracked. The exact inventory is in [baseline.log](evidence/2026-11-02-readiness/baseline.log); its `docs/evidence/` entry was created by this audit.
- Review host: macOS 26.7.1, ARM64, Python 3.12.15 in `.venv`. `dpkg-deb` is available. `nft`, `systemctl`, pytest and the Python YARA module are absent in the inspected environment. A Docker executable is present; no VM or Docker laboratory was established during this audit.
- Actual laboratory OS, snapshot IDs, interfaces, routed topology and client addresses: **not established**. Addresses in probes are fixtures, not evidence of provisioned clients.
- Owner of this audit: Codex. No second engineer or subagent assisted. Future engineer roles in the matrix are **unassigned**, not completed allocations.

Existing useful work includes sector-specific source kits, older prebuilt installers, sector policy files, a shared model, rule helpers, unit tests, and deployment/rollback guidance. `docs/technical-reference.md:478–506` already documents collector coupling, DNS-disabled hard-gate skipping, IPv4 scope, SafeSearch limitations and weak health evidence. Documentation of a defect is not its correction.

### Artifact identity and independently checked hashes

All paths below are under `dist/production-assessment/`; Debian packages are embedded in their corresponding installer ZIPs. No standalone `.deb` was found under `build/` or `dist/`.

| Artifact | SHA256 |
| --- | --- |
| `minifw-ai-education-v2.2.10-source-assessment.zip` | `60e7c2f20da0f3b9f8d79eda54806b081aaf19866bd974dfa3cf7d2bb36894c2` |
| `minifw-ai-financial-v2.2.10-source-assessment.zip` | `15b31e1c0ddef104584fcb46972099948ccd229b6cbaead38ff89f4a51c43e61` |
| `minifw-ai-education-v2.2.9-installer.zip` | `7b305597339a7907ea36a32498fc0aa0597295082a8258ba1743e3b3423c9747` |
| Embedded `minifw-ai_2.2.9-education_amd64.deb` | `508dc7488f718a55426a6e36a481741577b459ab37c0aef2df987f65f3bb4a2e` |
| `minifw-ai-financial-v2.2.9-installer.zip` | `9eccde6902304bfef85a4822e054f2665a0186831a20c933fd8d41f39841bef9` |
| Embedded `minifw-ai_2.2.9-finance_amd64.deb` | `3af65157cb43a1ffb61e1d8a00a53346c7c345a62e258c7ff1cd26f0372504e0` |

**Version mismatch:** the available v2.2.10 artifacts are source kits. The available prebuilt installer ZIPs and their actual Debian metadata are v2.2.9. A v2.2.10 installer/package acceptance result cannot be assigned to them. No rebuild was performed, so there are no updated package hashes.

The audit recalculated archive hashes and ZIP CRCs; checked all 200 source-manifest entries in each v2.2.10 kit; and compared 198 entries with existing repository files, applying only the declared shell/service LF normalization. There were no mismatches. `START_HERE.md` and `ASSESSMENT.md` are kit documents rather than same-path repository files. The base commit in both manifests equals actual `git rev-parse HEAD`.

For each v2.2.9 installer, the embedded Debian hash matches its build manifest; real `dpkg-deb --field` identifies `Package: minifw-ai`, `Architecture: amd64` and the edition-specific v2.2.9 version. All 196 manifest-listed payload file hashes match the Debian data archive. The older source snapshot differs from the current repository at `scripts/build_deb.sh`, whose default version changed to 2.2.10. Source-manifest entries inside an installer manifest describe provenance; they are not expected to be loose files in that ZIP.

The engine, flow parser, enforcement module and model in the source manifests also match their C0 Git blobs. The inspected core, policies and parser tests have no working-tree diff. This is independent evidence that the manifest's base-plus-local-changes description is accurate and that these packages do not contain the requested core corrections. Hash and packaging success establish integrity and identity, not operating effectiveness.

## Consolidated requirement matrix

`C0` means existing implementation at the exact base commit above. `—` means there is no corrective commit. “Verified complete” applies only to the stated narrow deliverable, such as this provenance check or input inventory. A broken existing implementation does not earn that status. `E1–E4` are defined below.

| Requirement | Owner | Status | Commit | Test | Expected result | Actual result | Evidence | Remaining work |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline: repository, commit and working tree | Codex | Verified complete | C0; audit uncommitted | Git identity and source hashes | Verify actual state against manifest | Exact C0 match; 7 tracked modified files; core unchanged | E1 | Preserve snapshot with corrective work |
| Baseline: supplied ZIP and Debian hashes | Codex | Verified complete | C0 + local packaging | Hash, CRC, Debian metadata/payload inspection | Identify every available installer and package | v2.2.10 source kits; v2.2.9 prebuilt installers; checks match | E1 | Locate any separately supplied v2.2.10 installers if they exist elsewhere |
| Isolated Linux lab, snapshots and actual client map | Lab operator, unassigned | Blocked | — | No live lab test | Separate gateways/snapshots for package name `minifw-ai` | Workstation only; topology and clients unavailable | E1 | Provision and record both environments before live testing |
| Correct original tuple and procfs/CLI TCP/UDP parsing | Core engineer, unassigned | Not started | — | Four parser requirement probes | Original client/destination/port and correct protocol | All four fail; CLI also returns timeout as protocol | E2; E3 | Fix parser and replace tests that expect reply tuples |
| Independent DNS, Zeek and flow collection | Core engineer, unassigned | Not started | — | Static control-flow review; live outage test absent | Decisions continue when any collector is quiet/missing/stopped | Synchronous iterator reads remain coupled | E3 | Independent scheduling and bounded reads; outage regression tests |
| Flow decisions without DNS | Core engineer, unassigned | Not started | — | Engine probe with no DNS and supplied flows | Evaluate and enforce controlled flow threat | Zero evaluator calls and zero enforcement calls | E2; E3 | Run flow evaluation outside DNS-only branch; then prove packets |
| Credible counters/deltas and disabled unsupported timing | Core engineer, unassigned | Not started | — | Trace parser → pump → FlowStats | Use measurements, never snapshot-as-packet estimates | Default 1,500 bytes per observation; no counter parsing/deltas | E3 | Correct telemetry and feature availability; keep thresholds unchanged |
| DNS/SNI correlation to the actual connection | Core engineer, unassigned | Not started | — | Two unrelated-connection probes | Unrelated connection stays unlabeled | Both DNS and SNI spread across client flows | E2; E3 | Preserve connection identity and correlate only supported metadata |
| Selected IP, nft entry and failed forwarded connection | Lab operator, unassigned | Implemented, verification pending | C0 | Existing enforcement code/mocks; no packet test | Same selected client appears in kernel set and loses forwarded access | IPv4 source-drop code exists; no live proof | E3 | Before/after nft evidence plus client-side connection failure |
| Unblock/expiry, duplicates and restart behavior | Lab operator, unassigned | Implemented, verification pending | C0 | Static timeout/rule reuse review | Recovery, bounded duplicate events and stable restart | Timeout/rule-reuse code exists; no acceptance test | E3 | Verify manual unblock, expiry, repeated decisions, restart and reboot |
| Financial: DMZ precedence | Core engineer, unassigned | Not started | — | `10.10.0.20` segment probe | `dmz` | `internal` | E2; E3 | Specific-subnet precedence plus overlap tests |
| Financial: each rule's input and live supply documented | Codex | Verified complete | Audit uncommitted | Rule-to-builder field trace | Complete input inventory | Inventory below identifies absent/unreliable inputs | E3 | Update inventory after telemetry changes |
| Financial: destination IP and ASN checks | Core engineer, unassigned | Not started | — | Main-loop address trace | Match destination and feed/ASN policy | Main loop looks up/checks client address | E3 | Use associated destination; populate sector ASN inputs/config |
| Financial: TLS minimum version | Core engineer, unassigned | Not started | — | Config → collector → evaluator trace | Reject prohibited versions if claimed | Version flag exists; version is not passed to evaluator or enforced | E3 | Mark unimplemented; implement only with a reliable metadata source |
| Financial: disconnected country/asset/JA3/API rules identified | Codex | Verified complete | Audit uncommitted | Field inventory below | No unsupported active-protection claim | Required inputs absent from live sector builder | E3 | Keep claims disabled until data-source integration and tests |
| Financial: approved deny-domain semantics | Product owner, unassigned | Blocked | — | Score-only control | Explicit immediate-block or score contract | Deny alone adds 40; sampled internal segment monitors | E2; E3 | Approve behavior and test it without threshold compensation |
| Financial: login, payment/API, downloads, authorized transfers | Lab operator, unassigned | Blocked | — | Not run | Legitimate tasks remain usable | No v2.2.10 client-side acceptance evidence | E1; E4 | Record all four workflows and false positives in Financial lab |
| Financial: enforcement scope and IPv6 limit documented | Codex | Verified complete | C0 documentation; audit uncommitted | Rule/set inspection | State actual restriction precisely | Client-source forwarded IPv4 isolation; no IPv6 or local INPUT/OUTPUT protection | E3 | Obtain product approval for intended isolation scope |
| Education: actual SafeSearch resolver enforcement | Core engineer, unassigned | Not started | — | Config/helper trace | Restricted resolver answers plus client search test | Only allow patterns; no supplied SafeSearch resolver directives found | E3 | Supply resolver configuration and test, or mark pending |
| Education: bare and subdomain content matches | Core engineer, unassigned | Not started | — | School-feed `4chan.org`/`www.4chan.org` probe | Both match | Bare false; subdomain true | E2; E3 | Explicit apex/subdomain semantics for all relevant patterns |
| Education: deny match causes approved restriction | Product owner and lab operator, unassigned | Blocked | — | Student score-only control | Client restriction under approved deny policy | DNS deny alone is monitor at 40, not a block | E2; E3 | Decide contract; prove client outcome in lab |
| Education: known VPN/proxy provider name controls | Lab operator, unassigned | Implemented, verification pending | C0 | Feed/YARA source review | Describe name-based matching accurately | Provider entries and domain-text patterns exist; not guaranteed blocking | E3 | Test apex/subdomains, score/action and client restriction |
| Education: VPN tunnel detection | Core engineer, unassigned | Not started | — | Metadata path review | Identify tunnels rather than provider names | No verified tunnel detector demonstrated | E3; E4 | Define support narrowly; additional protocol/flow evidence needed |
| Education: alternate DNS, DoH/DoT, direct IP and IPv6 bypass tests | Lab operator, unassigned | Blocked | — | Not run | Record actual outcome of each | Coverage limits below; no live blocked/detected/allowed result | E3 | Execute complete bypass matrix on isolated clients |
| Education: student/staff/guest/admin selection | Lab operator, unassigned | Implemented, verification pending | C0 | Four template-address assertions pass | Match actual lab map | Sample map works; actual lab map not available | E2 | Replace/verify real subnet map and routed tests |
| Education: legitimate learning and staff services | Lab operator, unassigned | Blocked | — | Not run | Learning, videos, searches and staff access work | No current acceptance evidence | E1; E4 | Record all four legitimate workflows |
| Education: reason for disabled Zeek and lost coverage | Product owner, unassigned | Blocked | C0 | Policy/docs review | Approved rationale and explicit unavailable features | `use_zeek_sni=false`; technical effects known, decision rationale not recorded in reviewed material | E3 | Record rationale; retain accurate coverage statement below |
| Architecture: local metadata, no required client agent or TLS decryption | Codex | Verified complete | C0 | Inspected collector/data paths | Preserve intended architecture | Current detection paths use local metadata/domain text | E3 | Recheck new sources; API semantics require server-side input |
| AI: synthetic training provenance | Codex | Verified complete | C0 model | Read bundled metadata | Report synthetic provenance accurately | 2,000 synthetic samples; embedded perfect metrics are synthetic-only | E2 | Obtain representative real validation sets |
| AI: bundled model load and fixture inference smoke test | Codex | Verified complete | C0 model | Actual bundled model, one fixture | Load and complete an inference | Loaded; inference counter 1; probability about 0.17906 | E2 | Repeat in package's pinned Linux environment; version warning recorded |
| AI: inference with correctly measured live features | Core engineer and lab operator, unassigned | Blocked | — | Not run with measured traffic | Credible features and observed inference | Current telemetry is invalid; fixture smoke test does not satisfy this | E2; E3 | Fix collection; disable unsupported inputs; validate compatible model/schema |
| AI: separate rules from model results | Codex | Verified complete | Audit uncommitted | Distinct control/test attribution | No rule result reported as model accuracy | 10 hard-gate helper passes reported separately from one model smoke pass | E2 | Correct any product/demo attribution that conflates them |
| AI: representative Financial/Education validation | Validation owner, unassigned | Not started | — | No representative dataset supplied | Edition-specific error and detection measurements | No real-world accuracy established | E2; E4 | Label benign/threat traces, holdouts and missing-telemetry cases |
| Service: dashboard root privileges | Service engineer, unassigned | Not started | — | Unit inspection | Review and reduce unnecessary privilege | Web unit still `User=root`; loopback TLS bind does not remove root privilege | E3 | Define service user and narrowly scoped privileged operations |
| Service: startup/readiness checks | Service engineer, unassigned | Not started | — | Unit and health handler inspection | Verify telemetry/decisions/enforcement health | Type=simple, static web `status: ok`; firewall init failure can return normally | E3 | Meaningful readiness and failure exit behavior; Linux tests |
| Service: logging, retention and disk behavior | Service engineer, unassigned | Implemented, verification pending | C0 | Log writers/units review | Useful logs with tested retention | Journal/JSONL logs exist; no tested rotation/retention here | E3 | Configure retention, measure disk growth and validate evidence attribution |
| Service: backup/restore and rollback | Lab operator, unassigned | Implemented, verification pending | C0 | Helper/document review | Restore consistent state and permitted traffic | Scripts/guidance exist; restore rehearsal absent | E3 | Quiesce DB writers; protect secrets; snapshot and network recovery test |
| Traceable corrective commits and rebuilt v2.2.10 packages | Core engineer, unassigned | Not started | — | Git/artifact audit | Corrective SHAs and matching release hashes | No corrective commits or v2.2.10 Debian packages found | E1 | Commit reviewed corrections; build and hash both editions separately |
| Consolidated 17:00 report and checkpoint submissions | Lead, unassigned | In progress | Audit uncommitted | This status audit | Baseline, noon, afternoon and evening evidence | Baseline/repository audit captured; later submissions not yet evidenced | E1–E4 | Append actual results/times; do not backfill success claims |

Licensing implementation is pre-existing local work and was not extended or made a Monday blocker. It must remain outside the correction scope unless a laboratory test demonstrates that it prevents testing.

## Reproduced defects and correction path

1. **Original tuples are replaced by replies (F1; E2, E3).** `collector_flow.py:370–405` overwrites each repeated `src`, `dst` and port field. The procfs TCP case returns `('192.0.2.80', '10.10.0.20', 52000, 'tcp')`, instead of client `10.10.0.20` → destination `192.0.2.80:443`. CLI lines beginning `tcp 6 ...` or `udp 17 ...` also use the wrong fixed protocol offset, returning `117`/`30` in the fixtures. `testing/test_conntrack_parser.py` explicitly asserts reply tuples and uses procfs-like prefixes in its CLI fixture. Fix both implementation and assertions; retain source port, directions and counters needed downstream.
2. **Collector limits are not nonblocking scheduling (F2; E3, static).** `main.py:554–586,666–668` calls `next()` synchronously. The DNS tail can wait without yielding, a quiet Zeek tail can wait before flows, and a flow iterator with no entries can wait before scoring. Up to three/five reads still block on the first unavailable item. Generator construction inside a `try` does not execute its later I/O. No successful quiet/missing/stopped collector acceptance test exists here. Schedule collectors independently and score available data on an independent cadence, with observable freshness and errors.
3. **Degraded mode skips decisions (F3; E2, E3).** The no-DNS engine probe supplies flow observations and uses a test-only frequency threshold of 1 to make the intended trigger unambiguous. After a processing iteration, evaluator calls and enforcement calls are both zero. `main.py:686–691` continues before `evaluate_hard_threat` at 747. `pump_flows()` only collects. The probe uses mocked state and a bounded stop; it does not prove live kernel behavior. No deployed threshold was changed.
4. **Snapshot-derived packet features are fabricated (F4; E3, static).** `main.py:550–552,579–583` assigns the 1,500-byte estimate to every repeated observation and increments flow frequency. `FlowStats.update()` treats each as a packet, accumulating bytes, poll-derived interarrival and bursts. The parser discards the real counters even when present. Add original/reply counter deltas, reset/expiry handling and observation identity. Packet arrival timing, per-packet size distribution and subsecond burst claims must be explicitly unavailable when the source cannot measure them. Do not tune thresholds around the error.
5. **Correlation spreads metadata across unrelated traffic (F5; E2, E3).** `FlowTracker.enrich_with_dns` labels all unlabeled flows for a client, and `enrich_with_sni` labels every flow for that client. The probe labels an unrelated destination and even a port-22 connection as `bank.example`. Flow keys omit source port; Zeek events discard connection endpoints/UID, and `last_sni` is keyed only by client. `_build_sector_flow`/AI choose the client's latest flow rather than a proven match to the DNS event. Preserve connection identity and use reliable DNS answer/connection metadata; query-only DNS does not identify the resolved destination.
6. **Financial policy selection and destination checks remain wrong (F6; E2, E3).** `segment_for_ip` takes the first matching segment, so broad internal `10.0.0.0/8` captures DMZ `10.10.0.0/24`. `main.py:729–734` resolves ASN and checks deny IPs using the client, not the destination. The sector builder does not provide destination ASN. Correct the source of each check and test a client whose destination is denied while the client is not.
7. **Education filtering has both matching and action gaps (F7; E2, E3).** School feed `*.4chan.org` matches `www.4chan.org` but not `4chan.org`. Bare-only provider entries likewise do not implicitly cover their subdomains. A denied domain contributes 40 points; in the sampled student and Financial internal configurations the resulting action is `monitor`, not `block`. That control includes the existing runtime sector adjustment. The configs describe thresholds as pre-adjusted, while `main.py:706–717` applies adjustments again; reconcile the intended threshold contract separately, without using it to conceal telemetry defects.
8. **Successful helpers and demo labels are insufficient (F8; E1–E4).** All 10 existing hard-gate helper tests pass, but they inject statistics directly and do not test collector scheduling or a forwarded client. The bundled model smoke pass uses a hand-built fixture. Older edition demo reports contain block JSON, screenshots and claims about zero false positives, tunnels prevented or PCI compliance; they are v2.2.0 sales/demo material, not v2.2.10 packet, accuracy or compliance evidence. Preserve them as historical demo material and withdraw unsupported current protection claims.

The call path (P1) is: conntrack snapshot → tuple parser (**F1/F4**) → synchronous `pump_flows` behind DNS/Zeek (**F2**) → client-wide metadata enrichment (**F5**) → no-DNS `continue` or DNS-triggered scoring (**F3/F6/F7**) → `ipset_add(client_ip)` → nft IPv4 source-forward drop (**F8: physical outcome unverified**). E3 supports every step; E2 reproduces tuple/correlation/selection/degraded failures. Correct collection and identity first, then scheduling/decisions, then prove the final kernel/client outcome.

## Financial input and acceptance inventory

This inventory covers every detection emitted by `sector_rules/financial_rules.py`, traced against `main.py:_build_sector_flow`. Rule unit inputs are not evidence that a live collector supplies them. The current sector call does not pass a custom Financial configuration; blocked/trusted ASN default sets are empty.

| Financial detection | Required inputs/config | What the live builder supplies | Current supported claim |
| --- | --- | --- | --- |
| High-risk country | `dst_country`; country list | No country | Disconnected |
| Blocked ASN | `dst_asn`; nonempty `blocked_asns` | Neither destination ASN nor custom blocked set | Disconnected |
| Unknown external ASN | `dst_asn`, `is_internal`, `known_vendor`; nonempty `trusted_asns` | None of these classifications/config inputs | Disconnected |
| Suspicious destination port | `dst_port`; suspicious-port set | Latest client flow's port, affected by reversed tuple/correlation | Rule exists; live correctness unverified |
| Large outbound transfer | `bytes_out`, `is_internal`; 50 MiB threshold | Estimated accumulated bytes; no internal-destination classification | Unreliable telemetry; no measured transfer claim |
| Very large outbound transfer | Same inputs; 200 MiB threshold | Same limitation | Unreliable telemetry; no measured block claim |
| Sensitive asset exfiltration risk | `asset_tag`, `bytes_out`, `is_internal`; sensitive tags | No asset tag; bytes unreliable | Disconnected asset rule |
| After-hours external activity | `hour`, `is_internal`, `bytes_out`; business hours | Host-local hour, estimated bytes; no `is_internal` | Can run, but internal traffic defaults to external; not validated |
| TLS fingerprint anomaly | `tls_used`, `ja3_risk_score`, `known_vendor`; optional `ja3` | TLS flag through broad enrichment; no JA3/risk/vendor data | Fingerprint branch disconnected |
| Missing SNI on external TLS | `tls_used`, `sni_present`, `known_vendor` | TLS/SNI booleans from broad enrichment | Partial path; no correct-connection or missing-SNI acceptance proof |
| Unknown API endpoint | `api_call`, `unknown_endpoint`; endpoint/method/status context | No API fields | Disconnected |
| API schema violation | `api_call`, `schema_violation`; endpoint/method | No API fields | Disconnected |
| API authentication failure burst | `api_call`, `auth_failure_burst`; source/endpoint/method | No API fields | Disconnected |
| Connection burst pattern | Actual connection count; default threshold 80 | DNS `burst_hit` boolean multiplied by 60 | Produces only 0 or 60; cannot reach default 80 |

`minimum_tls_version: 1.2` and `strict_tls` are configuration declarations. The Zeek event does not retain TLS version, and the decision path does not compare/enforce it. **TLS-version enforcement is unimplemented in the inspected path.** Education also cannot claim it through its disabled Zeek collector.

Country policy needs a local destination-geolocation source; asset rules need inventory/tag mapping; JA3 needs an actual fingerprint/risk source; API rules need application/API-gateway/server audit events. Encrypted API schema, authentication and endpoint semantics are not supplied by conntrack or DNS. These sources can be integrated without required client software or TLS decryption at this gateway, but no such integration has been demonstrated here.

Financial deny semantics remain a product decision: the current implementation is score-based, not an unconditional deny-domain block. A single deny contribution may allow or monitor depending on segment and other signals. Neither immediate blocking nor a scoring contract has been accepted by client tests. Legitimate login, payment/API, document downloads and authorized transfers all remain untested.

The intended enforcement scope needs explicit approval: the existing action adds the **client IPv4 address**, then drops packets from that source in the forward hook. It isolates that client's routed IPv4 traffic rather than blocking only the triggering destination/domain. It does not cover IPv6 or host-local INPUT/OUTPUT traffic. Existing block entries may remain while the process is stopped; expiry, unblock and restart behavior require actual observation.

## Education coverage and acceptance inventory

SafeSearch currently extends the domain allowlist; it does not force restricted search. The supplied DNS helper configures logging/upstream resolvers, not restricted-search aliases/answers. No actual resolver configuration or client restricted-search result was found. Mark SafeSearch **pending**, and preserve bare-domain/subdomain coverage when implementing resolver behavior.

The School policy explicitly disables Zeek SNI collection. **The reason for that choice is not documented in the reviewed policy or operational reference.** Do not invent a rationale. Consequently this edition receives no Zeek-fed SNI deny signal, TLS-presence/ALPN/certificate-chain heuristic or TLS-handshake enrichment from that collector. The handshake-time field is already a zero placeholder even when Zeek is enabled; JA3 is also a zero placeholder. DNS/flow metadata remains the intended input, subject to the shared defects above.

Known VPN/proxy provider names and YARA patterns in domain text are present. That supports only a narrow name/pattern-matching claim. It does not establish detection of arbitrary VPN tunnels, encrypted DNS, direct-IP tunnels or successful blocking before tunnel establishment. A `vpn_block_enforced` event flag is not client-side proof.

| Bypass case | Current coverage classification | Actual client test result |
| --- | --- | --- |
| Alternate DNS resolver | Outside current observed-resolver name coverage when queries bypass logging; no proven forced-resolver policy | Not run; cannot label blocked, detected or allowed |
| Encrypted DNS (DoH and DoT separately) | Encrypted query names outside current DNS collector coverage; provider-name matching is only partial metadata | Neither test run |
| Direct-IP access | Domain-only controls lack the name; flow controls would need the shared corrections and a relevant rule | Not run |
| IPv6 | Outside current IPv4 source-set enforcement coverage | Not run; no observed outcome claimed |

All four template segment selections pass offline: student `10.10.0.20`, staff `192.168.1.20`, guest `192.168.100.20`, administrator `10.0.0.20`. These addresses belong to the supplied example map; they are **not** the laboratory's actual assigned map. Approved learning platforms, video lessons, restricted searches and staff services require separate client workflows and recorded outcomes after the common fixes.

## Model and service evidence

The bundled model's SHA256 is `d1193ac54b75db30cc7b18bec0ea3ab3bba2302af348bcea4f5041073a2a37d9`. Its embedded metadata says `synthetic (generate_pretrained_model.py)`, 2,000 samples, 1,000 benign and 1,000 threat. Embedded accuracy/precision/recall/F1 of 1.0 describe that synthetic exercise only. They are not measured Financial or Education accuracy.

The actual bundled model loads and completes one fixture inference, probability approximately `0.1790596556890577`, with inference count 1. The review environment emits version warnings: serialized estimators identify scikit-learn 1.5.0 while this local `.venv` uses 1.9.1; `requirements.txt` pins 1.5.2. The smoke result establishes neither pinned-Linux compatibility nor classification quality. No representative measured feature vector or independent edition dataset was tested. Inference also calls the feature builder without a tracker, so the domain-repeat field is zero there even though flow export can populate it with a tracker.

The 10 passing hard-gate helper tests exercise rule behavior with manually injected statistics. YARA is pattern matching, not model inference. Rule-based gates, Financial rules and YARA outcomes must be recorded separately from MLP probabilities. Flow export's `ai_verdict` can include a hard-gate result, so that label alone is not proof of model detection.

Representative validation still needed includes anonymized, labeled Financial login/payment/API/download/transfer traces and Education learning/video/search/staff traces; benign high-volume events; approved VPN/remote-access use; controlled threat examples; IPv4/IPv6; and missing/quiet collector periods. Use separate holdouts and report false positives, false negatives, rates and time-to-decision with real packet outcomes. Do not reuse synthetic scores or old demo counts as this validation.

Both systemd units run as root. The web unit binds HTTPS on loopback but still executes the dashboard with root privileges. Units use `Type=simple` and `Restart=on-failure`; the inspected `/health/` handler returns constant `{"status":"ok"}`. Main-loop firewall initialization errors can log “FATAL” and return normally, so a startup message/HTTP 200 does not prove a ready firewall or a failure exit that triggers restart. Readiness must check actual collectors, progressing decisions and expected kernel rules.

Journal and JSONL logging exist. No tested rotation/retention or disk-growth evidence was established in this audit. Backup/restore helpers exist, but copy the database directly and contain secrets/TLS material; consistent backup needs writers quiesced and restricted archive handling. Existing guidance identifies missing license/installation-ID backup and separate DNS/routing preservation. No backup restore, traffic recovery, uninstall cleanup or rollback rehearsal was run. Use VM snapshots and verify the ruleset after recovery; do not equate service stop/package removal with restored network state.

## Evidence and exact reproduction commands

Run from the repository root using the existing `.venv`. The baseline script reads packages with `dpkg-deb`; it never installs them. `--save` writes only the corresponding local audit log. The probe command intentionally exits 1 while these requirement failures remain. Running it again overwrites that probe log, so preserve a copy when comparing a later corrective commit.

```bash
git remote get-url origin
git branch --show-current
git rev-parse HEAD
git status --short
git diff --stat
git diff HEAD -- app/minifw_ai/main.py app/minifw_ai/collector_flow.py app/minifw_ai/enforce.py config/modes/minifw_financial/policy.json config/modes/minifw_school/policy.json testing/test_conntrack_parser.py
.venv/bin/python docs/evidence/2026-11-02-readiness/baseline.py --save
.venv/bin/python docs/evidence/2026-11-02-readiness/probes.py --save
.venv/bin/python -m pytest --version
trail check
```

The pytest version command failed with `No module named pytest`; a full pytest run was not performed. No dependency install was used to conceal that limit. The independent `unittest` runner reuses `testing.test_baseline_hard_gates` and adds requirement probes without requiring pytest.

`trail check` also exited 1 with six learning conflicts in `.github/workflows/release.yml:40,47` and `README.md:37,61`. Its diagnostics are preserved in [trail-check.log](evidence/2026-11-02-readiness/trail-check.log). A scoped Git diff confirms that the workflow is unchanged at C0 and the only pre-existing README working-tree addition is a licensing-document link near line 534. The flagged installer line already uses the documented curl-to-sudo-bash pipe, and the other flags match existing build/manual-install wording against older host/packaging learnings. These observations explain why this audit did not change those lines; **the check still failed**, and no commit or PR was created. The next commit/PR must address or explicitly explain the conflicts and rerun the check.

Audit validation also checked both scripts' Python syntax, resolved every report file link, verified all 39 matrix rows against the requested columns/status vocabulary, confirmed the inspected product files remain unchanged, and recalculated the evidence-file checksums. These are report-integrity checks, separate from the failed product probes and unrun Linux acceptance tests.

Sanitized result excerpts (addresses/domains are fixtures):

```text
MANIFEST_HASHES 200 ARCHIVE_MISMATCHES []
CURRENT_REPO_COMPARISONS 198 MISMATCHES []
INSTALLED_PAYLOAD_HASHES 196 MISMATCHES []
DEGRADED_NO_DNS evaluation_calls 0 enforcement_calls 0
EDUCATION_BARE_SUBDOMAIN [False, True]
FINANCIAL_DMZ internal
DENY_DOMAIN_SCORE_ONLY minifw_school (40, ['dns_denied_domain'], 'monitor')
DENY_DOMAIN_SCORE_ONLY minifw_financial (40, ['dns_denied_domain'], 'monitor')
AUDIT_TOTAL 22 FAILURES 9 ERRORS 0 SKIPPED 0
```

The 9 failures are four tuple/parser cases, degraded evaluation, DNS correlation, SNI correlation, Financial DMZ precedence and Education bare-domain coverage. The 13 passes are 10 existing hard-gate helpers, template Education segment selection, current score-only behavior and bundled-model fixture inference. Those pass counts are not an acceptance percentage.

| Evidence ID | Source and observation | Reproduction / fixity |
| --- | --- | --- |
| E1 | [baseline.py](evidence/2026-11-02-readiness/baseline.py), [baseline.log](evidence/2026-11-02-readiness/baseline.log): 08:59 WIB workstation identity, source and artifact checks | Baseline command above; archive/payload hashes in log; audit-file hashes in evidence `SHA256SUMS` |
| E2 | [probes.py](evidence/2026-11-02-readiness/probes.py), [probes.log](evidence/2026-11-02-readiness/probes.log): failures and successful controls, local timestamps around 09:01 WIB | Probe command above; raw failure tracebacks retained; no physical network traffic generated |
| E3 | [main.py](../app/minifw_ai/main.py), [collector_flow.py](../app/minifw_ai/collector_flow.py), [collector_dnsmasq.py](../app/minifw_ai/collector_dnsmasq.py), [collector_zeek.py](../app/minifw_ai/collector_zeek.py), [enforce.py](../app/minifw_ai/enforce.py), sector configs/rules, systemd units and operational helpers | Named symbols/line spans in findings; compare at C0 and run the scoped Git diff above; static findings are explicitly distinguished from client tests |
| E4 | [Financial demo report](demo-evidence/financial/report/evidence-report.md), [Education demo report](demo-evidence/education/report/evidence-report.md), [technical reference](technical-reference.md) | Read version/scenario and source-limit statements; v2.2.0 demo material and documentation are not current edition acceptance |

Evidence → finding → call-path references are in F1–F8 and P1 above. This is a readiness review (no malware/vendor flavor, no attack on an external target).

**Before/after nftables evidence: absent.** No native nftables command was executed on this Mac, and no Linux test results were supplied. No fabricated nft listing or connection-failure/recovery log is included. The later isolated-lab acceptance record must contain the edition/package SHA, selected client/destination, actual `sudo nft -a list table inet minifw` snapshots before/blocked/recovered, set/rule observations, exact client connection commands and outcomes, and DNS/Zeek/flow freshness throughout. Test new and existing forwarded connections, expiry/manual unblock, repeated triggers, service restart and reboot independently.

## Continuation and checkpoint plan

1. **First: correct the common input/decision path.** Use an isolated development branch/snapshot of C0 plus the explicitly recorded local files. Preserve original/reply identities and counters; replace reverse-tuple assertions; establish independent collector scheduling; run flow decisions without DNS; then correct correlation and destination checks. Test counter resets, unchanged snapshots, quiet/missing/stopped collectors and source failures. Unsupported timing features must be disabled, not assigned invented values.
2. **Next: establish two isolated Linux gateways or clean snapshots.** Record actual OS/kernel, interfaces, routes/NAT, snapshot IDs, time zone, clients and controlled destination servers. Both packages are named `minifw-ai`; install/test one edition per environment. Assign one core owner and one lab owner before relying on parallel work; none is assigned by this report.
3. **Then: prove enforcement and recovery.** Capture the decision and selected address, kernel membership and a real failed forwarded connection. Unblock/expire it and show recovery; repeat decisions and restart/reboot. Do this before expanding optional sector features.
4. **Edition acceptance follows shared-core correctness.** Financial: fix overlap, approve deny-domain semantics, withdraw disconnected/TLS claims and exercise all legitimate workflows. Education: approve deny behavior, fix apex/subdomain coverage, mark SafeSearch pending unless actual resolver tests pass, document disabled Zeek rationale and run bypass/legitimate-learning matrices. Keep local metadata processing; document every additional source required.
5. **Rebuild only a traceable corrected snapshot.** Record corrective commits and remaining local changes, build both v2.2.10 packages separately, recalculate installer/package hashes, and repeat acceptance against those exact files. Packaging checks remain a separate result.

At 12:00 WIB report parser results, collector progress and blockers; at 15:00 provide shared-core outcomes and separate edition findings. At 17:00 update the single matrix with actual commits, commands, pass/fail evidence and unfinished work. If the core consumes the day, deliver credible shared-core evidence and an explicit edition backlog. These are planned submissions, not claims that those checkpoints have already been completed.

No defensible 100-point acceptance score is assigned here. Parsing/telemetry, independent/degraded collection and live enforcement/recovery do not meet their evidence gates; Financial and Education have no current client acceptance results. Provenance and this report are partial deliverables, not a production-readiness determination.
