# MiniFWAI v2.2.10 — shared corrections and separate lab acceptance

Record updated **2 November 2026, 11:10 WIB**. Both corrected editions passed controlled routed enforcement and recovery tests in separate QEMU VMs. **Neither edition is declared production-ready.** The full Debian regression run passed **546 tests**; the routed acceptance driver completed **22 Financial and 23 Education assertions/records**, including a final scope record, not 45 independent security protections. The user-requested fictional sandbox supplies actual TLS login, API, payment, transfer, document, lesson, search, video and staff workflows. Real institutions, external learning platforms and browser playback remain unverified.

The [08:59 baseline and original audit](2026-11-02_readiness-minifwai-report.md) remain an immutable account of the earlier state: 13 passing controls and 9 failed requirement probes. This report supersedes its current-status conclusions. It is an interim consolidated submission in the requested evening-report format; it does not claim that 12:00, 15:00 or 17:00 submissions have already occurred.

## Provenance, allocation and isolation

Repository: `https://github.com/vadhh/minifw-ai`. Starting branch `main`, independently checked starting commit **e6b62a9df65261bba2cfc10618af7d552f016817** (C0). Working branch: `fix/monday-core-20261102`.

The baseline recorded seven pre-existing modified files: `README.md`, `app/web/routers/admin.py`, `app/web/templates/admin/partials/sidebar.html`, `build_usb.sh`, `pyproject.toml`, `requirements.txt`, `scripts/build_deb.sh`, plus untracked licensing, assessment and tool files. Those user changes were preserved and excluded from corrective commits. Packaging includes eight explicitly declared existing local files/changes, including licensing and requirements, as listed in each source manifest; licensing was not extended for this task. Thus the packages are a recorded commit **plus declared local packaging/licensing changes**, not a clean signed release.

| ID | Exact commit | Change |
| --- | --- | --- |
| C0 | `e6b62a9df65261bba2cfc10618af7d552f016817` | Independently checked baseline |
| C1 | `1c9f91592fa256a674661773e4080f97890cff66` | Parser, measured deltas, independent readers, DNS-free evaluation, correlation, destination checks, immediate deny isolation and claim corrections |
| C2 | `cf39cf7b48439a1641846326a823dc4263a87834` | One collection timestamp per conntrack snapshot |
| C3 | `2bae0856c99b0789f7f2848d460999bc83a3a1c4` | Activate kernel tracking hooks/accounting; collision-free IPv6 connection identity; accurate model log wording |
| C4 | `f090e799061191adbc6daf565730952f6b9c20de` | Fictional sandbox, regression tests and VM-guarded routed acceptance driver |

**Owner/allocation:** Codex performed implementation, testing and reporting. No second engineer or subagent assisted. The user approved immediate client IPv4 isolation on a confirmed deny-domain match and creation of local acceptance targets.

The authorized host `100.64.135.126` was used only to create/run isolated QEMU guests and read host preservation state. No package was installed on its existing operational MiniFW services, ARCHANGEL systems or client networks. Its existing web service was observed `activating` during a read-only check; it was left untouched. The existing host engine remained PID 1672, active since 30 October. [Host preservation evidence](evidence/2026-11-02-lab/host-preservation.log) verifies both immutable backing images still match their original SHA256.

| Laboratory property | Financial | Education |
| --- | --- | --- |
| VM hostname | `minifw-monday-financial` | `minifw-monday-education` |
| Overlay | `/home/sydeco/vms/minifw-monday-20261102/financial/disk.qcow2` | `/home/sydeco/vms/minifw-monday-20261102/education/disk.qcow2` |
| OS/kernel | Debian 12 amd64; `6.1.0-54-cloud-amd64` | Same, separately booted |
| Runtime | Python 3.11.2, nftables 1.0.6, conntrack 1.4.7, dnsmasq 2.90 | Same |
| Management | QEMU user networking; guest `10.231.0.15`; host loopback SSH `23211` | Separate user network; guest `10.231.0.15`; loopback SSH `23210` |
| Packages | Only `minifw-ai 2.2.10-finance` | Only `minifw-ai 2.2.10-education` after inherited package purge |

Backing chain: the stopped `minifw-v2210-installer-test/minifw-v2210.qcow2` over `minifw-v229-installer-test/debian-12-genericcloud-amd64.qcow2`; hashes are in the host evidence. The guests started from an older Financial image, then underwent separate purge/reinstall with fresh configuration/database and retained dependency caches. These are isolated overlays, **not pristine operating-system installations**. Their initial states are recorded in [Financial baseline](evidence/2026-11-02-lab/baseline-financial.log) and [Education baseline](evidence/2026-11-02-lab/baseline-education.log), captured around **09:51 WIB**. The Linux laboratory therefore missed the 09:00 checkpoint even though workstation provenance was recorded at 08:59.

Each guest created its own routed test path:

```text
mf-client namespace                  VM gateway/root                  mf-server namespace
10.10.0.20/24   ---- veth ---- 10.10.0.1 | 198.18.0.1 ---- veth ---- 198.18.0.2/24
fd42:10::20/64                fd42:10::1 | fd42:18::1                fd42:18::2/64
                              nft inet minifw forward
```

Gateway DNS `10.10.0.1`; alternate resolver `198.18.0.2`; local TLS `443`, HTTP `8080`, DoT `853`, controlled scan listeners `20000–20014`. No host bridge connects this path to a client LAN. Management is separate. Education source aliases are staff `192.168.1.20`, guest `192.168.100.20`, administrator `10.0.0.20`; primary client is student. Financial aliases are internal `192.168.1.20`, guest `192.168.100.20`, trading `10.50.0.20`; primary client is DMZ. These addresses were actually assigned and routed in the VM; this verifies IP-based policy selection, **not VLAN isolation**.

All scoring thresholds and weights were retained. Only the lab block timeout changed from shipping **86,400 seconds to 15 seconds** to exercise expiry. AI was explicitly disabled in routed acceptance to prove rule-based operation independently. Both lab services and fixture namespaces were stopped/removed after testing; the QEMU overlays remain available. Test TLS private keys and installer secrets were excluded from exported evidence.

## Consolidated requirement matrix

`U` = [546-test Debian log](evidence/2026-11-02-lab/education/minifw-expanded-tests.log) and [JUnit XML](evidence/2026-11-02-lab/education/minifw-expanded-results.xml). `F` = [Financial routed commands/results](evidence/2026-11-02-lab/financial/minifw-acceptance.log). `E` = [Education routed commands/results](evidence/2026-11-02-lab/education/minifw-acceptance.log). `A` = [artifact verification](evidence/2026-11-02-lab/artifact-verification.log). These are evidence references, not implied verification of untested features. “Verified complete” applies only to each row's explicit scope.

| Requirement | Owner | Status | Commit | Test | Expected result | Actual result | Evidence | Remaining work |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Repository, branch, starting commit and dirty tree | Codex | Verified complete | C0 | Git and independent source comparison | Manifest agrees with actual repository | Exact C0 checked; original seven tracked changes preserved | Original baseline; A | Preserve declared local changes with any release |
| Supplied and rebuilt artifact SHA256 | Codex | Verified complete | C0/C3 | ZIP, manifest and Debian payload verification | Identify exact tested inputs | Original hashes retained; corrected hashes below; eight core files match C3 | Original baseline; A | Publisher signing/release process |
| Separate isolated lab and task allocation | Codex | Verified complete | C4 | Two VM overlays and actual routes | Separate package environments, actual client addresses | Both VMs recorded; one owner; lab ready after 09:00 | Baselines; F; E; host evidence | Pristine install matrix still unverified |
| Original/reply tuple parsing, procfs/CLI TCP/UDP | Codex | Verified complete | C1/C2 | Parser fixtures with both directions; actual CLI | Preserve original client, destination, source/destination ports | Four format/protocol combinations pass; live original tuple verified | U; F; E | Additional NAT/large-scale field captures |
| Independent collectors | Codex | Verified complete | C1 | Nine quiet/missing/stopped reader cases; live quiet/missing sources | One source cannot block decisions from another | Tests pass; DNS decisions in about 0.29–0.33 seconds with quiet/missing flows | U; F; E | Load/backpressure and long-duration validation |
| Flow decisions without DNS | Codex | Verified complete | C1/C3 | Actual 15-port connections with DNS disabled or missing | Flow rule selects client and enforces | Both editions select `10.10.0.20`, reason `port_scan`, forwarded connection times out | F; E | More representative threats, loss and outage durations |
| Credible counters/deltas and disabled timing features | Codex | Verified complete | C1/C2/C3 | Actual kernel snapshots; repeated observations; resets/partial counters | Measured deltas, zero increments for unchanged snapshots | 16 packets, 416 outgoing and 8,608 incoming bytes over measured interval; 20 identical snapshots add zero; no timing fabricated | U; F; E | Packet-level source for timing/distributions; first snapshot is a baseline |
| Correct DNS/SNI-to-connection correlation | Codex | Implemented, verification pending | C1/C3 | Exact tuple/source-port regression | Unrelated flows remain unlabeled | Unit tests pass; DNS query-only logs intentionally do not assign a destination flow | U | Live Zeek capture and DNS-answer mapping not supplied |
| Selected IP, nft entry and actual failed forwarding | Codex | Verified complete | C1/C3 | Domain and flow triggers; client HTTP; nft counters | Selected client appears in set and loses forwarding | Same client in events/set; real timeouts and increasing drop counters | F; E; per-run nft files | Existing long-lived session and throughput stress tests |
| Unblock, expiry, duplicate events and service restart | Codex | Verified complete | C1/C3/C4 | Repeat deny; restart; expire; delete entry | No duplicate block/refresh; restart retains block; recovery works | Both editions pass, HTTP 200 after expiry/manual unblock | F; E | Dashboard unblock workflow and long timeout tests |
| Full VM reboot behavior documented | Codex | Verified complete | C0/C3 | One-hour block before kernel reboot | Document actual persistence | Block disappears after reboot; engine recreates empty set/rules | Before/after reboot logs below | Persistent block restoration is unimplemented; decide policy before release |
| Financial DMZ subnet precedence | Codex | Verified complete | C1 | Longest-prefix test; routed DMZ DNS event | `10.10.0.20` selects DMZ before broad internal subnet | DMZ, trading, internal and guest selections pass | U; F | Deployment-specific subnet review |
| Financial complete rule-input inventory | Codex | Verified complete | C1/C3 | Trace builder into all Financial detectors | State supplied and missing inputs precisely | Fourteen outputs inventoried below; disconnected rules explicit | Source; inventory below | Integrate sources only with acceptance evidence |
| Financial destination IP/ASN, not client | Codex | Implemented, verification pending | C1 | Main-loop destination-IP and destination-ASN regression | Lookup/check destination; isolate client on resulting action | Unit test confirms destination ASN lookup; blocked-ASN path enforces; destination-IP adds configured score | U | Live ASN database/feed-target acceptance not run |
| Financial TLS-version enforcement | Codex | Not started | C1 claim correction | Source trace | Enforce only if implemented/proven | Marked unimplemented; no TLS-version comparison | Policy/source | Reliable TLS-version metadata and rule enforcement tests |
| Financial country, asset, JA3 and API claims | Codex | Verified complete | C1/documentation | Rule-input trace | Disconnected helpers not described as live protection | Required inputs absent; no active claim in this report | Inventory below | Data sources and end-to-end rule tests |
| Financial approved deny-domain isolation | Codex | Verified complete | C1 | Bare/subdomain DNS matches and client test | Immediate client forwarded IPv4 isolation | Score 100 isolation contract; kernel entry and timeout observed | U; F | Operational allow/deny governance |
| Financial legitimate workflows in created sandbox | Codex | Verified complete | C4 | TLS login/account API/payment/transfer/CSV | Authorized fictional workflows work; unauthorized operations rejected | Payment 1,250; transfer 2,500 credits; balances correct; overdraft rejected; document downloaded | U; F | Real bank/payment/API provider workflows unverified |
| Financial enforcement scope and IPv6 limitations | Codex | Verified complete | C1 | Rule and IPv6-during-block test | State actual scope | Client-source forwarded IPv4 isolation; IPv6 still succeeds | F; E | IPv6/host INPUT/OUTPUT policy outside coverage |
| Education SafeSearch | Codex | Not started | C1 claim correction | Resolver/configuration review | Actual restricted resolver answers or explicit pending status | Pending; allowlisting does not force restricted search | Policy; original audit | Resolver overrides, resolver-bypass controls, real search evidence |
| Education bare domains and subdomains | Codex | Verified complete | C1 | `4chan.org` and `www.4chan.org`; suffix-confusion tests | Both legitimate pattern forms match without unrelated suffix matches | Both cause real isolation; case/trailing-dot controls pass | U; E | Broader feed validation |
| Education deny-list client restriction | Codex | Verified complete | C1 | Deny DNS → event → nft → client connection | Actual restriction, not only dashboard/score | Immediate isolation and connection timeout | E | Operational exceptions/allowlist review |
| Education known VPN/provider-domain control | Codex | Verified complete | C1 | `nordvpn.com` DNS match and forwarded HTTP | Precisely test known-name restriction | Client forwarding blocked; no tunnel claim | E | Provider-feed quality and legitimate remote-access exceptions |
| Education arbitrary VPN tunnel detection | Codex | Not started | — | No tunnel detector acceptance | Do not confuse domains with tunnels | Unsupported/unverified | Source and scope below | Protocol/flow sensor, labeled tunnel validation |
| Education alternate DNS, DoH, DoT, direct IP, IPv6 | Codex | Verified complete | C4 | Five actual client cases | Record blocked/detected/allowed separately | All five allowed in controlled tests; name-based coverage bypassed | E; bypass table below | Controls for these bypasses remain unimplemented |
| Education student/staff/guest/admin selection | Codex | Verified complete | C1/C4 | Actual assigned aliases and recorded DNS events | Select four supplied policy segments | All four selected correctly | E | VLAN/physical segmentation and deployment map acceptance |
| Education legitimate learning/staff sandbox | Codex | Verified complete | C4 | Lesson, search, VP8 video/range, staff role/service | Approved sandbox remains usable | All pass; student denied staff service, staff allowed | U; E | External platforms, browser playback, sustained video unverified |
| Education disabled Zeek and missing protections | Codex | In progress | C1 | Supplied policy and installer review | Explain technical effect and historical rationale accurately | Policy disables SNI; installer does not provision Zeek; no historical product decision record found | Policy/source | Product owner rationale and actual sensor provisioning |
| Local metadata architecture, no TLS decryption/client agent | Codex | Verified complete | C1/C4 | Product path and lab routing review | Preserve architecture | Gateway uses local DNS/conntrack/optional Zeek metadata; test TLS terminates at fictional destination | Source; F; E | Country/asset/API/JA3 inputs need other local sources |
| AI synthetic provenance | Codex | Verified complete | C3 | Model metadata; logging wording | Do not call synthetic metrics real-world accuracy | 2,000 synthetic records, 1,000 per class; log states training provenance | Original probe; U; source | Representative validation data |
| AI model load and fixture inference | Codex | Verified complete | C0/C3 | Actual model load in Debian regression | Load and execute fixture inference | Pass; sklearn 1.5.0→1.5.2 serialization warnings retained | U | Version-matched export/revalidation |
| AI inference using measured live features | Codex | Blocked | C1/C3 | Feature availability gate | Never infer from invented packet timing/size distributions | 24-feature MLP disabled for conntrack observations; no live model-accuracy claim | U; F; E | Compatible measured schema/model or packet-level metadata source |
| Separate rule-based and model results | Codex | Verified complete | C1/C3 | Attribution regressions and AI-disabled packet tests | Rule successes not called model detections | Flow block owner Hard Gate; model status unsupported/not_run | U; F; E | Live eligible-model acceptance still pending |
| Representative Financial/Education validation data | Codex | Not started | — | No representative labeled dataset | Independent sector accuracy/false-positive measurements | None established; fictional sandbox is functional acceptance only | Scope below | Labeled real metadata, holdouts and privacy review |
| Dashboard root privilege review | Codex | In progress | C0 | systemd unit review | Record and reduce unnecessary root | Dashboard still runs as root; reviewed, not hardened | Units/source | Service account and narrow privileged-operation boundary |
| Startup and readiness | Codex | Implemented, verification pending | C1/C3 | nft startup and reboot tests; health-source review | Fail initialization correctly and verify collection/decisions | nft failures now exit 1; hooks/counters initialize; web health remains static | U; reboot logs | Meaningful health/readiness, negative startup faults and alerts |
| Logging/retention/disk behavior | Codex | Implemented, verification pending | C0/C1 | Actual journal, event, audit exports | Useful attributed logs with bounded retention | Decision attribution and sanitized evidence verified; retention/disk growth not tested | F; E | Rotation, disk-full and long-run duplicate/log-volume tests |
| Backup, restore and rollback | Codex | Implemented, verification pending | C0 | Helper/source review; overlay preservation | Consistent backup and demonstrated restore | Isolated overlays and unchanged backing images; backup restore not rehearsed | Host evidence; scripts | Quiesce DB writers, protect secret archive, restore/traffic recovery rehearsal |
| Traceable commits and separate rebuilt packages | Codex | Verified complete | C1–C4 | Independent repository/manifest/package comparison | Actual tested package maps to corrective source | C3 core matches both payloads, root ownership verified, exact hashes below | A; install logs | Release provenance/signatures and clean-install matrix |
| Consolidated report and checkpoints | Codex | In progress | C1–C4; report commit | This matrix and timestamped evidence | Complete candid current record; actual checkpoint submissions | Baseline 08:59, lab 09:51, routed acceptance 11:04–11:05; later checkpoints not yet due | All linked evidence | Update at 12:00/15:00/17:00 if work continues; no retroactive success timestamps |

## Financial rule-input inventory

The live sector builder now receives **the exact evaluated connection**, measured byte deltas since its initial baseline, actual newly observed connection counts, local hour, destination ASN when a local database is loaded, and destination membership in the configured site subnets. `blocked_asns` is supplied from the deny-ASN feed. A counter snapshot's initial totals are deliberately not counted as newly observed traffic. Short connections between five-second polls and transfers before the first snapshot can be missed; these volume rules are not complete exfiltration prevention.

| Financial detection | Required inputs/config | Live supply and acceptance limit |
| --- | --- | --- |
| High-risk country | `dst_country`, country list | No geolocation input; disconnected |
| Blocked ASN | `dst_asn`, `blocked_asns` | Destination lookup and feed connected; engine regression passes; live ASN data test pending |
| Unknown external ASN | `dst_asn`, `is_internal`, `known_vendor`, nonempty `trusted_asns` | Destination/internal inputs connected; trusted-ASN/vendor configuration absent; disconnected as delivered |
| Suspicious port | `dst_port`, configured port set | Exact connection port supplied; helpers tested; no dedicated packet acceptance per configured port |
| Large transfer | `bytes_out`, `is_internal`, 50 MiB | Measured outgoing deltas when accounting exists; no 50 MiB acceptance run |
| Very large transfer | Same, 200 MiB | Same; no 200 MiB block acceptance run |
| Sensitive asset exfiltration | `asset_tag`, `bytes_out`, `is_internal`, sensitive tags | No inventory/tag source; disconnected |
| After-hours activity | Local `hour`, `is_internal`, `bytes_out`, business hours | Inputs supplied; guests set Asia/Jakarta; actual after-hours acceptance unrun |
| TLS fingerprint anomaly | `tls_used`, `ja3_risk_score`, `known_vendor`, optional `ja3` | No fingerprint/risk/vendor source; disconnected |
| Missing SNI | `tls_used`, `sni_present`, `known_vendor` | Exact Zeek tuple enrichment implemented; sensor absent in these VMs; no live claim |
| Unknown API endpoint | `api_call`, `unknown_endpoint`, endpoint/method/status | No API audit source; disconnected |
| API schema violation | `api_call`, `schema_violation`, endpoint/method | No API audit source; disconnected |
| API auth-failure burst | `api_call`, `auth_failure_burst`, endpoint/source/method | No API audit source; disconnected |
| Connection burst | `burst_conn_count`, threshold 80 | New observed connections, not repeated polls/DNS boolean; helper/engine controls pass; 80-connection acceptance unrun |

Destination-IP denial keeps its existing score contribution; it is **not** claimed to block independently. Financial ASN sector rules can block through their rule decision. Neither was compensated with changed thresholds. `minimum_tls_version`/`strict_tls` declarations do not implement version enforcement and are marked unimplemented.

Additional sources needed: local destination-geolocation data, asset inventory, TLS fingerprint/risk metadata, and server/API-gateway audit events for encrypted API semantics. The fictional sandbox's application-level tests prove usability, not that MiniFW inspects encrypted account balances, payload schemas or login failures.

## Education coverage and sandbox acceptance

`use_zeek_sni=false` is supplied in the Education policy. The kit does not provision a functioning Zeek sensor; disabling its reader avoids presenting an absent data source as protection. The historical business/design reason was not supplied and is not invented here. Without that source, SNI deny matching, missing-SNI/TLS handshake, ALPN and certificate metadata are unavailable from Education live telemetry. Even a configured sensor would require correct placement, supported fields and acceptance tests; conntrack cannot replace those fields.

SafeSearch remains **pending**: no restricted-search resolver configuration or real restricted-result test was supplied or created. The sandbox's search endpoint only proves a legitimate lesson search succeeds. Known provider-domain matching is tested; arbitrary VPN tunnels are not detected by that result.

| Actual bypass test | Financial | Education | Meaning |
| --- | --- | --- | --- |
| Denied name queried through alternate local DNS | Allowed | Allowed | Query bypasses gateway DNS logging |
| DoH query over actual TLS | Allowed | Allowed | Encrypted queried name unavailable to DNS collector |
| DoT query over actual TLS | Allowed | Allowed | Same limitation; TLS 1.3 transport observed |
| Direct-IP HTTP to test server | Allowed | Allowed | No name to match; no independently triggered flow rule |
| IPv6 HTTP | Allowed | Allowed | IPv4 block set cannot enforce it |
| IPv6 HTTP while client IPv4 isolated | Allowed | Allowed | Confirms the isolation boundary rather than assuming dual-stack enforcement |

The sandbox uses fictional accounts and integer credits. Both editions passed unauthorized API rejection, invalid-login rejection, authenticated account access, 1,250-credit payment, 2,500-credit transfer, overdraft/negative rejection, correct resulting balances, CSV document download, lesson/search, student denial of the staff service, authorized staff service access, and a 14,723-byte VP8 WebM download plus HTTP 206 range. Download SHA256 `836f294b179103aa3d90ee58618435ce91e019c9a767b5994752d8eff947aacd` matches the generated fixture. No real money, external institution or learning-provider endpoint was contacted for these workflows. Media transport is verified; actual browser decoding/playback and long video sessions are unverified.

The architecture remains local metadata processing without gateway TLS decryption or mandatory client agent changes. TLS termination in the fictional **destination server** is ordinary application operation. Python test clients are lab fixtures, not a product deployment requirement.

## Enforcement, failures and service limits

The action approved by the user isolates **all of the selected client's forwarded IPv4 source traffic**, not just the denied destination/domain. It does not affect host-local INPUT/OUTPUT, force DNS restrictions, or enforce IPv6.

Representative actual Education snapshots from the successful run:

```text
# DNS block, client 10.10.0.20; subsequent forwarded HTTP times out
elements = { 10.10.0.20 timeout 15s expires 14s... }
ip saddr @minifw_block_v4 counter ... drop comment "MiniFW-AI-Blocklist"
# After expiry: no elements; subsequent forwarded HTTP returns 200
# Manual delete also restores HTTP 200
```

Exact unabridged before/blocked/recovered snapshots: [Education successful run](evidence/2026-11-02-lab/education/runs/minifw-monday-education-20261102T040407Z/results.json) with sibling `*.nft` files; [Financial successful run](evidence/2026-11-02-lab/financial/runs/minifw-monday-financial-20261102T040406Z/results.json) with sibling snapshots. The command logs contain each actual nft listing and client outcome. Repeated deny queries added zero duplicate block events and did not refresh expiry. Service restart retained an active kernel entry and still failed the forwarded connection.

Full guest reboot is different: a manually inserted one-hour client entry was present before boot, then absent after boot while the engine recreated an empty set/rules. [Education before](evidence/2026-11-02-lab/education/reboot-before.log), [after](evidence/2026-11-02-lab/education/reboot-after.log); [Financial before](evidence/2026-11-02-lab/financial/reboot-before.log), [after](evidence/2026-11-02-lab/financial/reboot-after.log). Different boot IDs verify a kernel reboot. Persistent block restoration is unimplemented. Existing-session interruption and GUI-driven unblock have not been accepted.

Failed results are retained and do not count as passes:

| Failure | Evidence | Resolution/current limit |
| --- | --- | --- |
| Original requirement probes: nine failures | Original audit/probes | C1–C3 target the named defects; original logs preserved |
| Initial expanded pytest collection lacked staged helpers/cryptography | [Initial collection log](evidence/2026-11-02-lab/unit-expanded-initial.log) | Complete source and existing requirements installed only in VM; final 546 pass |
| Decision-owner compatibility assertion failed | [Failed attribution regression](evidence/2026-11-02-lab/education/minifw-expanded-attribution-failed.log) | C1 supports actual numeric MLP reasons and legacy generic reason; final U passes |
| First acceptance driver could not parse empty namespace listing | [Driver failure](evidence/2026-11-02-lab/education/minifw-acceptance-driver-initial-failed.log) | Empty output handled as no namespaces |
| C2 routed HTTPS worked but kernel collection was empty | [No-tracking failure](evidence/2026-11-02-lab/education/minifw-acceptance-no-tracking-failed.log), [kernel probe](evidence/2026-11-02-lab/education/minifw-conntrack-hook-probe.log) | C3 activates tracking hooks and accounting; modprobe/startup alone was insufficient |
| Second scan case timed out after fixture retained half-open sockets | [Education failed run](evidence/2026-11-02-lab/education/minifw-acceptance-flow-scan-failed.log), [Financial failed run](evidence/2026-11-02-lab/financial/minifw-acceptance-flow-scan-failed.log) | C4 closes accepted sockets and waits for closure; late reply packets had become new kernel-original tuples after state deletion; successful rerun retained |
| Immediate rerun encountered lingering `mfsg` veth | [Education cleanup failure](evidence/2026-11-02-lab/education/minifw-acceptance-stale-veth-failed.log) | Explicit cleanup of owned interfaces; final runs exit zero |
| First reboot before-log stored under volatile `/tmp` | Execution record; no surviving before-log claimed | Repeated with `/var/tmp`; only the preserved paired evidence above supports persistence result |
| Old manual integration helpers fail Python parsing | `testing/integration_real_traffic.py:63`, `testing/integration_standalone.py:104` | Pre-existing, outside pytest's collected tests; remain broken/unverified |
| Final `trail check` reports 20 conflicts and a 400 KB checking cap | [Check log](evidence/2026-11-02-lab/trail-check-final.log) | Phrase-based conflicts explained in commit messages; check is not claimed to pass or cover the entire evidence diff |

Counter collection preserves the kernel's actual original tuple; clearing conntrack while live sockets remain can cause a late packet to become a new connection in the opposite direction. The test fixture now closes both endpoints before resetting state. Midstream restart/state-loss and client-direction classification deserve further validation; parsing must not invent a reversed tuple to hide this effect.

The dashboard still runs as root. Web `/health/` remains a static response and does not certify progressing telemetry, decisions or enforcement. Firewall initialization now fails nonzero and creates the required tracking hooks/accounting, but comprehensive negative startup/readiness tests remain pending. Logs include actual event/audit/journal evidence; retention, disk-full behavior and prolonged load are unverified. Backup helpers still need a quiesced database backup, protected secret archive, restoration and traffic-recovery rehearsal. Keeping QEMU overlays and unchanged parent images is a rollback aid, not evidence that the product backup/restore scripts work.

Authored code/document whitespace checks pass when raw command logs are excluded. Raw logs retain their original trailing spaces and blank lines; the unscoped Git whitespace check flags those bytes, which were preserved as evidence rather than rewritten.

## AI evidence and remaining validation

The shared model identifies its data as **synthetic**: 2,000 records, 1,000 benign and 1,000 threat. Embedded perfect training metrics are not real-world Financial/Education accuracy. The Debian suite demonstrates loading and fixture inference, with retained scikit-learn serialization warnings (model 1.5.0; runtime 1.5.2). This is compatibility smoke evidence only.

Conntrack does not supply per-packet sizes, interarrival timing or burst distributions required by the 24-feature model. The feature builder rejects those unsupported observations and the live engine does not infer using invented values. Actual routed enforcement in this report is **rule-based**, with `Hard Gate`/policy ownership and `mlp_status=disabled_unsupported_packet_features` or `not_run`. YARA remains pattern matching, not learned-model inference. Correctly measured live-model inference is still blocked on a compatible measured feature source/schema/model.

Required validation data: anonymized, labeled real metadata for benign and controlled-threat Financial login/payment/API/download/transfer traffic and Education lesson/video/search/staff traffic; legitimate high-volume usage and approved remote access; IPv4/IPv6; collector loss, quiet periods and restarts. Hold out independent environments/time periods and measure false positives, false negatives, rates, latency and actual packet outcomes. Fictional functionality tests do not substitute for representative data.

## Artifact hashes and reproduction

Original supplied source kits and older v2.2.9 installers/packages retain their hashes in the baseline audit. No separately supplied v2.2.10 binary installer was found there. Rebuilt C3 artifacts were created and installed separately inside the native Debian VMs:

| Corrected artifact | SHA256 |
| --- | --- |
| Education v2.2.10 source ZIP | `0b870aa2c9845d0635a286d94b532848ced359053ba59f0e184ccf2c85192679` |
| Financial v2.2.10 source ZIP | `e58246450a1405511e0263d538905d5623f7949669162b2f71c6be05833d4b11` |
| `minifw-ai_2.2.10-education_amd64.deb` | `0935041d24aea3c776d3af4659af31b43072fe3084de11b62f4bb9f23d6ee742` |
| `minifw-ai_2.2.10-finance_amd64.deb` | `9b41450f697f22f878df6978c087ef521fd07e260153d5514d55896e6cbc68cb` |

Location: `dist/monday-corrections/`, with Debian packages in the respective `education/` and `financial/` subdirectories. Same version strings have been reused during correction: identify the candidate by **hash and C3 base commit**, not version alone. Earlier candidate source ZIPs are retained in `candidate-*` subdirectories; they must not inherit final acceptance. Packages are for further isolated assessment, not approved operational deployment.

Independent [verification script](evidence/2026-11-02-lab/verify_artifacts.py) checks each source ZIP CRC and all 201 manifest hashes, compares 199 files to this actual repository with declared LF normalization, verifies real Debian metadata/root ownership, and compares eight core modules byte-for-byte to C3 Git blobs. This verifies the manifest rather than trusting its text. The bundled model is unchanged, SHA256 `d1193ac54b75db30cc7b18bec0ea3ab3bba2302af348bcea4f5041073a2a37d9`.

Build/install logs are [Education](evidence/2026-11-02-lab/education/minifw-native-build-install.log) and [Financial](evidence/2026-11-02-lab/financial/minifw-native-build-install.log). Installer credential lines were redacted before export; no private installer log or TLS key is included. Source manifests are under each edition's evidence `source/` directory. Reproduction uses the source kit, the C4 test fixtures and a dedicated matching VM hostname; the acceptance driver refuses arbitrary hosts.

```bash
# Workstation, read-only artifact checks
git show 2bae0856c99b0789f7f2848d460999bc83a3a1c4:app/minifw_ai/collector_flow.py
python3 docs/evidence/2026-11-02-lab/verify_artifacts.py

# Separate matching lab VM; extracted source kit, never operational host
sha256sum -c SHA256SUMS
bash scripts/build_deb.sh education 2.2.10   # Financial: finance
sudo MINIFW_SECTOR=education PRODUCT_MODE=minifw_school dpkg -i build/minifw-ai_2.2.10-education_amd64.deb
# Financial: MINIFW_SECTOR=finance PRODUCT_MODE=minifw_financial, its own .deb/VM

# Full staged checkout on Debian VM; pytest is a lab dependency
/opt/minifw_ai/venv/bin/python -m pytest -q testing/ -m 'not integration' --junitxml=/tmp/minifw-expanded-results.xml

# Copy C4 lab_gateway_acceptance.py, lab_sandbox.py, fixtures/lesson.webm adjacent in /tmp
sudo /opt/minifw_ai/venv/bin/python /tmp/lab_gateway_acceptance.py education /absolute/path/to/minifw-ai_2.2.10-education_amd64.deb
# Run financial separately with its matching package and VM.

# Actual commands emitted by the driver, retained verbatim in F/E:
conntrack -L -s 10.10.0.20 -o extended
nft -a list table inet minifw
nft get element inet minifw minifw_block_v4 '{' 10.10.0.20 '}'
ip netns exec mf-client /usr/bin/python3 /tmp/lab_gateway_acceptance.py client dns 10.10.0.1 4chan.org
ip netns exec mf-client /usr/bin/python3 /tmp/lab_gateway_acceptance.py client http 198.18.0.2 8080 /
nft delete element inet minifw minifw_block_v4 '{' 10.10.0.20 '}'
```

The complete per-run command logs, event/audit rows, policies, actual nft snapshots, both failed and successful results and evidence checksums live under `docs/evidence/2026-11-02-lab/`. The original failed probes are not overwritten by post-fix runs. An evidence SHA256 index provides fixity, not publisher authentication.

## Continuation and assessment

1. **Before broader deployment:** independently review the shared corrections, run long-lived-session and queue/load tests, rehearse reboot block restoration policy and backup/rollback. Reduce dashboard privileges and replace static readiness with telemetry/decision/enforcement health. Use isolated snapshots for each change and retain failures.
2. **Financial:** test live local ASN data/feeds, actual measured volume thresholds and time policy. Connect geolocation, asset, TLS fingerprint and API audit sources only when their inputs and acceptance tests exist. TLS-version enforcement stays unimplemented until tested.
3. **Education:** decide/provision resolver-based SafeSearch and bypass controls; validate actual restricted search. Provision a metadata sensor only with a recorded rationale and placement tests. Define VPN support accurately. Add external platform/browser/video and real segmentation acceptance.
4. **AI:** obtain representative labeled metadata and a compatible measured feature source/model. Separate functional fixtures, synthetic accuracy, rule decisions and real learned-model validation throughout.

The 100-point assessment should be awarded by the reviewer against the linked evidence. Parsing/telemetry (25), independent/degraded operation (25) and actual enforcement/recovery (20) now have controlled lab evidence, with the stated limits. Financial (10) and Education (10) have sandbox acceptance and explicit feature gaps, not full sector acceptance. Traceability/reporting (10) includes exact corrective SHAs, hashes, failures and commands, but later checkpoint submissions have not yet occurred. **No untested requirement is scored or represented as verified protection.**
