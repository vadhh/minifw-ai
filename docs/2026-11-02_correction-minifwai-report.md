# MiniFWAI v2.2.10 — shared corrections and separate lab acceptance

Record updated **2 November 2026, 15:50 WIB**. Only v2.2.10 was rebuilt/tested in this feature pass. The current candidate is C10 (599 Debian regression tests, update below); the earlier C9 feature candidate passed **566 Debian regression tests**, and the C9 results in this paragraph refer to that pass. Both separate VMs completed the new-feature suite (23 result/scope records each), followed by shared-core routed acceptance (22 Financial, 23 Education records). **Neither edition is production-ready.** Restricted resolver answers, reactive TLS-version isolation and WireGuard-pattern control have controlled packet evidence. Measured packet-model inference works, but a separate benign classification control **fails in both editions**; packet14 is therefore shadow-only and contributes zero enforcement score. Real institutions, external learning-platform acceptance, browser SafeSearch results and strict inline TLS prevention remain unverified.

The [08:59 baseline and original audit](2026-11-02_readiness-minifwai-report.md) remain an immutable account of the earlier state: 13 passing controls and 9 failed requirement probes. This report supersedes its current-status conclusions. It is an interim consolidated submission in the requested evening-report format; it does not claim that 12:00, 15:00 or 17:00 submissions have already occurred.

**v2.2.10-only verification update:** Following the user's explicit version restriction, fresh packet-level runs completed at **11:33–11:34 WIB** against only `2.2.10-finance` and `2.2.10-education`. Each installed version, exact package SHA256 and all 163 application/model/edition-policy payload files of that earlier build were checked before its run (the final C9 identity gates check 166 files). Both drivers exited zero with 22 Financial and 23 Education result/scope records. No package was rebuilt and no older version was tested in this pass. [Fresh identity, command, nftables and result evidence](evidence/2026-11-02-v2210-verification/README.md) is separate from the previous runs. The earlier 546-test regression count is historical evidence and was not counted as a fresh test run. Existing unsupported claims and bypass limitations remain unchanged.

**C10 continuation update (15:45 WIB):** rebuilt v2.2.10 candidates from C10 passed **599 Debian regression tests** and the extended suite in both separate VMs. Verified now, each within its stated scope: observed runtime readiness with three negative states, private config/database backup and restore, log rotation, Chromium playback in the sandbox, and an opt-in egress guard that stops alternate DNS, DoT and IPv6 (DoH and direct IP still pass). An actual OpenVPN tunnel is **not detected**. The browser SafeSearch probe does not discriminate pinning from Google's default. The model still misclassifies benign traffic in the lab and in a public IoT-23 probe, so it stays shadow-only. The installed engine unit differs from the package by one line that postinst adds. **Neither edition is production-ready.** [Continuation evidence](evidence/2026-11-02-v2210-continuation/).

## Current v2.2.10 feature result

The C9 feature packages are identified by `411c39f55e932b76bb92ba8c485e01cac3611ff9` and their hashes below; the current C10 candidates have their own hash table. [Feature evidence index](evidence/2026-11-02-v2210-features/README.md) separates successes, failed development runs and model-quality failures. [Lab operation and feature limits](v2210-metadata-controls.md) documents the required sources and exact configuration. Previous C3 acceptance and the 11:33 verification remain historical evidence; they do not cover these new features.

- **SafeSearch:** actual dnsmasq configuration and client CNAME/A answers for all 12 configured Google, Bing and YouTube aliases pass in both VMs. This verifies resolver pinning, not browser/content quality or resistance to alternate/encrypted DNS. DuckDuckGo and unlisted country domains remain outside coverage. Accounts and the unsupported YouTube apex remain unchanged.
- **TLS:** TLS 1.2/1.3 application access passes; the sensor recognizes TLS 1.3's selected version correctly. TLS 1.0 is accepted by the fixture without the sensor, then client forwarded IPv4 is isolated after its visible ServerHello. The held application request and subsequent forwarded connection fail. This is reactive response, **not proof that the initial handshake or earliest data cannot pass**; strict inline minimum-version prevention remains unimplemented.
- **VPN:** an actual kernel WireGuard tunnel passes ping in monitor mode; handshake/response/transport pattern detection then produces the configured IPv4 isolation and failed inner ping/forwarded connection in block mode. Ordinary UDP on the provider port is not classified as a tunnel. Default action is monitor. OpenVPN, IPsec, obfuscated protocols and cryptographic authentication of captured messages are not claimed.
- **AI:** 14 features are computed from actual capture timestamps/lengths, with DNS disabled, and the compatible model loads/infers. The known benign HTTP control receives probability about 0.999988–0.999998 and is incorrectly classified as threat. These are failed quality results, not real-world accuracy metrics. Shadow mode is enforced independently of probability; TLS/WireGuard rules act separately. Packet mode replaces conntrack and Zeek enrichment; DNS stays independent, avoiding mixed-source timing state. Initial ambiguous intra-site packet direction is skipped, not guessed.

The decoder runs as `nobody`, with supplementary groups removed and a minimal environment. A memory pipe replaces tshark's temporary capture file. [Financial process identities](evidence/2026-11-02-v2210-features/financial/capture-privileges.log) and [Education process identities](evidence/2026-11-02-v2210-features/education/capture-privileges-final.log) document the privilege split; source/payload verification confirms the same final implementation. The capture helper, engine and dashboard still require privilege review. The host rebooted externally during work; only our two stopped lab overlays were resumed. [Backing-image preservation](evidence/2026-11-02-v2210-features/backing-preservation.log) passes. No operational host service/package was modified by this feature work.

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
| C5 | `ea1b36d4ac8e070825dbdfa6ad30f3c51ace32b9` | Optional packet metadata, restricted DNS generator, TLS/WireGuard policy and packet14 model |
| C6 | `309d18e07423b26d4971330efed66b87f5f8c497` | Memory-only capture pipe and observed readiness |
| C7 | `366bf6feb64ad2fe9c0093418815480dafe7b133` | Unprivileged decoder, strict AI-disable behavior, shadow-only packet model and lab guide |
| C8 | `ff659643833cbcee6d179a5d5e1ed396ae59658b` | Skip ambiguous initial intra-site client attribution |
| C9 | `411c39f55e932b76bb92ba8c485e01cac3611ff9` | Packet source replaces conntrack and Zeek enrichment; DNS remains independent |
| C10 | `c712943a425add39a30ae772d5addf6b951e99f7` | Observed runtime readiness, private quiesced backup/restore, opt-in DNS/853 egress guard, web service restrictions |
| C10a | `fdb9bd823fe8973756cf9107239f3e693a42c603` | Lab fixture corrections (installed-module path, read-only health bind); product source unchanged |
| C10b | `5aa1323f9659c1093678a4083c75a19f5fcff9e0` | Packaged logrotate policy (already a declared local input of the C10 candidates; now committed) |
| C10c | `7a54d89664623af5c0ddf8a128702635d0e15d1b` |
| Report | `40223a2c73327e79063e9b8e4e59e76ce9a3529f` | C10 report update (this document's later edits follow in subsequent commits) | Continuation evidence, unit/logrotate identity check and public-capture model probe |

**Owner/allocation:** Codex performed implementation, testing and reporting through C10a. After Codex reached its usage limit at about 15:40 WIB, Claude Code recorded its uncommitted evidence (C10b/C10c), closed the identity check and updated this report. No other engineer assisted. The user approved immediate client IPv4 isolation on a confirmed deny-domain match and creation of local acceptance targets.

The authorized host `100.64.135.126` was used only to create/run isolated QEMU guests and read host preservation state. No package was installed on its existing operational MiniFW services, ARCHANGEL systems or client networks. Before the external host reboot, its web service was observed `activating` and engine PID 1672 was active since 30 October; those observations are historical. Neither service was changed by us. The later reboot changed host uptime; only the two lab VMs were resumed. [Host preservation evidence](evidence/2026-11-02-lab/host-preservation.log) verifies both immutable backing images still match their original SHA256.

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

All scoring thresholds and weights were retained. Only the lab block timeout changed from shipping **86,400 seconds to 15 seconds** to exercise expiry. AI is explicitly disabled in shared-core acceptance. The separate metadata suite enables only experimental packet14 shadow inference; rule enforcement remains independently attributable. Both lab services and fixture namespaces were stopped/removed after testing; the QEMU overlays remain available. Test TLS private keys and installer secrets were excluded from exported evidence.

## Consolidated requirement matrix

`U` = historical C3 [546-test Debian log](evidence/2026-11-02-lab/education/minifw-expanded-tests.log) and [JUnit XML](evidence/2026-11-02-lab/education/minifw-expanded-results.xml). `F` = [Financial routed commands/results](evidence/2026-11-02-lab/financial/minifw-acceptance.log). `E` = [Education routed commands/results](evidence/2026-11-02-lab/education/minifw-acceptance.log). `A` = [original C3 artifact verification](evidence/2026-11-02-lab/artifact-verification.log). `N` = [final feature/core evidence](evidence/2026-11-02-v2210-features/README.md), including the current 566-test results that supersede `U`, package identities and failed quality controls. `C` = [continuation evidence](evidence/2026-11-02-v2210-continuation/) for C10: final extended runs [Education](evidence/2026-11-02-v2210-continuation/education/runs/minifw-monday-education-20261102T081929Z/results.json) and [Financial](evidence/2026-11-02-v2210-continuation/financial/runs/minifw-monday-financial-20261102T081930Z/results.json), [599-test log](evidence/2026-11-02-v2210-continuation/education/minifw-continuation-tests.log), identity checks [Education](evidence/2026-11-02-v2210-continuation/education/identity-payload-final.log) / [Financial](evidence/2026-11-02-v2210-continuation/financial/identity-payload-final.log). These are evidence references, not implied verification of untested features. “Verified complete” applies only to each row's explicit scope.

| Requirement | Owner | Status | Commit | Test | Expected result | Actual result | Evidence | Remaining work |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Repository, branch, starting commit and dirty tree | Codex | Verified complete | C0 | Git and independent source comparison | Manifest agrees with actual repository | Exact C0 checked; original seven tracked changes preserved | Original baseline; A | Preserve declared local changes with any release |
| Supplied and rebuilt artifact SHA256 | Codex | Verified complete | C0/C3/C9 | Manifest and Debian verification | Identify exact inputs | Original hashes retained; C9 and current C10 hashes below; 207 hashes/205 repository comparisons and 13 committed modules per edition pass | A; N | Publisher signing/release process |
| Separate isolated lab and task allocation | Codex | Verified complete | C4 | Two VM overlays and actual routes | Separate package environments, actual client addresses | Both VMs recorded; one owner; lab ready after 09:00 | Baselines; F; E; host evidence | Pristine install matrix still unverified |
| Original/reply tuple parsing, procfs/CLI TCP/UDP | Codex | Verified complete | C1/C2 | Parser fixtures with both directions; actual CLI | Preserve original client, destination, source/destination ports | Four format/protocol combinations pass; live original tuple verified | U; F; E | Additional NAT/large-scale field captures |
| Independent collectors | Codex | Verified complete | C1 | Nine quiet/missing/stopped reader cases; live quiet/missing sources | One source cannot block decisions from another | Tests pass; DNS decisions in about 0.29–0.33 seconds with quiet/missing flows | U; F; E | Load/backpressure and long-duration validation |
| Flow decisions without DNS | Codex | Verified complete | C1/C3 | Actual 15-port connections with DNS disabled or missing | Flow rule selects client and enforces | Both editions select `10.10.0.20`, reason `port_scan`, forwarded connection times out | F; E | More representative threats, loss and outage durations |
| Credible counters/deltas and disabled timing features | Codex | Verified complete | C1–C3/C5–C9 | Actual kernel deltas and capture features | No fabricated packets, timing or unknown model inputs | Counters remain measured; optional packet14 uses actual timestamps/lengths; unsupported legacy24 inputs rejected; ambiguous intra-site direction skipped | U; N | Loss/offload/load calibration and intra-site direction source |
| Correct DNS/SNI-to-connection correlation | Codex | Implemented, verification pending | C1/C3 | Exact tuple/source-port regression | Unrelated flows remain unlabeled | Unit tests pass; DNS query-only logs intentionally do not assign a destination flow | U | Live Zeek capture and DNS-answer mapping not supplied |
| Selected IP, nft entry and actual failed forwarding | Codex | Verified complete | C1/C3 | Domain and flow triggers; client HTTP; nft counters | Selected client appears in set and loses forwarding | Same client in events/set; real timeouts and increasing drop counters | F; E; per-run nft files | Existing long-lived session and throughput stress tests |
| Unblock, expiry, duplicate events and service restart | Codex | Verified complete | C1/C3/C4 | Repeat deny; restart; expire; delete entry | No duplicate block/refresh; restart retains block; recovery works | Both editions pass, HTTP 200 after expiry/manual unblock | F; E | Dashboard unblock workflow and long timeout tests |
| Full VM reboot behavior documented | Codex | Verified complete | C0/C3 | One-hour block before kernel reboot | Document actual persistence | Block disappears after reboot; engine recreates empty set/rules | Before/after reboot logs below | Persistent block restoration is unimplemented; decide policy before release |
| Financial DMZ subnet precedence | Codex | Verified complete | C1 | Longest-prefix test; routed DMZ DNS event | `10.10.0.20` selects DMZ before broad internal subnet | DMZ, trading, internal and guest selections pass | U; F | Deployment-specific subnet review |
| Financial complete rule-input inventory | Codex | Verified complete | C1/C3 | Trace builder into all Financial detectors | State supplied and missing inputs precisely | Fourteen outputs inventoried below; disconnected rules explicit | Source; inventory below | Integrate sources only with acceptance evidence |
| Financial destination IP/ASN, not client | Codex | Implemented, verification pending | C1 | Main-loop destination-IP and destination-ASN regression | Lookup/check destination; isolate client on resulting action | Unit test confirms destination ASN lookup; blocked-ASN path enforces; destination-IP adds configured score | U | Live ASN database/feed-target acceptance not run |
| Financial TLS-version enforcement, reactive-isolation scope | Codex | Verified complete | C5–C9 | TLS 1.0 fixture/control and TLS 1.2/1.3 access | State actual prevention boundary | Reactive IPv4 isolation and post-ServerHello application failure verified; strict inline handshake/earliest-data prevention unimplemented | N | Inline enforcement and response-latency/escape acceptance |
| Financial country, asset, JA3 and API claims | Codex | Verified complete | C1/documentation | Rule-input trace | Disconnected helpers not described as live protection | Required inputs absent; no active claim in this report | Inventory below | Data sources and end-to-end rule tests |
| Financial approved deny-domain isolation | Codex | Verified complete | C1 | Bare/subdomain DNS matches and client test | Immediate client forwarded IPv4 isolation | Score 100 isolation contract; kernel entry and timeout observed | U; F | Operational allow/deny governance |
| Financial legitimate workflows in created sandbox | Codex | Verified complete | C4 | TLS login/account API/payment/transfer/CSV | Authorized fictional workflows work; unauthorized operations rejected | Payment 1,250; transfer 2,500 credits; balances correct; overdraft rejected; document downloaded | U; F | Real bank/payment/API provider workflows unverified |
| Financial enforcement scope and IPv6 limitations | Codex | Verified complete | C1 | Rule and IPv6-during-block test | State actual scope | Client-source forwarded IPv4 isolation; IPv6 still succeeds | F; E | IPv6/host INPUT/OUTPUT policy outside coverage |
| Education SafeSearch | Codex | Verified complete | C5–C9 | Actual resolver config and 12 client alias queries | Restricted endpoint answers for configured resolver users | Google/Bing/YouTube CNAME/A pinning verified; unrelated accounts and YouTube apex untouched. Browser probe: Google shows SafeSearch locked on both the pinned and the unpinned control, so the browser result does not discriminate pinning | N; C | Discriminating browser/content results, DuckDuckGo, other country domains and DNS bypass prevention unverified |
| Education bare domains and subdomains | Codex | Verified complete | C1 | `4chan.org` and `www.4chan.org`; suffix-confusion tests | Both legitimate pattern forms match without unrelated suffix matches | Both cause real isolation; case/trailing-dot controls pass | U; E | Broader feed validation |
| Education deny-list client restriction | Codex | Verified complete | C1 | Deny DNS → event → nft → client connection | Actual restriction, not only dashboard/score | Immediate isolation and connection timeout | E | Operational exceptions/allowlist review |
| Education known VPN/provider-domain control | Codex | Verified complete | C1 | `nordvpn.com` DNS match and forwarded HTTP | Precisely test known-name restriction | Client forwarding blocked; no tunnel claim | E | Provider-feed quality and legitimate remote-access exceptions |
| Education VPN tunnel detection, WireGuard-pattern scope | Codex | Verified complete | C5–C9 | Actual kernel tunnel, monitor/block and ordinary UDP | Detect real tunnel protocol metadata separately from names | Correlated WireGuard pattern detected; configured client IPv4 isolation stops inner ping/forwarding; UDP-port-only negative passes | N | Other VPN/obfuscated protocols, midstream handshakes and cryptographic identification unsupported |
| Education alternate DNS, DoH, DoT, direct IP, IPv6 | Codex | Verified complete | C4/C10 | Five actual client cases, default and with opt-in egress guard | Record blocked/detected/allowed separately | Default: all five allowed. Guard on: alternate DNS redirected to the gateway and denied name blocked, DoT blocked, IPv6 blocked by full IPv6 forwarding denial; DoH and direct IP still allowed; removal restores access | E; C; bypass table below | DoH/direct-IP controls unimplemented; guard is opt-in and interface-bound |
| Education student/staff/guest/admin selection | Codex | Verified complete | C1/C4 | Actual assigned aliases and recorded DNS events | Select four supplied policy segments | All four selected correctly | E | VLAN/physical segmentation and deployment map acceptance |
| Education legitimate learning/staff sandbox | Codex | Verified complete | C4/C10 | Lesson, search, VP8 video/range, staff role/service; unprivileged Chromium 156 | Approved sandbox remains usable | All pass; Chromium decodes 20 video frames (2 s, 160×90); student denied staff service, staff allowed | U; E; C | External platforms and sustained video unverified |
| Education disabled Zeek and missing protections | Codex | In progress | C1 | Supplied policy and installer review | Explain technical effect and historical rationale accurately | Policy disables SNI; installer does not provision Zeek; no historical product decision record found | Policy/source | Product owner rationale and actual sensor provisioning |
| Local metadata architecture, no TLS decryption/client agent | Codex | Verified complete | C1/C4 | Product path and lab routing review | Preserve architecture | Gateway uses local DNS/conntrack/optional Zeek metadata; test TLS terminates at fictional destination | Source; F; E | Country/asset/API/JA3 inputs need other local sources |
| AI synthetic provenance | Codex | Verified complete | C0/C5–C9 | Two model hashes/metadata and recipes | State training source accurately | Original legacy24 and new packet14 both synthetic; packet14 has 2,000 examples and no real sector quality claim | U; N | Representative validation data |
| AI model load and fixture inference | Codex | Verified complete | C0/C3 | Actual model load in Debian regression | Load and execute fixture inference | Pass; sklearn 1.5.0→1.5.2 serialization warnings retained | U | Version-matched export/revalidation |
| AI inference using measured live features | Codex | Verified complete | C5–C9 | Actual packet14 inference with DNS disabled | Use only supported measured inputs | Exact schema/scaler/version enforced; 14 real capture features logged; model is shadow-only with zero enforcement score | N | Classification quality not verified; benign control fails |
| Separate rule-based and model results | Codex | Verified complete | C1/C3 | Attribution regressions and AI-disabled packet tests | Rule successes not called model detections | Flow block owner Hard Gate; model status unsupported/not_run | U; F; E | Live eligible-model acceptance still pending |
| Representative Financial/Education validation data | Codex | Not started | C10 | Labelled benign lab corpus; public IoT-23 probe; [validation protocol](v2210-validation-data.md) | Independent real sector quality measurements | No representative dataset (approved source requested, not supplied). Lab corpus: 6/9 benign false positives. Public IoT-23 (not sector data): 139/155 benign flows flagged; Mirai capture 1228/1229 malicious caught but 36/39 benign flagged. Model stays shadow-only, training unchanged | N; C; [public probe](evidence/2026-11-02-v2210-continuation/public-data/) | Supply approved anonymized labelled Financial/Education data; do not enable model scoring |
| Dashboard root privilege review | Codex | In progress | C0/C7/C10 | Unit/source review, decoder process IDs, live web process status | Reduce unnecessary privilege | Decoder runs as nobody. Web service now has NoNewPrivileges, capability bound CAP_NET_ADMIN only, PrivateTmp, ProtectHome, ProtectSystem=full (verified in /proc on both VMs); it still runs as root with NET_ADMIN for unblock | N; C; units | Dashboard service account and separate unblock helper |
| Startup and readiness, progress and IPv4-rule scope | Codex | Verified complete | C1–C3/C6–C10 | Live `/health/` on both VMs: ready, engine stopped, rule flushed, sensor quiet | Do not equate process startup with protection | Ready (HTTP 200) only with same boot/process, fresh heartbeat, recent source and the drop rule present; returns 503 when the engine stops, the forward rule is flushed or the packet source is quiet >30 s | C | Load/loss alerting; health does not prove traffic enforcement or AI quality |
| Logging retention, rotation scope | Claude Code/Codex | Verified complete | C10b | Forced logrotate on packaged policy in both VMs | Bounded retention without losing state files | `*.jsonl` rotated and truncated (daily/100 MB, 14 compressed copies); `*.json` state preserved | C | copytruncate has a small concurrent-write loss window; disk-full and long-run volume untested |
| Backup and restore, config/database scope | Codex | Verified complete | C10 | Private backup, marker change, restore rehearsal on both VMs | Consistent backup and demonstrated restore | Services quiesced; config and database restored; SQLite integrity ok; archive 0600, directory 0700, unprivileged read denied; archive path/hash/edition validated before stopping services | C | Package rollback and dynamic block restoration not covered; traffic-recovery rehearsal after restore |
| Traceable commits and separate rebuilt packages | Codex | Verified complete | C1–C10 | Exact C9 and C10 package/source/payload checks | Tie actual tests to corrective source | C9 feature packages matched C9 plus declared local files; current C10 packages match C10 plus declared local files (178 installed files, one recorded postinst line); native installation, feature/core/extended acceptance pass | N; C | Clean-install matrix and release signatures |
| Consolidated report and checkpoints | Codex/Claude Code | In progress | C1–C10c; report commit | Current timestamped matrix/evidence | Candid current submission before evening | Final C9 feature/core results available by 14:44; exact runs indexed in N; 09:00 Linux lab and noon checkpoint were missed, not backfilled | All evidence | Submit current findings; retain real validation/service backlog; no future checkpoint claimed |

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
| Missing SNI | `tls_used`, `sni_present`, `known_vendor` | Visible ClientHello SNI and TLS version available via optional packet source; Zeek absent. Missing-SNI absence versus unobserved handshake remains unvalidated |
| Unknown API endpoint | `api_call`, `unknown_endpoint`, endpoint/method/status | No API audit source; disconnected |
| API schema violation | `api_call`, `schema_violation`, endpoint/method | No API audit source; disconnected |
| API auth-failure burst | `api_call`, `auth_failure_burst`, endpoint/source/method | No API audit source; disconnected |
| Connection burst | `burst_conn_count`, threshold 80 | New observed connections, not repeated polls/DNS boolean; helper/engine controls pass; 80-connection acceptance unrun |

Destination-IP denial keeps its existing score contribution; it is **not** claimed to block independently. Financial ASN sector rules can block through their rule decision. Neither was compensated with changed thresholds. `strict_tls` alone still does not enable an inline control. The new packet-source protocol policy uses observed ServerHello version and reactive isolation; strict handshake/earliest-data prevention remains unimplemented.

Additional sources needed: local destination-geolocation data, asset inventory, TLS fingerprint/risk metadata, and server/API-gateway audit events for encrypted API semantics. The fictional sandbox's application-level tests prove usability, not that MiniFW inspects encrypted account balances, payload schemas or login failures.

## Education coverage and sandbox acceptance

`use_zeek_sni=false` is supplied in the Education policy. The kit does not provision a functioning Zeek sensor; disabling its reader avoids presenting an absent data source as protection. The historical business/design reason was not supplied and is not invented here. Without Zeek or the new optional packet source, Education has no live TLS metadata. The packet source now supplies visible SNI and selected TLS version for unambiguous observed connections; JA3, certificate authenticity and full TLS/DNS features are not supplied. Zeek placement and live capture remain unverified; conntrack cannot replace missing fields.

SafeSearch resolver pinning for the documented 12 aliases is now verified with actual generated configuration and client DNS responses. Browser/content-result acceptance and bypass prevention remain pending. The sandbox lesson search is only a usability test. Provider-domain matching and the new WireGuard-pattern tests are separate; no all-VPN detection is claimed.

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
| Initial expanded pytest collection lacked staged helpers/cryptography | [Initial collection log](evidence/2026-11-02-lab/unit-expanded-initial.log) | Complete source and existing requirements installed only in VM; C3 suite 546 pass; final C9 suite 566 pass (N) |
| Decision-owner compatibility assertion failed | [Failed attribution regression](evidence/2026-11-02-lab/education/minifw-expanded-attribution-failed.log) | C1 supports actual numeric MLP reasons and legacy generic reason; final U passes |
| First acceptance driver could not parse empty namespace listing | [Driver failure](evidence/2026-11-02-lab/education/minifw-acceptance-driver-initial-failed.log) | Empty output handled as no namespaces |
| C2 routed HTTPS worked but kernel collection was empty | [No-tracking failure](evidence/2026-11-02-lab/education/minifw-acceptance-no-tracking-failed.log), [kernel probe](evidence/2026-11-02-lab/education/minifw-conntrack-hook-probe.log) | C3 activates tracking hooks and accounting; modprobe/startup alone was insufficient |
| Second scan case timed out after fixture retained half-open sockets | [Education failed run](evidence/2026-11-02-lab/education/minifw-acceptance-flow-scan-failed.log), [Financial failed run](evidence/2026-11-02-lab/financial/minifw-acceptance-flow-scan-failed.log) | C4 closes accepted sockets and waits for closure; late reply packets had become new kernel-original tuples after state deletion; successful rerun retained |
| Immediate rerun encountered lingering `mfsg` veth | [Education cleanup failure](evidence/2026-11-02-lab/education/minifw-acceptance-stale-veth-failed.log) | Explicit cleanup of owned interfaces; final runs exit zero |
| First reboot before-log stored under volatile `/tmp` | Execution record; no surviving before-log claimed | Repeated with `/var/tmp`; only the preserved paired evidence above supports persistence result |
| Old manual integration helpers fail Python parsing | `testing/integration_real_traffic.py:63`, `testing/integration_standalone.py:104` | Pre-existing, outside pytest's collected tests; remain broken/unverified |
| C10 payload check: installed `minifw-ai.service` differs from the package | [Education](evidence/2026-11-02-v2210-continuation/education/identity-payload-final.log), [Financial](evidence/2026-11-02-v2210-continuation/financial/identity-payload-final.log) | Package postinst inserts `EnvironmentFile=/etc/minifw/minifw.env`; `dpkg --verify` flags it. Top-level `preflight.py` (accepts only that one line) produced these logs; the `reproduction/minifw-continuation-preflight.py` copies are the earlier strict version that failed. Shipping the line in the unit is remaining work |
| C10 initial Debian suite: 4 failures | [Initial log](evidence/2026-11-02-v2210-continuation/education/minifw-continuation-tests-initial-failed.log) | Corrected before the final 599-test pass |
| Final `trail check` reports 20 conflicts and a 400 KB checking cap | [Check log](evidence/2026-11-02-lab/trail-check-final.log) | Phrase-based conflicts explained in commit messages; check is not claimed to pass or cover the entire evidence diff |

Counter collection preserves the kernel's actual original tuple; clearing conntrack while live sockets remain can cause a late packet to become a new connection in the opposite direction. The test fixture now closes both endpoints before resetting state. Midstream restart/state-loss and client-direction classification deserve further validation; parsing must not invent a reversed tuple to hide this effect.

The dashboard still runs as root. Web `/health/` remains a static response and does not certify progressing telemetry, decisions or enforcement. Firewall initialization now fails nonzero and creates the required tracking hooks/accounting, but comprehensive negative startup/readiness tests remain pending. Logs include actual event/audit/journal evidence; retention, disk-full behavior and prolonged load are unverified. Backup helpers still need a quiesced database backup, protected secret archive, restoration and traffic-recovery rehearsal. Keeping QEMU overlays and unchanged parent images is a rollback aid, not evidence that the product backup/restore scripts work.

Authored code/document whitespace checks pass when raw command logs are excluded. Raw logs retain their original trailing spaces and blank lines; the unscoped Git whitespace check flags those bytes, which were preserved as evidence rather than rewritten.

## AI evidence and remaining validation

The shared model identifies its data as **synthetic**: 2,000 records, 1,000 benign and 1,000 threat. Embedded perfect training metrics are not real-world Financial/Education accuracy. The Debian suite demonstrates loading and fixture inference, with retained scikit-learn serialization warnings (model 1.5.0; runtime 1.5.2). This is compatibility smoke evidence only.

Conntrack does not supply packet timing/distributions required by the legacy24 model, which remains disabled for those observations. The separate packet14 model now infers on real capture measurements and excludes all ten unsupported TLS/DNS inputs. It is synthetic and shadow-only. The final known benign HTTP controls incorrectly produce threat probabilities **0.9999881402205099 (Education)** and **0.9999977434106947 (Financial)**; the separate quality checks exit 1. This is a failed classification control, not an accuracy estimate or detected malicious traffic. Packet14 contributes zero enforcement score. Actual blocking is attributable to hard gates, domain or protocol rules; YARA remains pattern matching. Real sector model validation is still missing.

Required validation data: anonymized, labeled real metadata for benign and controlled-threat Financial login/payment/API/download/transfer traffic and Education lesson/video/search/staff traffic; legitimate high-volume usage and approved remote access; IPv4/IPv6; collector loss, quiet periods and restarts. Hold out independent environments/time periods and measure false positives, false negatives, rates, latency and actual packet outcomes. Fictional functionality tests do not substitute for representative data.

## Artifact hashes and reproduction

Original supplied source kits and older v2.2.9 installers/packages retain their hashes in the baseline audit. No separately supplied v2.2.10 binary installer was found there. Historical C3 artifacts were created/accepted separately before this feature work; their files and hashes are preserved:

| Corrected artifact | SHA256 |
| --- | --- |
| Education v2.2.10 source ZIP | `0b870aa2c9845d0635a286d94b532848ced359053ba59f0e184ccf2c85192679` |
| Financial v2.2.10 source ZIP | `e58246450a1405511e0263d538905d5623f7949669162b2f71c6be05833d4b11` |
| `minifw-ai_2.2.10-education_amd64.deb` | `0935041d24aea3c776d3af4659af31b43072fe3084de11b62f4bb9f23d6ee742` |
| `minifw-ai_2.2.10-finance_amd64.deb` | `9b41450f697f22f878df6978c087ef521fd07e260153d5514d55896e6cbc68cb` |


C9 feature artifacts are in `dist/v2210-feature-candidates/` (earlier candidates are retained separately). They include the exact committed C9 core plus the same explicitly declared pre-existing packaging/licensing inputs. No operational installation is authorized by these results.

| C9 feature v2.2.10 artifact (superseded by C10) | SHA256 |
| --- | --- |
| Education source ZIP | `c47704ba6367aaa7f1b7634e09bec993df08f87ef0e8cbec70520375cd09073e` |
| Financial source ZIP | `7eb058d512f3e3253ab888be021bd96aebdff2501e442f9e9667b920a4b24310` |
| Education Debian package | `d9ce4d6f64bebc2e71df1332d0a45faed7507846a5ecf3770413c2ed4ab85a68` |
| Financial Debian package | `c2362a9d498f47049e0d93ff993d34d113f78db8ccef80fa90e237917ff145ec` |

C10 continuation artifacts are in `dist/v2210-continuation-candidates/` (base C10 plus declared local inputs, including the logrotate policy later committed as C10b):

| C10 v2.2.10 artifact | SHA256 |
| --- | --- |
| Education source ZIP | `4c88a2fc8f2cf4dd3a71ff95808293e6cf80bd25984f5d09f27072111b186224` |
| Financial source ZIP | `628a96eeeda94f712d9c1af6189a5feb77648c03f55c1af9f02a1281993f3172` |
| Education Debian package | `d53755f868dc567a660c8892c1026e4e92f5821eff8d5007df6ce0ee3b3c96c4` |
| Financial Debian package | `017a287cfbaa5dcff6fac3ad6f760b48fc7f41f44d21a259aac7ebfb8162f2af` |

Each installed C10 package matches 178 application/model/policy/script/unit/logrotate files, apart from the one recorded postinst line.

[Final artifact verification](evidence/2026-11-02-v2210-features/artifact-verification.log) checks all 207 source hashes, 205 repository comparisons and 13 committed core modules per edition, both model hashes and root ownership. The new model hash is `98d4bf16c60e01e0e7780eaa581c3655e6483b7b17b7c15d3f524769666f489e`; the original model is unchanged. C9 identity gates compare all 166 installed application/model/edition-policy files to each exact package. Native builds and both feature/core suites exit zero in each VM; separate model-quality checks fail as recorded above.

Historical C3 location: `dist/monday-corrections/`, with Debian packages in the respective `education/` and `financial/` subdirectories. Same version strings have been reused during correction: identify each candidate by **hash and its corresponding C3/C9 base commit**, not version alone. Earlier candidate source ZIPs are retained in `candidate-*` subdirectories; they must not inherit final acceptance. Packages are for further isolated assessment, not approved operational deployment.

The historical C3 [verification script](evidence/2026-11-02-lab/verify_artifacts.py) checks each source ZIP CRC and all 201 manifest hashes, compares 199 files to this actual repository with declared LF normalization, verifies real Debian metadata/root ownership, and compares eight core modules byte-for-byte to C3 Git blobs. This verifies the manifest rather than trusting its text. The bundled model is unchanged, SHA256 `d1193ac54b75db30cc7b18bec0ea3ab3bba2302af348bcea4f5041073a2a37d9`.

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
2. **Financial:** test live local ASN data/feeds, actual measured volume thresholds and time policy. Connect geolocation, asset, TLS fingerprint and API audit sources only when their inputs and acceptance tests exist. Reactive TLS-version isolation is tested; strict inline prevention remains unimplemented.
3. **Education:** extend the verified resolver pinning with bypass controls and actual browser/content-result acceptance; DuckDuckGo/other country domains remain uncovered. Provision a metadata sensor only with a recorded rationale and placement tests. Define VPN support accurately. Add external platform/browser/video and real segmentation acceptance.
4. **AI:** obtain representative labeled metadata and validate a compatible measured model; keep packet14 shadow-only while the benign control fails. Separate functional fixtures, synthetic accuracy, rule decisions and real learned-model validation throughout.

The 100-point assessment should be awarded by the reviewer against the linked evidence. Parsing/telemetry (25), independent/degraded operation (25) and actual enforcement/recovery (20) now have controlled lab evidence, with the stated limits. Financial (10) and Education (10) have sandbox acceptance and explicit feature gaps, not full sector acceptance. Traceability/reporting (10) includes exact corrective SHAs, hashes, failures and commands, but later checkpoint submissions have not yet occurred. **No untested requirement is scored or represented as verified protection.**
