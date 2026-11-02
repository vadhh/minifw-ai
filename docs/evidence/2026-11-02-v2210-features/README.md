# Final v2.2.10 feature evidence — 2 November 2026

Only v2.2.10 was installed, rebuilt or tested in this feature pass. Each edition uses its own `minifw-monday-*` QEMU overlay. Product source is frozen at **411c39f55e932b76bb92ba8c485e01cac3611ff9 (C9)** plus the manifests' declared pre-existing packaging/licensing inputs. The original C3 accepted artifacts remain under `dist/monday-corrections/`; final feature candidates are under `dist/v2210-feature-candidates/`.

**Functional verification passed; AI classification quality did not. Neither product is production-ready.** The final pinned-Debian regression suite passed **566 tests**. Both final feature runs contain 23 asserted result/scope records; shared-core reruns contain 22 Financial and 23 Education records. These aggregate records are not counts of independently validated protections or an accuracy percentage. Separate known-benign model controls fail in both editions and exit 1. The model is hard-gated to shadow mode and contributes zero enforcement score.

## Exact final candidates and runs

| Edition | Installed version and SHA256 | Feature run | Core rerun |
| --- | --- | --- | --- |
| Financial | `2.2.10-finance`; `c2362a9d498f47049e0d93ff993d34d113f78db8ccef80fa90e237917ff145ec` | [23 records](financial/runs/minifw-monday-financial-20261102T074248Z/results.json), 14:42:53–14:43:31 WIB; exit 0 | [22 records](financial/runs/minifw-monday-financial-20261102T074333Z/results.json), 14:43:37–14:44:33 WIB; exit 0 |
| Education | `2.2.10-education`; `d9ce4d6f64bebc2e71df1332d0a45faed7507846a5ecf3770413c2ed4ab85a68` | [23 records](education/runs/minifw-monday-education-20261102T074146Z/results.json), 14:41:51–14:42:29 WIB; exit 0 | [23 records](education/runs/minifw-monday-education-20261102T074230Z/results.json), 14:42:35–14:43:30 WIB; exit 0 |

[Financial identity](financial/identity-final.log) and [Education identity](education/identity-final.log) verify the exact installed version, Debian name/version/architecture, expected package hash and all **166 installed application/model/edition-policy files** byte for byte. The [preflight script](preflight.py) fails before testing if these do not match. [Independent artifact verification](artifact-verification.log), reproduced by [verify_artifacts.py](verify_artifacts.py), checks each ZIP CRC, all 207 source-manifest hashes, 205 current repository comparisons, 13 core modules against C9 Git blobs, two model hashes and root-owned Debian payload entries.

Full final commands and raw sanitized output:

- [Financial feature commands](financial/v2210-feature-metadata.log), [core commands](financial/v2210-core-final.log), [native build/install](financial/v2210-feature-install.log).
- [Education feature commands](education/v2210-feature-metadata.log), [core commands](education/v2210-core-final.log), [native build/install](education/v2210-feature-install.log).
- [566-test log](education/v2210-feature-tests.log), [JUnit XML](education/reproduction/v2210-feature-tests.xml).
- Per-run `*.nft`, `events.jsonl`, `audit.jsonl`, policy, resolver config and journal files are siblings of the linked `results.json` files.

## Supported observations and boundaries

**SafeSearch resolver pinning:** all 12 explicitly configured aliases return CNAME/A records for Google's forced-search, Bing strict or YouTube restrict endpoints from the actual dnsmasq instance to the actual namespace client. The generated [Education resolver configuration](education/runs/minifw-monday-education-20261102T074146Z/safesearch.conf) and [Financial configuration](financial/runs/minifw-monday-financial-20261102T074248Z/safesearch.conf) are retained. `accounts.google.com` and the unsupported `youtube.com` apex remain untouched relative to the fixture resolver. This does not verify browser/content results, DuckDuckGo, unlisted country domains or bypass prevention.

**TLS:** the TLS 1.0 fixture genuinely succeeds without the packet sensor. With the sensor, its visible ServerHello causes client IPv4 isolation; the client holds application data for one second, then the request fails. TLS 1.2 and TLS 1.3 application requests succeed and correct selected-version events are observed. [Education TLS block](education/runs/minifw-monday-education-20261102T074146Z/tls10-blocked.nft), [Financial TLS block](financial/runs/minifw-monday-financial-20261102T074248Z/tls10-blocked.nft). This is reactive control after metadata, not proof that the initial handshake/earliest application data cannot escape. Strict inline minimum-version prevention and latency/escape tests remain unimplemented/unverified.

**WireGuard:** a real kernel tunnel carries inner ICMP successfully in monitor mode. Correlated initiation/response/transport metadata is detected; configured block mode creates the client nftables entry and makes subsequent inner ping and forwarded HTTP fail. [Education WG block](education/runs/minifw-monday-education-20261102T074146Z/wireguard-blocked.nft), [Financial WG block](financial/runs/minifw-monday-financial-20261102T074248Z/wireguard-blocked.nft). Ordinary UDP on port 51820 is not labelled a tunnel. These are observed WireGuard protocol patterns, not cryptographic message authentication or detection of all VPN/obfuscated protocols. Default action remains monitor.

**Measured AI:** actual captured sizes/timestamps produce 14 features and inference with DNS disabled. Features and probabilities are in the linked results/events. Legacy24 inputs are not padded with invented TLS/DNS values, and packet14 exports are kept out of legacy24 training records. The new model is trained on **2,000 synthetic examples**, with pinned sklearn 1.5.2, not representative Financial/Education data. [Actual model metadata](education/model-metadata.json) and its hash are retained. The original legacy model is preserved.

The known-benign local HTTP control is wrongly classified as threat:

| Edition | Raw threat probability | Expected/predicted | Enforcement contribution | Separate quality test |
| --- | --- | --- | --- | --- |
| Financial | `0.9999977434106947` | benign / threat | 0, `shadow_only` | [FAIL, exit 1](financial/model-quality-failed.log) |
| Education | `0.9999881402205099` | benign / threat | 0, `shadow_only` | [FAIL, exit 1](education/model-quality-failed.log) |

Run [check_model_quality.py](check_model_quality.py) against a final feature `results.json` to reproduce that failed control. One labelled sample is not a representative accuracy estimate. It is sufficient evidence to withhold model enforcement/quality claims. The functional suite intentionally verifies actual inference and zero score; it does not treat a high probability as a real threat detection.

## Failures and changes retained

- C5's first feature runs loaded the model but missed the request while direct tshark capture was starting. [Financial failure](financial/v2210-feature-c5/metadata-failed.log), [Education failure](education/v2210-feature-c5/metadata-failed.log). They do not count as feature acceptance. C6 replaced the default temporary capture with an in-memory dumpcap/tshark pipe and required a new observed packet decision after each start.
- C6's first fixture read `flows.jsonl` before asynchronous export completed. [Financial failure](financial/v2210-feature-c6/export-readiness-failed.log), [Education failure](education/v2210-feature-c6/export-readiness-failed.log). Waiting for the actual export fixed the fixture; later successful C6/C7 results remain in their candidate directories.
- A new model test exposed `numpy.bool_` instead of the documented Python `bool`. [Failed regression](education/unit-model-bool-failed.log) is retained; the public return type was corrected, and the final 566-test run passes.
- C9 replaces counter and Zeek flow enrichment when packet mode is selected, preventing source-order corruption of measured timing flags. Normal conntrack/DNS/Zeek mode is retained; a Financial source-selection regression brings the Debian suite to 566 passing tests.
- The workstation attempted unavailable `unzip` on the VMs. A subsequent retry overlapped the earlier Financial installer and hit the dpkg lock; [failure log](financial/v2210-overlap-lock-failed.log) is retained. The cached lab virtual environment was restored, the installer ran sequentially, and exact hash/all-file identity gates passed before acceptance. The failed [stale-hash gate](financial/identity-pre-retry-hash-failed.log) correctly refused the package rebuilt during that retry. No lock file was removed. These are failed test-orchestration attempts, not accepted product results.
- Final benign classification controls fail independently as shown above. Shadow mode prevents these predictions from amplifying enforcement.
- [Trail check logs](trail-check-c8.log) remain nonzero because of phrase-based learning conflicts and a 400 KB cap. Commit messages explain the conflicts; no check-pass/comprehensive coverage claim is made. Raw logs retain their command whitespace.

Controlled service stops can log a packet-reader EOF/retry traceback while systemd terminates its children. These shutdown messages are distinct from a failed main-loop decision or failed test. Real readiness is demonstrated by new packet decisions and the asserted outcomes, not absence of every shutdown message. Product-wide health and logging still need operational review.

## Isolation, privileges and unfinished work

The host rebooted externally during the session. Only the two dedicated QEMU overlays were resumed, with loopback-only SSH management; [backing-image checks](backing-preservation.log) pass. Operational host packages/services and client networks were not changed. Final lab engines/web services are inactive and namespace lists empty: [Financial state](financial/final-lab-state.log), [Education state](education/final-lab-state.log), [guarded check](final_lab_state.py). The root dnsmasq unit is left failed/inactive after fixture teardown; that state is not claimed as service readiness.

The new decoder runs as `nobody` with a minimal environment and no supplementary groups: [Financial process identities (C7)](financial/capture-privileges.log), [Education process identities](education/capture-privileges-final.log). Capture remains privileged; enforcement engine/dashboard privilege review is incomplete. The RAM-pipe [probe](education/v2210-unprivileged-pipe-probe.log) shows actual observations and zero reported drops. No raw PCAP, application payload, TLS/WireGuard private keys, installer-private logs or runtime databases are exported.

Initial packet tuples with both endpoints in configured client subnets are skipped rather than guessed. Intra-site/midstream attribution, sensor losses/offloads/load, strict inline TLS prevention, other tunnels, IPv6/alternate DNS/DoH/DoT/direct-IP bypass controls, browser SafeSearch/content acceptance, realistic long video/platform/payment traffic, model validation, meaningful service health, dashboard privileges and backup/rollback remain unfinished. The original model's 1.5.0→1.5.2 warnings remain in legacy tests; the packet14 model enforces its exact pinned version.

Use the [lab guide](../../v2210-metadata-controls.md) for supported configuration and the [single consolidated requirement report](../../2026-11-02_correction-minifwai-report.md) for status, owner, commits, expected/actual results and continuation. `SHA256SUMS` provides artifact fixity, not publisher authentication.
