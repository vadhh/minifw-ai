# C13 v2.2.10 candidate evidence — 2 November 2026

Only v2.2.10, only the separate `minifw-monday-*` QEMU overlays. C13 = `84c90a68b4995a560401cc3cd00ec07de64f04de` plus the declared local inputs in each `source/MANIFEST.json`. The only product change from C12: the generated SafeSearch dnsmasq file answers `use-application-dns.net` with NXDOMAIN, Mozilla's canary that keeps Firefox's *default* DoH off on this resolver.

| Check | Education | Financial |
| --- | --- | --- |
| Package SHA256 | `0546f76711b16e45f74182b09ea8f1d3769052df5c73af4034e83c50a7545207` | `084678af1070eb0679d7c3dccebb1ff6cbf9e6d49356b523c766750247b2294a` |
| Strict identity ([preflight.py](preflight.py)) | [178 files; `dpkg --verify` clean](education/identity.log) | [178 files; `dpkg --verify` clean](financial/identity.log) |
| Debian regression suite | [609 passed](education/minifw-c13-tests.log) | (same source; run once) |
| Feature run (includes SafeSearch and canary) | [24 records, exit 0](education/runs/minifw-monday-education-20261102T092524Z/results.json) | [24 records, exit 0](financial/runs/minifw-monday-financial-20261102T092525Z/results.json) |
| Core run | [23 records, exit 0](education/runs/minifw-monday-education-20261102T092610Z/results.json) | [22 records, exit 0](financial/runs/minifw-monday-financial-20261102T092610Z/results.json) |
| Extended run | [20 records, exit 0](education/runs/minifw-monday-education-20261102T092716Z/results.json) | [20 records, exit 0](financial/runs/minifw-monday-financial-20261102T092707Z/results.json) |

`firefox_doh_canary`: the client's `dig use-application-dns.net A` against the actual generated resolver returns `status: NXDOMAIN`, even though the lab resolver answers every other name (catch-all `address=/#/`). Scope: Firefox's default DoH only. Users who switch DoH on explicitly, other browsers and other DoH clients are unaffected; no Firefox browser was run in this test. All other results match C12. Neither edition is production-ready.

Install logs have credential lines redacted. No PCAP, private key or runtime database is exported. `SHA256SUMS` provides fixity, not publisher authentication.
