# C11 v2.2.10 candidate evidence — 2 November 2026

Only v2.2.10, only the separate `minifw-monday-*` QEMU overlays. C11 = `3aaa7051486d4f2e8a01940c5636988ce77d858f` plus the declared local inputs listed in each `source/MANIFEST.json`. The only product change from C10 is that the engine unit now ships `EnvironmentFile=/etc/minifw/minifw.env` itself, and the package postinst no longer rewrites it.

| Check | Education | Financial |
| --- | --- | --- |
| Package SHA256 | `5940bef20013cbc96a37ab9899ebf9a15a5426114cd61862bcc87abb858ca9ef` | `575c72630aa35acccfa7bfacea162a066fd0b523db249e7e02e0ff72b19e1f3b` |
| Strict identity, no unit allowance ([preflight.py](preflight.py)) | [178 files match; `dpkg --verify` clean](education/identity.log) | [178 files match; `dpkg --verify` clean](financial/identity.log) |
| Debian regression suite | [604 passed](education/minifw-c11-tests.log) | (same source; run once) |
| Feature run (`--metadata`) | [23 records, exit 0](education/runs/minifw-monday-education-20261102T085238Z/results.json) | [23 records, exit 0](financial/runs/minifw-monday-financial-20261102T085238Z/results.json) |
| Core run | [23 records, exit 0](education/runs/minifw-monday-education-20261102T085324Z/results.json) | [22 records, exit 0](financial/runs/minifw-monday-financial-20261102T085324Z/results.json) |
| Extended run | [20 records, exit 0](education/runs/minifw-monday-education-20261102T085435Z/results.json) | [20 records, exit 0](financial/runs/minifw-monday-financial-20261102T085421Z/results.json) |

The extended records match the C10 run apart from timings and probabilities. The single browser-status record is now split into a pinned run and an unconfigured control:

| Provider | Pinned | Unconfigured control | Meaning |
| --- | --- | --- | --- |
| Google | filtering locked | filtering locked | Does not discriminate pinning from Google's own behaviour |
| Bing | strict status observed | unverified | Discriminates: strict status appears only with pinning |
| YouTube | strict status observed | unverified | Discriminates: strict status appears only with pinning |

These are status pages in the lab browser, not proof of content filtering. Unchanged limits: OpenVPN is not detected, the egress guard does not stop DoH or direct IP, packet14 stays shadow-only (6/9 benign false positives in the lab corpus), and the dashboard still runs as root with NET_ADMIN. Neither edition is production-ready.

Install logs have credential lines redacted. No PCAP, private key, installer-private log or runtime database is exported. `SHA256SUMS` provides fixity, not publisher authentication.
