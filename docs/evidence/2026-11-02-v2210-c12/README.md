# C12 v2.2.10 candidate evidence — 2 November 2026

Only v2.2.10, only the separate `minifw-monday-*` QEMU overlays. C12 = `97945ac4` plus the declared local inputs in each `source/MANIFEST.json`. The only product change from C11 is in the opt-in egress guard: it now drops client TCP/UDP 443 to the public DoH resolver addresses in `config/feeds/doh_resolvers.txt`.

| Check | Education | Financial |
| --- | --- | --- |
| Package SHA256 | `398fe8056527822cdcbbbc9d9cb614f32527dd6c69019ac8e7f846c67225070d` | `6388811848330d868a5291f0d43237701c8e628b3c533ff861d449aaa97da904` |
| Strict identity ([preflight.py](preflight.py)) | [178 files match; `dpkg --verify` clean](education/identity.log) | [178 files match; `dpkg --verify` clean](financial/identity.log) |
| Debian regression suite | [609 passed](education/minifw-c12-tests.log); first attempt [1 failed](education/minifw-c12-tests-packer-failed.log) because the lab test-source packer omitted `config/feeds/*.txt` (fixture gap, the `.deb` contained the file) | (same source; run once) |
| Feature run | [23 records, exit 0](education/runs/minifw-monday-education-20261102T090547Z/results.json) | [23 records, exit 0](financial/runs/minifw-monday-financial-20261102T090547Z/results.json) |
| Core run | [23 records, exit 0](education/runs/minifw-monday-education-20261102T090633Z/results.json) | [22 records, exit 0](financial/runs/minifw-monday-financial-20261102T090633Z/results.json) |
| Extended run | [20 records, exit 0](education/runs/minifw-monday-education-20261102T090744Z/results.json) | [20 records, exit 0](financial/runs/minifw-monday-financial-20261102T090730Z/results.json) |

**DoH result.** The lab DoH fixture at `198.18.0.2:443` was added to the shipped list for the test. With the guard on, the DoH query fails while HTTP on port 8080 to the same address still succeeds. The IPv4 rule's counter shows 2 dropped packets in each edition ([Education rules](education/runs/minifw-monday-education-20261102T090744Z/egress-guard.nft), [Financial rules](financial/runs/minifw-monday-financial-20261102T090730Z/egress-guard.nft)). After removal, DoH, DoT and IPv6 work again. The full shipped list (31 IPv4/IPv6 addresses) parsed and loaded into nftables on both VMs.

**Scope.** This blocks DoH only to listed resolver addresses. Unlisted, self-hosted and CDN-fronted DoH (for example browser TRR endpoints on shared edges) still pass, as does other direct-IP traffic. No public resolver was contacted; the listed addresses were loaded, not exercised. All other extended results match C11. Neither edition is production-ready.

Install logs have credential lines redacted. No PCAP, private key or runtime database is exported. `SHA256SUMS` provides fixity, not publisher authentication.
