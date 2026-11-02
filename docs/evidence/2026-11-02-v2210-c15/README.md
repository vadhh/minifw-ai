# C15 v2.2.10 candidate evidence — 2 November 2026

Only v2.2.10, only the separate `minifw-monday-*` QEMU overlays. C15 = `532ecc21` plus the declared local inputs in each `source/MANIFEST.json` (the committed `build_deb.sh` was repaired in `cc51f0e9`; kits are built from the working tree, which was correct). C15 is C13 plus a dashboard that runs as the unprivileged `minifw-web` user, with restore and installer steps that never follow symlinks or block on FIFOs in directories that user can write.

| Check | Education | Financial |
| --- | --- | --- |
| Package SHA256 | `a96bb1c24df8d16679dc1f5b220201cdea0fe37f87f461d6b28e6620a7bb14d9` | `d703219eb1d46032d60e46b31356f6e90e3c8073c14325925e9a6a9c8d8fba55` |
| Strict identity ([preflight.py](preflight.py)) | [178 files; `dpkg --verify` clean](education/identity.log) | [178 files; `dpkg --verify` clean](financial/identity.log) |
| Debian regression suite | [616 passed](education/minifw-c15-tests.log) | (same source; run once) |
| Feature run | [24 records, exit 0](education/runs/minifw-monday-education-20261102T094412Z/results.json) | [24 records, exit 0](financial/runs/minifw-monday-financial-20261102T094412Z/results.json) |
| Core run | [23 records, exit 0](education/runs/minifw-monday-education-20261102T094500Z/results.json) | [22 records, exit 0](financial/runs/minifw-monday-financial-20261102T094459Z/results.json) |
| Extended run, including dashboard smoke | [21 records, exit 0](education/runs/minifw-monday-education-20261102T094606Z/results.json) | [21 records, exit 0](financial/runs/minifw-monday-financial-20261102T094556Z/results.json) |
| In-place upgrade C13 → C15 | [pass](education/upgrade-c13-to-c15.log) | not run |

**Dashboard smoke (`dashboard_unprivileged_smoke`), both editions.** The web process runs as uid 105 with `CapBnd=0`, `CapEff=0` and `NoNewPrivs=1`. As that user it:
- enforced the fresh admin's password change, then completed it (a database write)
- loaded `/admin/`, events, policy and license pages (HTTP 200)
- reported the kernel rule active from the engine's runtime health
- added and removed a `deny_domains.txt` entry
- saved burst settings to the same sector policy file the engine's packaged unit enforces

It then restored the installer password; `must_change_password` is now false on the lab VMs.

**Upgrade.** On top of a clean C13 install (root-run dashboard, database at `/opt/minifw_ai/minifw.db`), `dpkg -i` of C15 without purge:
- moved the database to `/var/lib/minifw-ai`, keeping a seeded row and the admin account (integrity ok)
- moved `/etc/minifw/license.json` to `/var/lib/minifw-ai/license.json`
- applied the designed ownership (state `minifw-web`, logs `root:minifw-web 2750`, audit `660`, TLS key `640`, `minifw.env` `600 root`, editable feeds and sector policy group `minifw-web`)
- started both services, with `dpkg --verify` clean

**Lab-image finding.** `/opt/minifw_ai` and `/opt/minifw_ai/app` on both VM images are owned by the image user `debian` (created 26 October, before these packages). The package entries are `root:root`, but dpkg keeps the owner of directories that already exist. A real gateway with a pre-created `/opt/minifw_ai` would keep that owner too. The installer should `chown root:root` the code directories; this is not yet done.

Unchanged limits: OpenVPN is not detected; unlisted, self-hosted or CDN-hosted DoH and direct-IP traffic pass; Google SafeSearch is not browser-confirmed; packet14 stays shadow-only; the engine runs as root. Neither edition is production-ready. Install logs have credential lines redacted; no PCAP, private key or runtime database is exported.
