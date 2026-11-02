# MiniFW-AI v2.2.10 — work report, 2 November 2026

Written **17:10 WIB**. Covers all work on branch `fix/monday-core-20261102` today. The detailed requirement matrix, hashes and per-run evidence are in the [consolidated correction report](2026-11-02_correction-minifwai-report.md); this page is the summary.

## Status

**Neither the Financial nor the Education edition is production-ready.** All testing used only v2.2.10, on two separate QEMU lab VMs (`minifw-monday-financial`, `minifw-monday-education`) reached through the testbed host. No operational host service or client network was touched.

- **Latest fully verified candidate: C15.** It is C13 plus a dashboard that no longer runs as root, with fixes for two security-review findings. Strict package identity, 616 Debian regression tests, and the feature, core and extended lab suites (including a real dashboard smoke test as the non-root user) all pass in both editions.
- **In-place upgrade passes:** installing C15 over a C13 install (root dashboard) on the Education VM moved the database (with existing data and the admin account) and the license to `/var/lib/minifw-ai`, applied the new ownership, started both services, and left `dpkg --verify` clean.

Nothing has been pushed. Seven files with pre-existing uncommitted changes (licensing feature, README, build defaults) were preserved; each source kit declares them as local inputs.

## Who did what

| Time (WIB) | Who | Work |
| --- | --- | --- |
| 08:59–14:47 | Codex | Baseline audit, then C1–C9: parser and measured counters, independent collectors, DNS-free flow decisions, immediate deny isolation, kernel tracking hooks, routed lab acceptance, optional packet metadata, SafeSearch pinning, TLS-version and WireGuard controls, shadow-only packet AI model |
| 15:12–15:31 | Codex | C10: observed runtime readiness, private backup/restore, opt-in DNS egress guard, browser/OpenVPN/bypass probes. Hit its usage limit at about 15:40 with work uncommitted |
| 15:44–16:50 | Claude Code | Took over: committed Codex's evidence, closed its open identity check, then C11–C15 below. Updated the consolidated report after each candidate |

## Candidates built and tested today

| Candidate | Change | Lab result (both editions) |
| --- | --- | --- |
| C1–C9 | Core corrections and v2.2.10 metadata features (see the consolidated report) | 566 tests; feature and core suites pass |
| C10 | Readiness, private restore, egress guard, web service restrictions | 599 tests; all suites pass. The installed engine unit differed from the package by one line |
| C11 | Engine unit ships `EnvironmentFile`; postinst no longer edits a packaged file | Strict identity with `dpkg --verify` clean; 604 tests; all suites pass |
| C12 | Egress guard also drops client TCP/UDP 443 to 31 public DoH resolver addresses | 609 tests; all suites pass; fixture DoH blocked (2 packets dropped per VM) and restored after removal |
| C13 | SafeSearch resolver answers Firefox's DoH canary (`use-application-dns.net`) with NXDOMAIN | 609 tests; all suites pass; canary NXDOMAIN from the real resolver |
| C14 | Dashboard runs as unprivileged `minifw-web` | **Superseded.** Extended smoke test failed (test bug, see below); security review then found symlink issues |
| C15 | C14 plus symlink/FIFO-safe restore and installer, repaired build script, corrected smoke test | 616 tests; all suites pass, including the dashboard smoke test; in-place upgrade from C13 passes |

## Verified today, within stated scope

| Area | What was shown in the lab |
| --- | --- |
| Packaging | Every installed application/model/policy/unit/logrotate file (178) matches its package byte for byte; `dpkg --verify` clean from C11 on |
| Readiness | `/health/` returns ready only with a live engine, fresh decisions and the drop rule present; returns 503 when the engine stops, the rule is flushed or the sensor goes quiet |
| Backup/restore | Private (0600/0700) quiesced backup; configuration and database restored with SQLite integrity ok. Package rollback and active blocks are not restored |
| Log retention | Packaged logrotate policy rotates `*.jsonl` (daily or 100 MB, 14 copies) and leaves state files alone |
| Bypass controls (opt-in guard) | Alternate DNS redirected to the gateway, DoT blocked, IPv6 forwarding denied, DoH to listed public resolvers blocked; removal restores access |
| Firefox DoH | Resolver returns NXDOMAIN for the canary, which keeps Firefox's default DoH off |
| SafeSearch | DNS pinning for 12 Google/Bing/YouTube aliases; in the browser, Bing and YouTube strict status appear only with pinning |
| Dashboard privileges (C15) | Web process runs as uid 105 with no capabilities (`CapBnd=0`, `CapEff=0`). As that user it completed the forced password change, loaded the dashboard, events, policy and license pages, reported the kernel rule active, added and removed a deny-domain entry, and saved the same sector policy file the engine enforces |

## Failures and corrections kept on record

- **Codex's last preflight failed** on the engine unit file. Cause: the package's install script edited a file it installs. Recorded as a product finding, then fixed in C11.
- **C12's first test run failed (1 test)** because the lab packing script left out the new DoH list file; the `.deb` had it. Fixed the packer and kept the failed log.
- **I misreported the browser SafeSearch result** at first ("does not discriminate"). Only Google fails to discriminate; Bing and YouTube do. Corrected in the report.
- **C14's smoke test was wrong:** a fresh admin is correctly forced to change the password first. The C15 test performs that change.
- **Security review found two real issues in C14:** root-run restore and installer steps could follow symlinks the dashboard user can plant, and restore could hang on a planted FIFO. Fixed in `715114ab` and `532ecc21`, with regression tests.
- **My partial staging corrupted the committed `build_deb.sh`** in two commits: the permission block was dropped, and a state-directory deletion moved outside the purge branch. The lab built from the correct working tree. Repaired in `cc51f0e9`, and a team learning was recorded.
- **Codex's note that the dashboard kept NET_ADMIN "for unblock" was wrong.** The dashboard has no unblock path; its only firewall use was a read-only status listing.

## Bugs found and fixed beyond the original list

- Policy edits made in the dashboard never reached enforcement: the dashboard edited the base policy, but the engine reads the sector policy. Fixed in C14/C15 at your request.
- The license file moves from `/etc/minifw/` to `/var/lib/minifw-ai/` so the non-root dashboard can install licenses. Your `licensing.py` is unchanged; only the service environment, installer migration and deployment doc change.

## Still open

| Item | State |
| --- | --- |
| OpenVPN tunnel detection | Not detected (a real static-key tunnel passes) |
| DoH to unlisted, self-hosted or CDN-hosted resolvers; direct-IP traffic | Still pass |
| Google SafeSearch browser confirmation | Google shows locked with or without pinning |
| AI model quality | Packet model misclassifies benign traffic (lab 6/9; public IoT-23 139/155). Stays shadow-only with zero enforcement weight |
| Engine privileges | Engine still runs as root (needed for nftables) |
| Pre-existing `/opt/minifw_ai` ownership | On both lab VM images the code folder is owned by the image user `debian` (it existed before these packages). dpkg keeps the owner of existing folders, so the installer should reset code folders to root; one-line fix, not yet built |
| Older non-package installer `scripts/install_systemd.sh` | Not updated for the dashboard account |
| Real sites, sustained load, disk-full, long-run behaviour | Not tested |

## Decision needed from you

- **Approved dataset for AI validation.** Codex asked whether anonymised, labelled Financial/Education traffic exists; nobody has answered yet. Without it the model stays shadow-only.

## Evidence

- Consolidated report: [2026-11-02_correction-minifwai-report.md](2026-11-02_correction-minifwai-report.md)
- Per-candidate evidence: [C10](evidence/2026-11-02-v2210-continuation/), [C11](evidence/2026-11-02-v2210-c11/README.md), [C12](evidence/2026-11-02-v2210-c12/README.md), [C13](evidence/2026-11-02-v2210-c13/README.md), [C14, failed](evidence/2026-11-02-v2210-c14/README.md), [C15](evidence/2026-11-02-v2210-c15/)
- Lab access for the next session: `ssh -F ~/.ssh/minifw-lab/config minifw-lab-education` (or `minifw-lab-financial`)
