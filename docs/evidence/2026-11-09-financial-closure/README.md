# Financial C22: DNS-outage acceptance, inspected 9 November 2026

Afridho, 09:10 WIB. This closes the open item in the 6 November report: "the raw files of the final independent DNS run have not been inspected."

## Source

The tester's privately sent archive (`c22-financial-independent-evidence-rerun2-20261106.tar.gz`, SHA-256 `53eece66…68da`, posted on issue #8) had not arrived. The release owner therefore read the original logs directly from the tester's guest `minifw-friday-c22-financial`, which is still running unchanged. The guest's own journal, dnsmasq log and engine event log are the source the tester's archive was made from. Access was read-only.

Extract: `c22-guest-dns-outage-extract.txt`, SHA-256 `df2d12e81f3a587a9efdc2b4f458d459d1f3d10cb55a2e47d2ca72c67d58b7ca`. All times are UTC (WIB = UTC + 7).

## Result: the check passes

| Check | What the guest's logs show | Result |
| --- | --- | --- |
| Candidate | `minifw-ai 2.2.13-finance amd64` installed. The installer kept beside the guest on the lab host hashes to `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9`, the delivered installer. Model SHA-256 `d06ce40e…d6ee`, the delivered model. | Pass |
| AI enforcement on during the test | Engine PID 13658 started at 08:58:26 and ran until 09:08:40. Both state transitions are logged by that PID, and the same PID placed an `enforcing` AI block at 09:08:37. No restart between. | Pass |
| DNS actually stopped | Feeder stopped 08:59:40. Last dnsmasq query 08:59:37; **no** query logged 09:00:00–09:05:59; first query back 09:06:28 | Pass |
| Fallback to baseline | `[STATE_TRANSITION] AI_ENHANCED_PROTECTION -> BASELINE_PROTECTION … telemetry_lost_2_consecutive_checks` at 09:01:27, 110 s after the last query (expected 90–120 s) | Pass |
| AI paused in baseline | 10.10.0.177 ran 09:05:17–09:06:27 in baseline: 129 events, rate up to 59 new connections in 60 s, every event `allow`, AI mode `not_run` | Pass |
| Rules still block in baseline | 10.10.0.178 blocked 09:06:22 for `port_scan`, owner Hard Gate, inside the baseline window | Pass |
| Recovery | `BASELINE_PROTECTION -> AI_ENHANCED_PROTECTION … telemetry_healthy_3_consecutive_checks` at 09:07:29, 61 s after DNS returned (expected 60–90 s) | Pass |
| AI isolates again after recovery | 10.10.0.177 blocked 09:08:37, reason `ai_window_rate`, count 39, probability 0.902, mode `enforcing`, owner "AI Engine (client window)" | Pass |
| Delivered state restored | Engine restarted 09:08:40 (approval line removed, per the tester) | Consistent |

## Differences from the tester's report

- The tester reported the post-recovery AI block "at count 40". The event log records the block decision at count **39** (probability 0.902). Count 38 scored 0.887 and was allowed. This matches the documented boundary. It does not change the result.
- The tester's archive itself was not inspected. Its hash stays on record. The guest logs make it unnecessary for this check.

## Effect on the delivered documents

None. The release notes' summary ("loss and return of DNS" among the independently repeated checks) is now supported by inspected raw evidence. The package, its checksums and the zip hash are unchanged.
