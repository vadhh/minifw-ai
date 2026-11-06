# Financial v2.2.13 (C22): delivery recommendation

Friday 6 November 2026, 16:30 WIB. Prepared by Afridho with Claude Code. Code frozen at 15:00; the independent reruns finished at 16:12 (issue #8).

## Candidate (frozen)

| Item | Value |
| --- | --- |
| Source commit | `50058d10` on `fix/monday-core-20261102` |
| Source tarball SHA-256 | `7184a0039d852bfff6069b402589b859b1ffcf0ee8300fff41f151048106963f` |
| Installer | `minifw-ai_2.2.13-finance_amd64.deb`, SHA-256 `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` |
| Connection-rate AI model | `client_window_v1.json`, SHA-256 `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` |
| State at handover | Connection-rate AI in shadow mode (isolation off); rule blocks on. Approved by management at 14:37 WIB because the customer's segments and exemptions do not arrive today. |

No code change after `50058d10`. Later commits change documents and evidence only.

## Recommendation

**Deliver C22 in the approved handover state:** connection-rate AI in shadow mode, rule blocks on. Every product requirement is met, by the lab and independently.

One requirement is not a product item and is **not met: signing authority (row 13).** Licence signing is not yet restricted to named signers. It is escalated to management, who decide who may sign. The customer licence is signed by the release owner after the customer installs, for that gateway's deployment ID, and sent privately.

Row 8 is met only in the approved form. No customer policy exists today, so the customer's own workflows are covered by the shadow period, in which the AI cannot isolate anyone.

## Requirements

"Lab" means the vendor's lab VMs, with evidence in `docs/evidence/2026-11-06-financial/`. "Independent" means Ilham, on his own clean guest (issue #8).

| # | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Exact candidate identified | **Met** | Table above. Reproducible: the same installer, byte for byte, on two VMs. Ilham's installer hash matched. |
| 2 | Restart false block fixed | **Met** | Lab: no re-block, 3 of 3 runs on C21 and 1 on C22. Independent: not re-blocked after Save → Apply. |
| 3 | Upgrade gap: a policy without `ai_enforcement` is reported, not silent | **Met (lab)** | The engine and the installer warn; upgrades add the commented approval lines once. 2.2.12 → 2.2.13 upgrade clean. |
| 4 | AI boundary at 30–39 and 60/min | **Met** | Lab 150 s runs: 36/min 0 of 3, 37/min 0 of 4, 38/min 4 of 4, 39/min 59 s, 60/min 39 s. Independent: 30/min not isolated; 60/min isolated at count 39, `timeout 15m`, reason `ai_window_rate`, owner "AI Engine (client window)". Documents say "about 37–40 a minute". |
| 5 | Benign automation, with and without exemption | **Met** | A poller opening one new connection a second is isolated in about 39–44 s. Exempt, it is not (lab and independent). Reported beside the headline in the release notes, limitation 2. |
| 6 | Dashboard and documents describe connection-rate detection accurately | **Met (lab)**, one part by code review | Status rows match the engine. No invented labels or made-up time to block. HTML escaping checked by code review only. |
| 7 | Independent fresh install: first login, signed licence, unprivileged dashboard, Save → Apply, service recovery | **Met** | Independent report passed every point. The raw evidence of the first run and the first rerun was checked; tarball hashes match the posted ones. Licence signing is covered in row 13. |
| 8 | Financial workflows on the intended policy | **Not met as specified; met in the approved form** | No customer policy exists today. Independent, on the delivered state with lab subnets: web, balance and statement-export requests from internal, guest, trading and DMZ addresses all returned HTTP 200. A poller opening one new connection a second for 45 s returned HTTP 200 every time. No client was isolated. Clients behind a shared NAT address were not tested. |
| 9a | Independent AI kernel block, restart, F1 | **Met** | Independent: AI block as in row 4; no re-block after restart; 20 MB download and a sustained stream not isolated. |
| 9b | Delivered state: approval line absent, 60/min not isolated, port scan still isolated | **Met (independent)** | Approval line commented out; a client at 60/min logged `shadow_only` (count 41, probability 0.93) and was not isolated; a port scan from another client was isolated. |
| 9c | AI block expires after 15 minutes | **Met (independent)** | AI block placed at about 07:40 UTC with `timeout 15m`; gone from the kernel set at 07:55:20. |
| 9d | F2: full log volume, enforcement continues, warning shows, recovers | **Met (independent)**, warning shown by health only | Log directory on a full 256 KiB filesystem: a deny-listed domain query still isolated its client, and health returned 503. After space was freed and the engine restarted, health returned 200. The dashboard banner itself was not captured; it is driven by the same health state. |
| 9e | DNS telemetry lost: baseline, rules keep blocking, AI resumes | **Met (independent, second rerun)** | DNS off for more than 5 minutes. The engine journal logged the switch to baseline (`telemetry_lost_2_consecutive_checks`). In baseline, a 60/min client was not isolated and a port scan was. After DNS returned, the switch back took about 75 s, and the 60/min client was isolated at count 40. The journal lines match the engine's log format. The raw files of this rerun were sent privately and have not been checked. |
| 9f | Model missing or corrupt: engine keeps running, AI off | **Met (independent)** | The engine stayed active. Its journal shows "No model …; AI window scoring disabled" and "Model … rejected …", then the model loading again after it was restored. |
| 10 | Every correction has its affected checks rerun | **Met** | The C22 change (packet-rate gate) reran F1 bulk, port scan, regression (659 passed), gates, boundary, backup and restore. |
| 11 | Package | In progress | See below. |
| 12 | Authorized handover record | Open | End of day. |
| 13 | Lab licence containment | **Not met: signing authority** | The leaked licence and its deployment ID are recorded privately and not used. Signing authority is not yet restricted to named signers; escalated to management. Separately, evidence pushed to a public branch included two lab admin passwords; those commits were removed and the issue comment redacted. No signed licence or private key was exposed. |

## Package (16:00)

| Item | Status |
| --- | --- |
| Installer and `SHA256SUMS` | Ready (`dist/v2213-c22-candidates/`) |
| Setup guide, recovery procedure, release notes with known limitations | Ready (`docs/delivery/2026-11-06-financial-v2.2.13/`) |
| Tested policy | Shipped Financial policy. Its subnets are lab examples and must be replaced on site (setup guide, section 11). |
| Exemptions | Empty at handover. Built by the site from the shadow-period review (setup guide, section 14). |
| Customer licence | Signed after installation, for the customer gateway's own deployment ID, and sent privately. It cannot be signed before the customer installs. |

## Residual risks the customer accepts with this handover

- **Shadow period.** The connection-rate AI does not isolate anyone until the site approves it.
- **Lab evidence only.** No false-isolation rate has been measured on a real network.
- **Rule blocks have no per-client exception.** A deny-listed domain or a port scan isolates a client for 24 hours from day one.
- **Address spoofing.** A LAN device that forges a neighbour's address can get the neighbour isolated. The site needs switch anti-spoofing.
