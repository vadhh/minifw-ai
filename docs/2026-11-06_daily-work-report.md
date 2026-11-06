# MiniFW-AI execution report — Friday 6 November 2026

Afridho · Financial only (Education and RISKIPSO deferred) · v2.2.13 (C22) · All times WIB

**Financial: recommend delivery of v2.2.13 with the connection-rate AI in shadow mode.** Management approved shadow mode at handover at 14:37. Every product requirement passed in the vendor lab, and again in the independent test on a clean guest. One requirement is not met, and it is not a product item: licence signing is not yet restricted to named signers. It was escalated at 15:42, and management's decision is pending. The client handoff package is built, but it has not been sent and no receipt has been returned.

## Work against today's programme

| Checkpoint | Executed work and result | Assessment |
| --- | --- | --- |
| 09:30 — candidate, requirements, inputs | Identified C20 (v2.2.11, commit `9148fad1`), listed 13 open delivery requirements, and requested six customer inputs: segments and subnets, exemptions, fresh install or upgrade, DNS on the gateway, AI scope, and licence delivery. Recorded the leaked lab licence privately and stopped using it. | Done. The customer inputs did not arrive today. |
| 11:00 — corrections and AI boundary | **C21** (v2.2.12, `a9c87e93`) fixed four defects: the restart false block, the silent upgrade gap, backup and restore on non-2.2.10 versions, and invented dashboard labels. It also added HTML escaping. **Boundary, C22, 150 s runs:** 36/min 0 of 3, 37/min 0 of 4, 38/min 4 of 4, 39/min isolated in 59 s, 60/min in 39 s. **Benign poller:** isolated in about 39–44 s; not isolated when exempt. | Met, later than 11:00. The documents now state "about 37–40 new connections a minute" (option A, 09:55). |
| 10:45 — escalation (F1) | On C21 the packet-rate hard gate ran on connection-tracking counters. Any ordinary download or stream faster than about 2.3 Mbit/s isolated the client for 24 hours. This was reproduced with a 20 MB download and a 2.5 Mbit/s stream. **C22** (v2.2.13, `50058d10`) runs that gate only with a packet sensor. | Fixed and built by 10:52 and lab-verified by about 11:20. Ilham was held at 10:50 and released at 10:54. |
| 12:30 — independent fresh install (Ilham) | **Install and access:** new guest, installer hash match, clean `dpkg --verify`, forced first-login password change. **Licence:** signed licence accepted, tampered copy rejected. **Operations:** unprivileged dashboard, Save → Apply, recovery 7 s after a kill, both services back after a reboot, backup and restore. | Met. Raw evidence checked; tarball hashes match. |
| 13:00 — Financial workflows | No customer policy exists, so the workflows ran on the delivered state with lab subnets. Web, balance and statement-export requests from internal, guest, trading and DMZ addresses all returned HTTP 200. A poller opening one new connection a second for 45 s also returned 200 every time. No client was isolated. | Not met as specified; met in the approved form. Clients behind a shared NAT address were not tested. The customer's own traffic is covered by the shadow period. |
| 14:00 — AI and resilience (Ilham) | **AI block:** isolated at count 39 with `timeout 15m`, the right reason and owner; it expired at 15 minutes. **Not isolated:** 30/min, an exempt poller, a 20 MB download and a stream; no re-block after restart. **Full log volume:** a deny-listed domain still isolated its client; health went 503, then 200. **Model missing or corrupt:** AI scoring disabled, engine kept running. **DNS outage:** see the note below. | Met after reruns. |
| 15:00 — freeze and recommendation | Code frozen at `50058d10`. Wrote the requirement-by-requirement recommendation (`2026-11-06_financial-c22-recommendation.md`). | Done. |
| 16:00 — package | The client package `minifw-ai-financial-2.2.13-handoff.zip` holds four PDFs (handover with a receipt page, setup guide, recovery procedure, release notes), the installer, `SHA256SUMS` and the tested policy. | Built and checked. The customer licence follows installation, when the customer sends their deployment ID privately. |
| End of day — handover record | The handover PDF records the version, hashes, state at handover and a receipt for both sides to sign. | Open until the package is sent and the receipt returned. |

**Note on the DNS outage test.** Ilham's first two DNS outage runs did not test the outage. The engine switches to baseline only 90–120 s after the last DNS query: 60 s without a query, then two failed checks 30 s apart. The runs were shorter than that. One reported "isolated after DNS returned" for a block that, by the kernel timer, began before DNS returned. The third run (16:12) kept DNS off for more than 5 minutes:
- the engine journal logged the switch to baseline;
- in baseline, the AI did not isolate a 60/min client, and a port scan was still isolated;
- the switch back took about 75 s, after which the AI isolated the client.

The journal lines match the engine's log format. The raw files of that run were sent privately and have not been inspected.

## Decisions

| Time | Decision | By |
| --- | --- | --- |
| 09:55 | Document the AI boundary as "about 37–40 new connections a minute" (option A) | Afridho |
| 10:52 | Fix the packet-rate defect as C22 and hold the independent test until it was built | Afridho |
| 14:37 | Hand over with the connection-rate AI in shadow mode and rule blocks on. The customer's segments and exemptions do not arrive today, and without exemptions its servers and pollers would be isolated. | Management |
| Pending | Who may sign licences | Management |

## Defects found and fixed today

| Defect | Effect | Fixed in | Verified |
| --- | --- | --- | --- |
| Port-scan rule counted connections already open at an engine restart | A client could be re-blocked for 24 h after **Apply saved changes** | C21 | Lab 4 runs; independent |
| Policy without `ai_enforcement` gave no warning | AI isolation silently absent after an upgrade | C21 | Lab |
| Backup and restore refused any version but 2.2.10 | No backup on the delivered version | C21 | Lab; independent |
| Dashboard showed invented labels, a random "time to block" and a fixed detection mode | Misleading operator information | C21 | Lab |
| A DNS name from a LAN client was displayed unescaped | Script injection in the admin's browser | C21 | Code review only |
| Packet-rate gate on connection-tracking counters | Ordinary downloads above about 2.3 Mbit/s isolated the client for 24 h | C22 | Lab; independent |
| Documents said baseline follows "a minute" without DNS | Wrong operator expectation | Documents | Code and independent journal |

**Education** v2.2.11 still has the packet-rate defect. It was seen live in the lab, where an administrator's file copy was blocked. Education needs a build from the C22 source before its own delivery.

## Licence and evidence handling

- The lab licence leaked this morning is recorded privately and has not been reused. Its identifiers are not repeated here. No licensing code was changed.
- Licence signing is not yet restricted to named signers. It was escalated to management at 15:42, with the correction to restrict the key to named signers. That takes about 30 minutes and needs no code change.
- Independent-test evidence pushed to a public branch included two lab admin passwords. Those commits were removed, the issue comment was redacted, and, as the tester reports, the exposed C21 lab guest was destroyed. No signed licence or private key was exposed. Test evidence now goes to the release owner privately.

## Not claimed

- No false-isolation rate on a real network. All AI results come from scripted lab clients.
- No test on the customer's network or policy.
- No test of clients behind a shared NAT address.
- HTML escaping was checked by code review only.
- The raw files of the final independent DNS run have not been inspected.

## Identity

| Item | Value |
| --- | --- |
| Source commit | `50058d10` on `fix/monday-core-20261102` |
| Source tarball | `7184a0039d852bfff6069b402589b859b1ffcf0ee8300fff41f151048106963f` |
| Installer `minifw-ai_2.2.13-finance_amd64.deb` | `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` (reproduced byte for byte on two VMs) |
| Model `client_window_v1.json` | `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` |
| Client package `minifw-ai-financial-2.2.13-handoff.zip` | `9d14ffc34af95e09db95c7d680ddc54d6cd5686fea4ec2954a06b6974544900d` |

## Next

1. Management decides who may sign licences, and the vendor key is restricted to them.
2. Send the package through a private channel, with the zip's SHA-256 sent separately. Collect the signed receipt.
3. Sign the customer licence when the customer sends its deployment ID privately.
4. At the site, a shadow period of a few days follows. Then the exempt list is built from the shadow review, and AI isolation is turned on with the 15-minute expiry checked once.
5. Rebuild Education from the C22 source before its delivery.
6. Follow-ups:
   - one shared classifier for block reasons (currently in four places);
   - HTML escaping moved into the base template;
   - README thresholds;
   - the stale `docs/rollback.md`;
   - the lab VM's failed dnsmasq;
   - slow all-events exports.
