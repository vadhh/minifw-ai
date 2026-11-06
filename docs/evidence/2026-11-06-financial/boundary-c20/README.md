# 6 Nov C20 client-window AI boundary test, Financial lab VM

`minifw-monday-financial`, minifw-ai `2.2.11-finance` (C20) as installed, 09:37–09:44 WIB. Lab-only, fictional sandbox traffic.
The model is the same in C21, so these numbers carry over until that rerun. `results.json` holds every number below.

**Main findings.**
- **Isolation starts at 38 new connections per minute, not 30.** The shipped `ai_enforcement._note` says the scope is "roughly 30+ new TCP connections per minute". In this test, clients at 30 to 37 per minute ran the full 150 s and were never isolated (0 of 4 runs at 36 and 0 of 4 at 37).
- **38 per minute was always isolated**, in 4 of 4 runs, but slowly: 60 to 88 s after the first connection.
- **A benign poller opening a new connection every second (60/min) was isolated** after 43.7 s, with a 15-minute block. Only the `exempt` list prevents this (case e).

## Set-up

- **Policy.** The shipped Financial policy was used with two edits (see `policy.diff`):
  - `segment_subnets.internal` gained `10.10.0.128/25`, so the lab clients are in `internal`. That /25 is more specific than dmz `10.10.0.0/24`, and segment lookup takes the longest prefix.
  - `ai_enforcement.exempt` gained `10.10.0.205/32`. Case (e) needs an exempt address, so this is the one edit beyond `segment_subnets`.
  - `ai_enforcement.segments` stayed `internal, guest, default`. dmz and trading were not added.
- **Approval.** `MINIFW_AI_ENFORCE_MODEL_SHA256=d06ce40e…d6ee` was appended to `/etc/minifw/minifw.env` (`env.diff`). No other env values were recorded.
- **Protection state.** Before each run, `deployment_state.json` was removed so the engine started in AI_ENHANCED, as on 5 Nov. A DNS feeder at 10.10.0.70 queried every 4 s (about 300 DNS events per run). The engine logged no `[STATE]` transition in either run, and every test-IP flow event shows `segment=internal` with `ai_window_mode=enforcing`.
- **Lab network.** The lab network was the 5 Nov one: client and server namespaces, sandbox HTTPS server 198.18.0.2:443 from `lab_gateway_acceptance.py server`, and dnsmasq on 10.10.0.1.
  - The system `dnsmasq.service` was already `failed` (`unknown interface enp0s2`) and was left as found.
  - A lab dnsmasq wrote the policy's `/var/log/dnsmasq.log`. That file was restored byte-exact afterwards.
- **Clients.** `scripts/rate_client.py`, all running at the same time from separate addresses, for 150 s each. Each tick opened one new TLS connection to 198.18.0.2:443, sent `GET /` and closed, at evenly spaced intervals.
  - Case (d) held one TCP connection to the lab sink 198.18.0.2:20000 and sent one request line per second. The sandbox HTTPS server speaks HTTP/1.0 and closes after every response, so 443 cannot hold a kept-alive session. n60 counts per (client, server, port), so the port does not change what is measured.
- **Time to isolation** runs from the client's first connection to the address first appearing in `minifw_block_v4` (the set was polled every 0.5 s). `nft-snapshots.txt` records every change to the set, with a timestamp.

## Results: attack rates (R1, plus R2 replicates at 36/37/38 with phase offsets 0, 1.7 and 3.4 s)

| Rate (conn/min) | Client | Isolated | Time to isolation | Max n60 | Max p | Kernel element |
| --- | --- | --- | --- | --- | --- | --- |
| 30 | 10.10.0.130 | no | – | 31 | 0.710 | – |
| 33 | 10.10.0.133 | no | – | 34 | 0.801 | – |
| 35 | 10.10.0.135 | no | – | 36 | 0.849 | – |
| 36 | 10.10.0.136 (+.170–.172) | no (0/4) | – | 36 | 0.849 | – |
| 37 | 10.10.0.137 (+.173–.175) | no (0/4) | – | 38 | 0.887 | – |
| 38 | 10.10.0.138 (+.176–.178) | **yes (4/4)** | 84.8 s (R2: 84.4, 87.8, 60.7) | 39 | 0.902 | timeout 15m (900 s) |
| 39 | 10.10.0.139 | yes | 59.4 s | 39 | 0.902 | timeout 15m |
| 45 | 10.10.0.145 | yes | 53.9 s | 39 | 0.902 | timeout 15m |
| 60 | 10.10.0.160 | yes | 39.2 s | 39 | 0.902 | timeout 15m |

Every isolation shows the same three things: a block event with reason `ai_window_rate`, decision owner `AI Engine (client window)` and n60 39. The kernel element was `timeout 15m` (`block_timeout_seconds` 900, not the 86400 s baseline timeout).

For isolated clients, max n60 stops at 39. After the block, their SYNs are dropped in `forward` and never become conntrack entries, so nothing more is counted.

**Observed boundary: 38 connections per minute.** 37/min never isolated (4 of 4 runs, peak n60 38). 38/min always isolated (4 of 4 runs).

**Why 38 and not 39.** Measured n60 is about 1.03 × the rate (30→31, 33→34, 37→38, 38→39) for two reasons:
- Conntrack polls arrive every 5.05 s on average (4.6–5.5 s).
- `first_seen` is the wall-clock time each flow is processed, spread up to about 0.6 s inside a poll.

So about 12.4 polls fall inside the 60 s window, and the window covers about 62 s of traffic. The 5 s sleep comes after each snapshot has been read and processed, so this cadence, and with it the 38/min figure, was measured at light lab load. On a busier gateway the polls would be further apart, which moves the boundary up. The C21 rerun should measure the cadence the same way. Near the boundary, isolation is slow (60–88 s), because the client needs the window's extra polls to reach 39.

## Results: benign automation (R1, same run)

| Case | Client | Isolated | Max n60 | Max p | Notes |
| --- | --- | --- | --- | --- | --- |
| (a) poller, new connection every 1 s (60/min) | 10.10.0.201 | **yes**, 43.7 s | 39 | 0.902 | `ai_window_rate`, element timeout 15m. A false positive in the internal segment. |
| (b) poller every 2 s (30/min) | 10.10.0.202 | no | 31 | 0.710 | |
| (c) monitoring check every 10 s | 10.10.0.203 | no | 6 | 0.037 | |
| (d) 1 request/s over one kept-alive connection | 10.10.0.204 | no | 1 | 0.017 | One 5-tuple for the whole run. |
| (e) as (a), from exempt 10.10.0.205/32 | 10.10.0.205 | no | 61 | 0.997 | Mode `enforcing`, p ≥ 0.9, no block event, no element. The exemption is what stopped it. |

`ai_window_modes` lists both `enforcing` and `not_run` for every client. The `not_run` rows do not mean the AI was off at times. They are repeat conntrack observations of flows already counted, which carry no window features. Every new-flow event was scored in `enforcing` mode.

## Restore (09:44:01 WIB, `post-restore.txt` vs `pre-test.txt`)

The test's blocks were deleted with `nft delete element`, both at the start of R2 and in restore. The set is empty, as it was before the test.

The policy, env, state-file and dnsmasq.log SHA-256s all match their pre-test values. `env_approval_lines=0`. The services were back in their pre-test states: `minifw-ai` active, `minifw-ai-web` active, `dnsmasq` failed (as found). The engine restarted in BASELINE_PROTECTION from the restored state file. The lab namespaces, veths and `bc20-*` units were removed. The driver printed `RESTORED_MATCHES_PRE True []`.

## Commands (from the Mac; every phase runs on the VM as root under systemd-run)

```bash
SSH="ssh -F ~/.ssh/minifw-lab/config minifw-lab-financial"
scp -F ~/.ssh/minifw-lab/config scripts/boundary_c20.py scripts/rate_client.py minifw-lab-financial:/var/tmp/boundary-c20/
$SSH 'sudo -n mkdir -p /var/tmp/boundary-c20/out && sudo -n systemd-run --unit=bc20-setup --wait -p StandardOutput=file:/var/tmp/boundary-c20/out/driver-setup.log -p StandardError=inherit /usr/bin/python3 /var/tmp/boundary-c20/boundary_c20.py setup'
$SSH 'sudo -n systemd-run --unit=bc20-run1 -p StandardOutput=file:/var/tmp/boundary-c20/out/driver-run-R1.log -p StandardError=inherit /usr/bin/python3 /var/tmp/boundary-c20/boundary_c20.py run R1 main'
$SSH 'sudo -n systemd-run --unit=bc20-run2 -p StandardOutput=file:/var/tmp/boundary-c20/out/driver-run-R2.log -p StandardError=inherit /usr/bin/python3 /var/tmp/boundary-c20/boundary_c20.py run R2 replicas'
$SSH 'sudo -n systemd-run --unit=bc20-restore --wait -p StandardOutput=file:/var/tmp/boundary-c20/out/driver-restore.log -p StandardError=inherit /usr/bin/python3 /var/tmp/boundary-c20/boundary_c20.py restore'
```

## Files

| Path | Contents |
| --- | --- |
| `results.json` | Combined results for both runs, the policy changes, state evidence and the restore check |
| `R1/`, `R2/` | Per run: `results.json`, `client-*.jsonl` (one row per request, written by the client), `nft-snapshots.txt`, `journal-minifw-ai.txt` |
| `R1/`, `R2/` events | `events-new-flows-and-decisions.jsonl` (scored new flows and any non-allow decision) and `events-test-ips.jsonl.gz` (the full extract for the test IPs) |
| `pre-test.txt`, `post-setup.txt`, `post-restore.txt` | Hashes, env variable names only, approval-line count, service states, `nft list table inet minifw` |
| `policy.diff`, `env.diff` | The only configuration changes |
| `driver-*.log` | Driver output for each phase |
| `scripts/` | `boundary_c20.py` (setup, run and restore; refuses to run outside this guest) and `rate_client.py` |

No keys, licence files or admin passwords are included. The root-only backups in `/var/tmp/boundary-c20/orig` were deleted once the restore was verified, so no second copy of the env file stays on the VM.
