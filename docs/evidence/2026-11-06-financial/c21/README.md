# 6 Nov C21 (v2.2.12) Financial candidate: build and lab verification

Lab VM `minifw-monday-financial` (the build also ran on `minifw-monday-education`), 09:55–10:52 WIB. Lab-only, fictional sandbox traffic.
- **Source.** `dist/v2212-c21-candidates/source.tar.gz` (SHA-256 `0be83f2a…a6c`, git archive of `a9c87e93`). The model is unchanged (`d06ce40e…d6ee`).
- **Superseded.** At 10:5x C21 was replaced by C22 (`../c22/`), which changes only the pps_saturation gate. This folder is the C21 record and the "before" evidence for that gate (`f1-bulk/`).
- **`results.json`** holds every number below.
- **Nothing secret is in this folder.** It holds no env values, admin password, licence file, private key or session token.

| Step | Result | Key numbers | Evidence |
| --- | --- | --- | --- |
| 1 Build on both VMs | **pass** | Tarball hash verified on each VM. `.deb` SHA-256 is `41c8345de1a8fd880bbbd36d6d91a3977137ed133f7e0ce7e215559ca7b2dd11` on **both** VMs. | `build/`, `dist/v2212-c21-candidates/SHA256SUMS` |
| 2 Upgrade 2.2.11 → 2.2.12 | **pass** | `dpkg_rc=0`; `dpkg --verify` clean. No ai_enforcement warning in postinst; the unit names the sector policy, so the check did run. Env gained `#MINIFW_AI_ENFORCE_MODEL_SHA256=` and `#MINIFW_AI_WINDOW_MODEL=` once each. The 2.2.13 upgrade later left both still at one (`../c22/upgrade/`), so they were not added twice. runtime-health has `protection_state` and `ai_window`. Services are active. | `upgrade/` |
| 3 Regression | **pass** | 658 passed, 0 failed (29 s) | `regression/` |
| 4 Restart false block (×3) | **pass 3/3** | At each restart, conntrack held **15 ESTABLISHED flows on 15 ports** from the client. Over the next 30.4 s the client had **87 / 89 / 82 events, all `allow`**, and no element. A fresh scan re-isolated it in 3.5 / 3.5 / 8.5 s (`port_scan`). | `lab/out/restartfb/`, `lab2/out/restartfb-run{2,3}/` |
| 5 Upgrade gap | **pass** | The startup WARNING "has no ai_enforcement segments…" was logged. runtime-health showed `approved: true, segments: []`. A client at 60 conn/min (internal) for 90 s gave 90 `shadow_only` events, n60 60, p 0.997, and was **not isolated**. | `lab/out/gap/` |
| 6 backup.sh / restore.sh | **pass** | Both returned rc 0, and services were active afterwards. A deliberate feed edit was reverted. All 33 entries matched the archive after restore, including env, db and licence (checked in place; their hashes were not recorded). `dpkg --verify` clean, login OK, archive deleted. | `lab/out/backup-restore/` |
| 7 Dashboard and exports | **pass**, with two findings (exports below) | `/admin/api/live-blocks` showed `trigger` "Hard gate (packet rate/burst/port scan)". None of Ransomware, FRAUD, Banking trojan or Math.random appeared on the pages. The status rows matched runtime-health: BASELINE → "Baseline (AI off: DNS log not healthy)" / "Off (baseline)"; AI_ENHANCED with approval → "AI enhanced" / "Enforcing in internal, guest, default". The CSV and PDF exports carry the new score / decision owner / AI window columns. | `lab/out/restartfb/`, `lab/out/exports/`, `lab2/out/exportall/`, `lab2/out/rows-ai-approved.json` |
| 8 Baseline gates | **pass** | Both gates exited 0. The licence upload was valid; the tampered upload got 400. Save → Apply changed the timeout from 86400 to 11 s. The deny domain isolated the client, and routed HTTP was blocked. The labelled corpus (8 captures, 240 requests) caused no isolation. The F1 port scan was isolated as `port_scan`. | `gates/` |
| 9 AI boundary | **pass**; isolation starts at 37–38/min, not a clean 38 (see below) | **150 s runs:** 36/min 0/4, 37/min 0/5, **38/min 5/5** (79–137 s), 39/min 2/2, 45/min 1/1, 60/min 2/2 (39 s). Benign: the 1 s poller was isolated 2/2 (39 s); the 2 s poller, 10 s monitor and keep-alive were not; the exempt 1 s poller was not (now `shadow_only`). **300 s runs:** 37/min **1/3** (104 s), 38/min 3/3. Polls came every 5.03–5.04 s. | `lab/out/R1/`, `lab2/out/{R1full,R2,R3long}/` |
| F1 bulk (added) | **finding** | With MTU-sized segments, a 20 MB download at 4 MB/s and a 2.5 Mbit/s stream were **both isolated for 24 h by `pps_saturation`**, at 7.0 s and 7.1 s. The unpaced 20 MB and the 2 MB control were not. With the lab's default veth offloads, nothing was isolated. | `f1-bulk/` |

## Notes per step

- **Build.** `SOURCE_DATE_EPOCH=1793836800 bash scripts/build_deb.sh finance 2.2.12` ran as user `lab` from a fresh extraction, through `scripts/c21_phase2.sh build`. That script is `c20_phase2.sh` with these changes: version, path and hash; the finance build only; extra post-upgrade checks.
- **Upgrade and health banner.**
  - The 2.2.11 policy was unmodified, so dpkg installed the shipped 2.2.12 policy (`ad580ecb…`).
  - The banner element is on the dashboard.
  - `/health/` answers 503 `not_ready` on this VM. Every source must be recent, and dns and zeek are quiet here: dnsmasq was already `failed`, and Zeek is not installed. So the banner shows its warning. That readiness code is unchanged in C21.
- **Restart false block.** `scripts/boundary_c21.py restartfb [label delay checks]` scans 15 ports from 10.10.0.20, deletes the element by hand, does an authenticated dashboard Save (values unchanged) and Apply, then watches for 30 s and finally scans again.

  | Run | Wait before Save | Delete → Apply | Old engine re-added the client before Apply? | Engine PID | Re-blocked after restart? |
  | --- | --- | --- | --- | --- | --- |
  | 1 | none | 4.1 s | no | 119067 → 120036 | no |
  | 2 | none | 3.5 s | no | 124878 → 124970 | no |
  | 3 | 30 s | 33.8 s | yes, 4.6 s after the delete | 125380 → 125569 | no |

  - **Run 3 detail.** The element was still there when the new PID appeared, so it was deleted again 1.2 s after the new engine started. The new engine logged no hard-gate line and never re-added the client. All 90 port-scan triggers in that run came from the old PID.
  - **Validity.** Every run had `restart_test_valid: true`: the PID changed, the new engine saw ≥15 open ports from the client, and the client produced events after the restart.
  - **Other restarts.** The later engine restarts (gap, boundary, F1) also gave no hard-gate trigger from flows that were already open.
  - **Policy file.** The dashboard Save rewrites the policy file (`ad580ecb…` → `cbdf0cda…`, same values). The shipped bytes were written back after each run.
- **Upgrade gap.** The policy was the shipped one, plus the lab /25 mapped to internal (so the client would otherwise be in AI scope), minus the whole `ai_enforcement` block. The approval line was set, and the state file was removed so that the engine started in AI_ENHANCED. Policy and env were restored byte-exact afterwards.
- **Dashboard (change 6), scope of the checks.**
  - **Escaping was checked by inspection only, with no live injection.** Every `innerHTML` built from event fields uses `esc()`, and the other paths use `textContent`.
  - **"Status = engine action"** was seen for blocks only.
  - **Forbidden strings in the app source:** the only hit is `Math.random`, in the suggested-password generator of `user_management.html`. That is outside C21 and not cryptographic.
- **Boundary.**
  - Same method as this morning's C20 run (`../boundary-c20/README.md`). The policy changed only in `segment_subnets.internal` (+ `10.10.0.128/25`) and `exempt` (`10.10.0.205/32`), plus the approval line.
  - The runs: R1 (C21 short list), R1full (this morning's full list), R2 (36/37/38 × 3, phase offsets) and R3long (37/38 × 3 for 300 s). R3long was added because one 38/min replicate needed 136.7 s of its 150 s.
  - At 37/min, n60 peaks at 38, and occasionally at 39 when the polls fall unfavourably. So a long-running 37/min client can be isolated.
  - Every isolation was `ai_window_rate`, with element timeout 900 s. The exempt client is now scored `shadow_only` (C21 change 2).
- **Gates.** `scripts/c21_gate_wrapper.py` makes no harness override, because the C21 harness checks the package version itself. It changes one thing in memory: the financial package-hash pin in `lab_thursday.py`, from C18 to C21.

## F1 bulk: legitimate bulk traffic vs the `pps_saturation` hard gate (before C22)

- **What the gate does.** `main.py::evaluate_hard_threat` isolates a client, as a Hard Gate with a 86400 s element, when any one flow measures more than 200 packets/s. For conntrack flows, the rate is counter deltas since the flow's first poll divided by the elapsed time.
- **Policy and state.** Shipped policy with only `segment_subnets.internal` + `10.10.0.128/25`; no approval; shipped state file (BASELINE); fresh engine.
- **Clients.** Four fresh clients at the same time, through the gateway to the lab HTTP server, `scripts/boundary_c21.py f1bulk A|B`.
- **Two passes.** Pass A used the lab's default veth offloads (TSO/GSO on), so conntrack counts coalesced super-packets. Pass B turned TSO/GSO/GRO off on all four veth ends, so segments were MTU-sized, as on a NIC that does not coalesce before netfilter.

| Pass | Client | Transfer | Isolated | After | Reason / owner | Element | Conntrack pkts | Max pkt/s (5 s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | .150 | 20 MB unpaced (0.05 s) | no | – | – | – | 1242 | 0 |
| A | .151 | 20 MB paced 4 MB/s (5.2 s) | no | – | – | – | 542 | 55 |
| A | .152 | 2.5 Mbit/s stream, 60 s, 1 connection | no | – | – | – | 1730 | 32 |
| A | .153 | 2 MB control | no | – | – | – | 148 | 0 |
| B | .154 | 20 MB unpaced (0.11 s) | no | – | – | – | 16275 | 0 (done between polls) |
| B | .155 | 20 MB paced 4 MB/s (5.2 s) | **yes** | 7.0 s | `pps_saturation`, Hard Gate | **timeout 86400 s** | 15684 | 1546 |
| B | .156 | 2.5 Mbit/s stream, 1 connection | **yes**; the stream was then cut | 7.1 s | `pps_saturation`, Hard Gate | **timeout 86400 s** | 2132 | 234 |
| B | .157 | 2 MB control | no | – | – | – | 2366 | 0 |

- **Earlier routed check.** curl downloads up to 300 MB at 0.18–510 MB/s with default offloads were not isolated (`lab2/out/bulk/`).
- **Cleanup.** The test deleted its own elements (.155, .156). The veths were removed by the restore.

## Unexpected

1. **`pps_saturation` isolates 127.0.0.1 during all-events dashboard exports.** This is the same gate as F1 bulk.
   - Run 1 hit it at 10:05:54.
   - The repeat at 10:27–10:30 reproduced it: the engine re-added 127.0.0.1 25 times, about every 5 s, for 2 min after the transfer, and it was deleted each time.
   - The dashboard listens on 127.0.0.1:8443 only, and the block sits in the `forward` chain, so no traffic was cut. The effect is a false 1-day block entry and repeated block events on the dashboard and in exports.
2. **All-events exports are slow.** For about 64k events, the CSV took 25.4 s and the PDF 62.5 s. The first PDF attempt ran into the 20 s client timeout. Block-only exports take about 1.5 s.
3. **The running engine undoes a hand unblock at its next poll while it still tracks the client's scan flows.** Seen four times: 2 s (run 1 cleanup), 4.6 s (run 3, before the Apply), 2.0 s and 2.5 s (cleanup of runs 2 and 3). The restart path that C21 fixes is not affected. An operator's unblock does not stick until the flows age out or the engine restarts.
4. **The gate harness leaves `minifw-ai` and `minifw-ai-web` stopped.** They were started again at 10:15.
5. **Right after `backup.sh`, at least one file no longer matched its archive entry.** The names were not recorded. Everything matched after `restore.sh`. Rechecked on C22 with names recorded.
6. **The AI boundary is 37–38/min, not a clean 38** (see step 9).

## State after C21 (10:52 WIB)

- **Brackets.** Both lab brackets printed `RESTORED_MATCHES_PRE True []` (policy, env, state, dnsmasq.log).
- **Cleanup.** The netns, veths and `bc20-*` units are gone, the set was empty, and `/var/tmp/c21/lab/orig` was deleted both times.
- **Not restored.** `events.jsonl`, the engine journal and the dashboard audit/DB entries keep today's lab events and logins, as on 5 Nov.
- **Package.** At 10:52 the VM was upgraded to C22 (2.2.13). The final state is recorded in `../c22/`. `final-state.txt` here is the C21 state at 10:15.
- **Education VM.** Untouched apart from the build directories `/var/tmp/c21` and `/var/tmp/c22`. It is still `2.2.11-education`, with services as before. While the C22 deb was copied off it with scp at 10:52, its 2.2.11 engine isolated the jump host's address with `pps_saturation`. That block was deleted at 11:02 and is recorded in `../c22/`.

## Commands (from the Mac; each runs on the VM as root under systemd-run)

```bash
SSH="ssh -F ~/.ssh/minifw-lab/config minifw-lab-financial"   # Education: minifw-lab-education, build only
$SSH 'sudo -n systemd-run --unit=c21-build ... bash /var/tmp/c21/scripts/c21_phase2.sh financial build|upgrade|regression'
# lab driver /var/tmp/c21/lab/boundary_c21.py, in this order:
#   setup; restartfb; gap; exports; edit; run R1 main; restore; backuprestore
#   setup; restartfb restartfb-run2 0 no; restartfb restartfb-run3 30 no; exportall; bulk; edit; run R1full full;
#   rows ai-approved; run R2 replicas; run R3long long; f1bulk A on; f1bulk B off; restore
$SSH 'sudo -n systemd-run --unit=c21-gates --wait bash /var/tmp/c21/baseline/run_gates.sh financial /var/tmp/c21/src-current/build/minifw-ai_2.2.12-finance_amd64.deb'
```
