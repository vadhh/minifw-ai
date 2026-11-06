# 6 Nov C22 (v2.2.13) Financial candidate: build and lab verification

Lab VM `minifw-monday-financial` (the build also ran on `minifw-monday-education`), 10:52–11:15 WIB. Lab-only, fictional sandbox traffic.
- **Source.** `dist/v2213-c22-candidates/source.tar.gz`, SHA-256 `7184a003…963f`, commit `50058d10`.
- **The one change from C21 (`a9c87e93`).** In `main.py::evaluate_hard_threat`, the `pps_saturation` gate now requires `flow.packet_timing_available`, which only the packet sensor provides. Conntrack-measured flows can no longer trip it. One unit test was added.
- **C21 evidence.** All C21 results, and the "before" evidence for this gate, are in `../c21/`.
- **`results.json`** holds every number below.
- **Nothing secret is in this folder.**

| Check | Result | Key numbers | Evidence |
| --- | --- | --- | --- |
| Build on both VMs | **pass** | Tarball hash verified on each VM. `.deb` SHA-256 is `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` on **both** VMs; `cmp` says byte-identical. | `build/`, `dist/v2213-c22-candidates/SHA256SUMS` |
| Upgrade 2.2.12 → 2.2.13 | **pass** | `dpkg_rc=0`; `dpkg --verify` clean before and after; 0 postinst warnings. The policy conffile is unchanged (`ad580ecb…`), so there was no prompt. The commented `#MINIFW_AI_ENFORCE_MODEL_SHA256=` and `#MINIFW_AI_WINDOW_MODEL=` lines are still **1 each** after this second postinst, so they were not appended twice. runtime-health has `protection_state` and `ai_window`. Services are active. | `upgrade/` |
| Regression | **pass** | 659 passed (C21: 658, plus the new test), 11 warnings, 30 s | `regression/` |
| **F1 bulk "after"** | **pass** | Same 8 clients and transfers as the C21 "before" run. **No client was isolated in either pass**, and the engine logged 0 HARD_GATE lines. With MTU-sized segments, a 20 MB download at 4 MB/s peaked at 1709 pkt/s and a 2.5 Mbit/s stream at 265 pkt/s. On C21 both were isolated for 24 h at about 7 s; on C22 all 18.75 MB of the stream arrived. | `f1-bulk/` |
| Port scan still isolates (F1 control) | **pass** | The 15-port scan was isolated in 6.6 s, and a fresh scan in 3.3 s (`port_scan`, Hard Gate). The gate harness F1 test was also `port_scan`. `/admin/api/live-blocks` showed `trigger` "Hard gate (packet rate/burst/port scan)". | `lab/out/restartfb-c22/`, `gates/thursday/` |
| Restart false block (×1) | **pass** | Hand delete at 10:55:34, then Save and Apply 3.6 s later (HTTP 200/200); engine PID 135315 → 135417. At restart, conntrack held **15 ESTABLISHED flows on 15 ports**. Over the next 30.4 s the client had **86 events, all `allow`**, and was not re-blocked. | `lab/out/restartfb-c22/` |
| Baseline gates | **pass** | Both gates exited 0. The licence upload was valid; the tampered upload got 400. Save → Apply changed the timeout from 86400 to 11 s. The deny domain led to routed HTTP being blocked. The labelled corpus (8 captures, 240 requests) caused no isolation. F1 was `port_scan`. | `gates/` |
| AI boundary sanity | **pass** (same as C21) | **150 s runs:** 30/min no; 36/min 0/3; 37/min 0/4; **38/min 4/4** (82.7–86.0 s); 39/min 59.1 s; 60/min 38.8 s; the 1 s poller was isolated in 39.3 s; the exempt 1 s poller was not (n60 60, `shadow_only`). Every isolation was `ai_window_rate` with timeout 900 s. Polls came every 5.02–5.03 s. Dashboard rows with AI enhanced and approval: "AI enhanced" / "Enforcing in internal, guest, default". | `lab/out/R1/`, `lab/out/R2/`, `lab/out/rows-ai-approved.json` |
| Dashboard all-events exports | **pass** | CSV in 48.1 s (14.4 MB, about 119k lines, 9-column header); PDF in 114.9 s (10.2 MB, `%PDF` … `%%EOF`). **127.0.0.1 was not isolated**, and there were 0 hard-gate lines. On C21 it was re-added 25 times. | `lab/out/exportall/` |
| backup.sh / restore.sh on 2.2.13 | **pass** | Both returned rc 0, and services were active afterwards. Right after the backup, only `var/lib/minifw-ai/minifw.db` differed from its archive entry. A deliberate feed edit was reverted. All 33 entries matched after restore (env, db and licence checked in place). `dpkg --verify` clean, login OK, archive deleted. | `lab/out/backup-restore/` |

## Notes

- **Scripts.** `scripts/` holds copies of the C21 ones with the C22 paths: `c22_phase2.sh`, `boundary_c22.py` and `c22_gate_wrapper.py` (pin C18 → C22). The only behavioural change in `boundary_c22.py` is that `f1bulk` writes back the shipped policy and env when it finishes.
  - The `test` label inside `lab/out/backup-restore/results.json` still reads "C21 … 2.2.12", a string copied from the C21 driver. Its `package` field shows `2.2.13-finance`.
- **F1 bulk method** (as in `../c21/README.md`).
  - Shipped policy with only `segment_subnets.internal` + `10.10.0.128/25`; no approval; shipped state file (BASELINE); fresh engine.
  - Four clients ran at the same time to the lab HTTP server.
  - Pass A used the default veth offloads (TSO/GSO on). Pass B turned TSO/GSO/GRO off on all four veth ends, so segments were MTU-sized.
  - The max pkt/s figures come from conntrack counters sampled every 1 s over a 5 s window. Events do not carry a packet rate.

| Pass | Client | Transfer | Conntrack pkts | Max pkt/s (5 s) | C21 | C22 |
| --- | --- | --- | --- | --- | --- | --- |
| B | .155 | 20 MB paced 4 MB/s | 15239 | 1709 | **isolated 7.0 s, 24 h** | not isolated |
| B | .156 | 2.5 Mbit/s stream, 60 s | 15748 | 265 | **isolated 7.1 s, 24 h, stream cut** | not isolated, 18.75 MB complete |
| B | .154 | 20 MB unpaced | 15846 | – | not isolated | not isolated |
| B | .157 | 2 MB control | 2457 | – | not isolated | not isolated |
| A | .150–.153 | same four transfers | 148–1655 | ≤56 | not isolated | not isolated |

## Unexpected

1. **The Education VM (still 2.2.11) isolated the jump host's address 10.231.0.2 for 24 h with `pps_saturation` at 10:52:40.** That was while the C22 deb was being copied off the VM with scp (flow 10.231.0.2 → 10.231.0.15:22).
   - This is the F1 gate firing on a real virtio NIC from ordinary admin traffic.
   - The block was in the `forward` chain only, so SSH kept working.
   - It was deleted at 11:02:01 (`education-scp-block-cleanup.txt`).
   - Only the **finance** edition of C22 was built. The Education edition keeps this gate until an Education build from `50058d10` exists.
   - On the Financial VM, the journal since the C22 upgrade (10:53) has **0** `pps_saturation` lines, although several MB of evidence were pulled over SSH in that time. Under C21 (09:57–10:52) it had 218: 127.0.0.1 ×211 and the F1 clients ×7 (`pps-gate-journal-count.txt`).
2. **All-events exports are slow and get slower as events.jsonl grows:** CSV 48.1 s and PDF 114.9 s for about 119k events, against 25.4 s and 62.5 s at about 64k on C21.
3. **The running engine re-isolates a hand-deleted port scanner at its next poll** (1.0 s here) while it still tracks the scan flows. The same happens on C21; this is not the restart path.
4. **The gate harness leaves `minifw-ai` and `minifw-ai-web` stopped.** They were started again at 11:12.
5. **SSH through the jump host timed out a few times** ("banner exchange") during the 11:03–11:06 boundary runs while I polled every 10 s. Slower polling worked.
   - The cause was not investigated, because the jump host is out of scope.
   - The jump host runs its own pre-C22 MiniFW and relayed every multi-MB transfer of this session, so a `pps_saturation` block on it is possible. **Unverified: its block set should be checked by someone with that scope.**

## Final state (11:14:50 WIB, `final-state.txt`)

- **Financial VM, package.** `minifw-ai 2.2.13-finance`, `dpkg --verify` clean.
- **Financial VM, services.** `minifw-ai` and `minifw-ai-web` active; `dnsmasq` failed, as found.
- **Financial VM, policy.** SHA-256 equals the shipped one (`ad580ecb…`).
- **Financial VM, approval.** 0 active approval lines, 1 commented.
- **Financial VM, clean-up.** The `minifw_block_v4` set is empty. There are no lab netns and no running transient units. `/var/tmp/c2{1,2}/lab/orig`, the env copies, were removed. Only the pre-existing 3 Nov archive is in `/opt/minifw_ai/backups/`. Both lab brackets printed `RESTORED_MATCHES_PRE True []`.
- **Not restored.** `events.jsonl` (now 149,146 lines), the engine journal and the dashboard audit/DB entries keep today's lab events, logins and Save→Apply records, as on 5 Nov. That growth also slows the all-events exports.
- **Education VM** (`education-vm-state.txt`). `2.2.11-education`, services as before (`dnsmasq` failed, as found), block set empty, no netns. Only `/var/tmp/c21` and `/var/tmp/c22` were added (builds).

## Commands (from the Mac; each runs on the VM as root under systemd-run)

```bash
SSH="ssh -F ~/.ssh/minifw-lab/config minifw-lab-financial"   # Education: build only
$SSH 'sudo -n systemd-run --unit=c22-build ... bash /var/tmp/c22/scripts/c22_phase2.sh financial build|upgrade|regression'
# /var/tmp/c22/lab/boundary_c22.py: setup; restartfb restartfb-c22 0 no;
#   exportall; f1bulk A on; edit; run R1 main; rows ai-approved; run R2 replicas; f1bulk B off; restore; backuprestore backup-restore
$SSH 'sudo -n bash /var/tmp/c22/baseline/run_gates.sh financial /var/tmp/c22/src-current/build/minifw-ai_2.2.13-finance_amd64.deb'
```
