# 5 November C20 evidence: client-window AI enforcement (v2.2.11)

Supports `docs/2026-11-05_end-of-day-report.md`. Lab-only, fictional sandbox traffic on the two `minifw-monday-*` VMs.

| Folder | What it shows |
| --- | --- |
| `model/` | Training and evaluation scripts, training report, and `manifest.json`. The manifest fixes the model hash and the held-out acceptance rule; it was written at 15:41 WIB, before any held-out data existed. |
| `heldout/` | Held-out corpus collected 15:42–15:53 with the shipped conntrack collector: actor logs (the labels), gateway events and flows, and the manifest. |
| `heldout-eval/` | First-flow-event records from `scripts/events_to_flows.py`, and `evaluation.txt`, the frozen evaluator's PASS output. |
| `build/` | C20 build logs on both VMs (byte-identical debs), the upgrade from C19, and the regression run (645 passed per edition). |
| `acceptance/` | AI scenarios per edition: shadow, approved isolation, other-model approval, corrupt or missing model, restart. Includes nft snapshots and event extracts. |
| `scripts/` | Held-out corpus driver and client, the events adapter, and the C20 acceptance driver. Root drivers refuse to run outside the named lab guests. |

No keys, licence files or admin passwords are included. The pcaps stay on the lab VMs; their hashes are in the manifests.
