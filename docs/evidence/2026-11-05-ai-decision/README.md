# 5 November lab evidence for the AI decision note

Supports `docs/2026-11-05_ai-decision-note.md`. All runs were executed 09:40–11:00 WIB on dedicated lab guests only: the two `minifw-monday-*` VMs and two new disposable `minifw-c19fresh-*` overlays. Lab traffic is fictional and is not evidence about a real Financial or Education client.

| Folder | What it shows |
| --- | --- |
| `fresh-install/` | C19 on clean Debian 12 guests (same base image hash as the C18 fresh check). Verifier output for both editions. |
| `licence/` | Dashboard activation of vendor-signed lab licences on the same fresh guests (`activate_fresh_licence.py`): valid, tampered copy rejected, still valid after a web restart. The licences were signed on the lab host, where the `minifw-vendor-2026` key is kept; before signing, its public half was checked against the packaged keyring. Only activation summaries are included, not the licence files or any key material. |
| `invalid-policy/` | A truncated policy file applied through the dashboard's apply call, run as `minifw-web`: failure message, restart loop, existing block retained, automatic recovery after correction. Simulates a damaged or hand-edited file. `health-banner-education.json` is inconclusive: the fresh guest has no DNS source, so `/health/` was already not ready before the fault. `warning-<edition>/` re-ran the outage on the configured Monday VMs with `lab_invalid_policy_warning.py` and shows the warning appearing and clearing, with Chromium screenshots. `warning-financial-failed-no-zeek-fixture/` is the first Financial attempt: it failed because no Zeek source was fed, and is kept as the record of that fixture fix. |
| `switch/` | `ai-enforcement-switch.patch` against C19 source (not in any candidate). `regression-*.txt`: 634 passed on each lab VM. `<edition>/results.json`: shadow, AI-caused kernel isolation, mismatched approval, and corrupt or missing model, using a **test-only always-threat model** and a lab policy copy with block threshold 30. |
| `corpus/` | Realistic-pace corpus per edition: actor logs (labels), gateway `flows.jsonl.gz` and `events.jsonl.gz`, pcap, and manifest. `analysis.json` and `rate-sweep.txt` hold the feasibility results. |
| `scripts/` | Every driver used. The root drivers refuse to run outside the named lab guests. |

## Reproducing the analysis

```bash
cd corpus && for f in */flows.jsonl.gz */events.jsonl.gz; do gunzip -k "$f"; done
python3 -I ../scripts/analyze_corpus.py education financial
```

## Limits

- The switch result shows only the enforcement mechanism. The test model is deliberately useless as a detector.
- The corpus is fictional. The server is HTTP/1.0 (one TLS connection per request), the users are scripted, and the sample is 8 users and 805 normal connections. It is not field representativeness.
- The packet sensor logs an ERROR traceback when the engine is stopped normally (tshark exit 0). This is cosmetic, but it may mislead someone reading the journal.
- Run-generated TLS server keys, the test-model pickle, administrator passwords and the private backup are not included.
