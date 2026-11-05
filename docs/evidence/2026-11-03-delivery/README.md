# Tuesday C16 evidence

Start with [the acceptance report](../../2026-11-03_acceptance-minifwai-report.md).
Recommendation: **HOLD**. Both editions fail the bounded legitimate-traffic control;
the combined load/log-failure outcome remains unresolved.

`education/` and `financial/` contain raw commands, logs, regression XML, final
state and `runs/` JSON/event/nft/resource evidence. `run-index.json` indexes test
records; a driver's exit zero is not a blanket acceptance claim. In particular,
`bounded_load_acceptance` and combined `isolated_disk_full` include failed outcomes.

`candidate-source-identity.json`, `release-inputs-final.patch`,
`artifact-verification.log` and `build-reproducibility.log` identify C16 exactly.
`source-identity.json`, `working-tree.txt` and `release-inputs.patch` are the earlier
triage snapshot, not the final build inputs. Existing user changes were preserved.

The Python scripts here are reviewable lab reproduction procedures. Destructive
scripts refuse hosts other than the dedicated Monday QEMU guests. Re-running
`lab_install_upgrade.py` also refuses to overwrite its private backup directory.
Do not run these against client systems. They are evidence tools, not new product
features. Original failures and subsequent fixes remain in the raw logs.

The independent disk-only probe verifies an empty block set before injection;
the earlier combined run does not establish that baseline. Its failure is retained
and remains open rather than being replaced by the isolated pass. The final
disk-only run also records actual full-filesystem bytes and dashboard HTTP status.

Private credentials, keys, runtime databases and backup archives remain on the
guests under `/var/tmp/minifw-tuesday-private-backup` (0700 root). Public evidence
exports exclude these artifacts. `SHA256SUMS` provides fixity, not authentication.
