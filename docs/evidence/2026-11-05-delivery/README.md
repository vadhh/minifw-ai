# Thursday execution evidence

Financial HOLD / Education HOLD. C19 is an operator-warning candidate with unchanged shadow-only AI. No model qualifies for enforcement.

Read the [daily Word report](../../2026-11-05_daily-work-report.docx) and [technical Word report](../../2026-11-05_acceptance-minifwai-report.docx). `acceptance-summary.json` distinguishes executed baseline gates from blocked/unrun AI gates. `SHA256SUMS` records fixity for this evidence tree; it is not a signature or an external reproduction claim.

- `session-baseline.json`, `workspace-status.txt`: repository/branch/commit and uncommitted state; archived source is the candidate identity.
- `c18-archive-verification.json`: rechecked historical handoff, including 404 checksum entries and all payload files.
- `hikari-download-manifest.json`, `hikari-pilot-result.json`: verified publisher inputs, actual archive contents, missing label-identity fields and zero accepted labels.
- `model-comparison.json`: final corrected 480-prefix diagnostic experiment, split manifests, all per-edition confusion counts, 14-feature parity and resource measurements. Session attack labels do not establish attack onset at a five-packet TLS prefix. Experimental models were not installed.
- `education/` and `financial/`: raw generated PCAPs, manifests, per-request outcomes, nft snapshots, regression XML/logs, upgrade/licence/application records and failed fixture runs. Paths use UTC timestamps; reports convert important times to WIB.
- Final C19 fault/recovery runs: Education `runs/minifw-monday-education-20261105T020433Z`, Financial `runs/minifw-monday-financial-20261105T020432Z`. `operator-browser/` contains actual 503/200 warning/recovery screenshots and viewport assertions. `final-state.json` records restored source formatting, clean package verification and cleanup.
- `fresh-education.json`, `fresh-financial.json`, `fresh-guest-manifest.json`: clean C18 installation and initial password-change checks, kept separate from C19 upgrade checks. New fresh guests have not undergone signed activation or a full routed gateway acceptance run.
- `c19-source-identity.json`, `artifact-verification.log`: C19 source derivation, declared one-file product change and package/source consistency.

The reproduction scripts are included here. Root traffic drivers are guarded to dedicated lab guest names; `create_fresh_guests.py` refuses an existing experiment directory. Never run these drivers on operational services or a client. `verify_fresh_install.py` expects initial password-change onboarding. `lab_fault_visibility.py` expects the original Wednesday fault driver at `/var/tmp/lab_c18_fault_original.py`; the parent evidence supplied in the handoff contains that file. Stage `browser_health_check.py` in `/var/tmp/` too. Use source and package identities from the manifests rather than a version string alone.

Initial incorrect fixture inputs remain: old-package preflight rejection, incomplete buffered PCAPs, health-path mismatches, browser API assertion and first-login redirect assumption. Corrected runs do not erase those failures. `lab_c19_dashboard.py` additionally restores original feed formatting; the executed original driver normalised ordering, which was subsequently restored after a semantic-equality check. No production behaviour was changed to force a pass.

Third-party data are referenced by pinned publisher URLs and checksums rather than redistributed in this archive. CC BY attribution belongs with any derived dataset/model. No private key, administrator password, browser session state, database, private backup or secret-bearing installer output is included. Lab traffic is fictional; it is not evidence that a real Financial/Education client has been qualified.
