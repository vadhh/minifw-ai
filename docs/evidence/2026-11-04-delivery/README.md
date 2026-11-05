# Wednesday C18 evidence

Production decision: **HOLD for both editions**. F1/F2 correction and bounded
acceptance pass. Required AI participation in enforcement is still unaccepted.

Start with [Wednesday acceptance](../../2026-11-04_acceptance-minifwai-report.md)
or [the management report](../../2026-11-04_daily-work-report.md).

`acceptance-summary.json` indexes results without the 300 individual request rows;
the raw `bounded-load.json` in each run retains every scheduled/start/finish time
and outcome. `education/` and `financial/` contain original logs, regression XML,
nft snapshots, events and final-state records. Initial fixture failures remain.

`baseline-archive.json` records the independently checked C16 management archive.
`candidate-source-identity.json` records C18's 468 source/fixture files and its
declared changes from C16. `artifact-verification.log` checks every one of the 381
payload files per edition against source or exact unit transformations. C16 input
hashes precede its declared LF conversions; Wednesday inputs hash the final bytes.
Both independent VM builds agree in `minifw-c18-package-hashes.log`.

`lab_c16_combined_diagnosis.py` reproduces the original combined sequence, including
the lack of a pre-fault block-set flush. `f2_sitecustomize.py` and
`lab_c16_instrumented.py` add temporary lab-only traces; they are never packaged
into the product. The decision trace records a consumed deny query, block decision,
then `ipset_add=False`. `lab_block_expiry.py` isolates that expiry bug without any
storage failure, using a separate unhooked nft table, on both guests.

`lab_candidate_fault.py` tests 300 scheduled HTTP requests and the full-log case
with event and flow writes both on the full filesystem, 30 additional HTTP
requests, stable engine PID/zero automatic restarts, and a deliberately older
two-second kernel block. The newer deny must still block
four seconds later. The full filesystem is a disposable 64-KiB tmpfs; the root and
database filesystems are untouched. This reproduces the original restart-based
fault setup; it does not establish uninterrupted operation for every disk failure.

`lab_dashboard_activation_apply.py` uses the existing vendor keyring and real
vendor signatures for the two lab deployment IDs. It uploads through the actual
dashboard API, rejects tampering, verifies persistence, then saves a timeout/feed
change and applies it through the dashboard restart endpoint. Collector fixtures
are selected by lab root before the save; there is no root restart after the save.
`browser_apply_check.cjs` verifies the rendered Education control and keyboard
activation at 1280×900 and 390×844. Credentials arrive only on stdin. Its screenshots
and `browser-check.json` are public; no browser session state is exported.

Guarded drivers refuse any hostname except the dedicated Monday QEMU guests and
require root/virtualization checks. `lab_install_candidate.py` refuses to overwrite
its private backup directory. Re-running acceptance changes disposable lab state;
never run these procedures on a client or the host's operational services.

Private installer output, original database/configuration backups and signing keys
are excluded. The signed lab licences remain installed on the guests. Services
are stopped, temporary networking is removed, and `dpkg --verify minifw-ai` is clean
after restoring fixture configuration. The apply path remains enabled for next boot.
`SHA256SUMS` supplies file fixity, not publisher authentication.

C17 was an intermediate candidate. Its event-only success, source identity and
original logs remain. 'local-full-volume-before.log' and Education's
'minifw-c17-full-volume-before.log' retain the subsequently found export failure.
The final C18 results cover that shared-volume case; C17 is superseded.
