# Tuesday standalone v2.2.10 acceptance

Recommendation: **HOLD production release; further correction before pilot acceptance.**
Financial and Education were assessed separately on the existing isolated Monday
QEMU guests. No ARCHANGEL or operational client system was changed. VPN expansion
was excluded. Candidate C16 corrects installer ownership and packaging; it does
not resolve the legitimate-traffic failure found below.

## Source and packages

Base: `e59ace4b228d3c6f14c32473fd8c462c9a84db1a`, clean Git export plus 13 declared
overlay inputs. [Source identity](evidence/2026-11-03-delivery/candidate-source-identity.json)
records all 463 files and the explicit LF conversion of 11 shell scripts.
The seven original tracked changes were preserved: five relevant application/build
inputs are included; the README licensing link and USB builder change are excluded
from this Debian-only candidate. Additional licensing inputs are declared.

Each edition was built natively on **both VMs**, as the unprivileged lab account,
using `SOURCE_DATE_EPOCH=1793664000 bash scripts/build_deb.sh SECTOR 2.2.10`.
Both independent builds produced identical hashes. Debian archive entries are
root-owned, including builds performed without root.

| Package | SHA256 |
| --- | --- |
| Education | `aae5a64cf65bc5facf30308294ee28b5b74c20cbacc2cbf2c75f342ef638a189` |
| Financial | `55d36aa58575d6705efa419afd766d21173013311cddff35ed09459cb5c3afa3` |

[Artifact verification](evidence/2026-11-03-delivery/artifact-verification.log)
checks the source against Git plus declared overlays and compares all **378 payload
files per package** against source or edition-specific unit expectations.
Packages/source are in `dist/v2210-c16-candidates/`. Version strings remain
v2.2.10: identify candidates by hash. C15 is historical evidence, not C16 acceptance.

## Implemented and verified

| Gate | Education | Financial | Evidence |
| --- | --- | --- | --- |
| Regression suite | 619 pass, 10 warnings | 619 pass, 10 warnings | Each edition's `minifw-c16-tests-final.log` and XML |
| Fresh package installation | Pass | Pass | Each edition's `minifw-c16-install-upgrade.log` |
| C13→C16 migration | Pass | Pass | Same logs: database integrity, exact admin row, policy bytes and licence-fixture bytes preserved |
| Root code ownership and write denial | Pass, fresh and upgrade | Pass, fresh and upgrade | Same logs: roughly 18,700 code/venv inputs checked; actual write-access probes as `debian` and `minifw-web` |
| Core routed enforcement and recovery | Pass | Pass | Each edition's `minifw-c16-core.log` and corresponding run directory |
| Operational health and restore | Pass | Pass | `minifw-c16-operational.log`: observed readiness, stopped engine, missing rule, quiet sensor, private backup/restore, log rotation |
| Dashboard least privilege | Pass | Pass | Operational logs: non-root uid, no effective/bounding capabilities, authenticated database/feed/policy smoke |
| Dashboard policy→engine action | Pass after restart | Pass after restart | `minifw-c16-propagation.log`: authenticated timeout change 11→13 seconds and deny-domain addition; actual kernel timeout and routed block |

All raw logs and selected per-run results/snapshots are under
[Tuesday evidence](evidence/2026-11-03-delivery/). The test harness uses temporary
namespace routing and collector locations; those adaptations are recorded rather
than represented as shipping configuration. Policy propagation proves a change
after an explicit engine restart, not automatic live reload.

The installer now repairs ownership before invoking installed Python, removes
group/other write access to executable inputs and later restores only intended
dashboard config access. The legacy `scripts/install_systemd.sh` exits unsupported.
Fresh installation here means fresh package/configuration/database state on an
existing Debian VM **with cached dependencies**, not a pristine OS or new dependency
download qualification. Previously writable dependency contents are not authenticated
by chown; suspected compromise requires a trusted rebuild.

## Failed or incomplete

**F1 — ordinary repeated HTTP traffic triggers the shared connection hard gate.**
At an offered five new HTTP connections/second for a nominal 60 seconds:

| Edition | Measured duration | HTTP successes | Failures | Client isolated |
| --- | --- | --- | --- | --- |
| Education | 61.280 s | 202 | 10 | Yes |
| Financial | 61.487 s | 203 | 10 | Yes |

Both runs fail the legitimate-traffic control. The event reason is
`flow_frequency` plus `hard_threat_gate_override`, owned by **Hard Gate**, not AI.
The shared default is 200 new connections in 60 seconds (`main.py`). Tests enabled
the optional packet sensor and used the existing lab policy timeout of 15 seconds.
This is a bounded fixture result, not an institution capacity benchmark. Resource
samples were retained; it is not prolonged-load qualification.

Owner: Afridho. Next correction must define acceptable connection-rate behavior
for legitimate clients, preserve demonstrated threat controls and rerun this same
probe plus attack controls in both editions. Do not conceal the failure by raising
a lab-only threshold. Correction estimate needs the confirmed rule/acceptance choice;
no unsupported delivery-time promise is made.

**F2 — full-log behavior after prior load is not accepted.** In the combined
load/fault runs, after the failed traffic control, a deny query produced no kernel
block and forwarded HTTP succeeded while the 64-KiB test filesystem was full.
Independent disk-only reruns began with an explicitly empty block set and a
successful legitimate HTTP control; they did create the deny block despite real
ENOSPC errors. Both measured zero free bytes and a zero-byte event log; dashboard
login returned HTTP 200 and health returned 503. Both restored HTTP after removing the fault and explicitly restarting
the engine. The passing isolated case does not erase the failed combined case.
Owner: Afridho; investigate accumulated state and fault sequencing before claiming
general enforcement continuity under storage failure. Scope: full event-log
filesystem, not the root disk, database disk or every possible write failure.

Other incomplete gates: real signed licence activation, representative external
institution traffic, approved AI quality data and contractual acceptance of
advisory-only AI. The migration licence was a labelled byte-preservation fixture.
AI remains shadow-only; no model effectiveness claim is made.

## Retained failures and test corrections

- Initial regression collection failed because two tracked `tools/` helpers were
  omitted from the export. They were included before the 619-test reruns; the
  initial log remains.
- Initial propagation probes incorrectly requested a `/var/tmp` collector location
  through the dashboard. The application correctly rejected it. The final harness
  sets collector fixture paths directly as lab root; timeout and deny-domain changes
  still go through authenticated dashboard requests.
- An initial propagation cleanup assertion masked that response and left a modified
  policy. Cleanup was corrected, a distinct before/after timeout was required, and
  final fixture configuration is reset to package contents.
- The first Financial load run stopped at its failed traffic assertion. A subsequent
  run retained that failure and proceeded to the independent fault observations.
- Combined load/fault and independent disk-only outcomes are reported separately.

Private state backups and credential-bearing installer logs remain root-protected
on each guest, outside the public evidence bundle. Raw public results retain their
original text. Services and temporary lab networking are stopped/cleaned at handoff.

## Release scope and next action

Keep production **HOLD**, correct F1 and investigate F2, then rerun affected gates
against a new hashed candidate. Ownership, reproducible packaging and Financial
migration gaps are now supported by direct evidence. Broad VPN/DoH feature work,
VPN-server/device binding and ARCHANGEL integration remain outside this assignment.
The [task record](2026-11-03_delivery-tasks.md) also contains the AI dataset specification.
