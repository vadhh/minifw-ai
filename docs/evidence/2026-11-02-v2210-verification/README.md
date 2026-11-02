# v2.2.10-only verification — 2 November 2026

The user's instruction restricts ongoing work to v2.2.10. No earlier package was installed, rebuilt or tested in this run. Product code and scoring thresholds were unchanged. The already corrected C3 candidates were verified in their separate dedicated QEMU VMs using the C4 acceptance fixtures.

| Edition | Installed version | Package SHA256 | Installed payload comparison | Fresh acceptance |
| --- | --- | --- | --- | --- |
| Financial | `2.2.10-finance` | `9b41450f697f22f878df6978c087ef521fd07e260153d5514d55896e6cbc68cb` | 163 application/model/edition-policy files match | Exit 0; 22 asserted result/scope records; 11:33:24–11:34:14 WIB |
| Education | `2.2.10-education` | `0935041d24aea3c776d3af4659af31b43072fe3084de11b62f4bb9f23d6ee742` | 163 application/model/edition-policy files match | Exit 0; 23 asserted result/scope records; 11:33:28–11:34:23 WIB |

The result counts include aggregate workflow and final scope records; they are not counts of independently validated protections. The earlier 546-test regression result was not rerun or counted as a fresh result here.

Verified again: actual kernel counter deltas; zero increments from repeated snapshots; immediate IPv4 client isolation on deny-domain matches; DNS decisions with quiet/missing flow collectors; flow-only port-scan decisions with DNS disabled/missing; actual forwarded HTTP timeout; no duplicate block events or expiry refresh; service-restart block retention; successful expiry/manual-unblock recovery; all four edition subnet selections; fictional Financial and Education workflows. Both scripts returned zero. Lab services were inactive and namespace lists empty after cleanup.

Observed gaps remain: alternate DNS, DoH, DoT, direct-IP and IPv6 tests were allowed; IPv6 also succeeded during client IPv4 isolation. SafeSearch, TLS-version enforcement, arbitrary VPN tunnel detection and live measured-feature model inference were not implemented or newly validated. No production-ready conclusion follows. The previous full-reboot persistence finding was not retested in this pass.

Evidence:

- [Financial identity](financial/identity.log), [commands](financial/acceptance.log), [results](financial/run/results.json), with sibling event/audit logs and `*.nft` snapshots.
- [Education identity](education/identity.log), [commands](education/acceptance.log), [results](education/run/results.json), with sibling event/audit logs and `*.nft` snapshots.
- [Read-only preflight](preflight.py) checks hostname, exact package hash, installed version, Debian name/version/architecture and installed payload bytes before acceptance begins.
- `SHA256SUMS` covers this evidence set. Private TLS keys, credentials, runtime databases and installer-private logs are excluded.

Commands, executed only inside the matching dedicated VM (Financial shown; Education uses its own edition/package):

```bash
sudo python3 /var/tmp/minifw-v2210-preflight.py financial /home/lab/minifw-ai-financial-v2.2.10-source-assessment/build/minifw-ai_2.2.10-finance_amd64.deb
sudo /opt/minifw_ai/venv/bin/python /var/tmp/lab_gateway_acceptance.py financial /home/lab/minifw-ai-financial-v2.2.10-source-assessment/build/minifw-ai_2.2.10-finance_amd64.deb > /var/tmp/minifw-v2210-verification.log 2>&1
```

The acceptance script, sandbox module and WebM fixture were copied adjacent under `/var/tmp`. Its native commands, actual IPs and kernel outputs are recorded in each edition's command log. Review the [consolidated requirement report](../../2026-11-02_correction-minifwai-report.md) for the complete unfinished-work matrix.
