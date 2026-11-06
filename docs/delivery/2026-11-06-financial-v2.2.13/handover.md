# MiniFW-AI Financial v2.2.13: handover

| Item | Value |
| --- | --- |
| Product | MiniFW-AI, Financial edition (product mode `minifw_financial`) |
| Version | 2.2.13 |
| Handover date | 6 November 2026 |
| Installer | `minifw-ai_2.2.13-finance_amd64.deb`, SHA-256 `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` |
| Connection-rate AI model | `client_window_v1.json` (inside the installer), SHA-256 `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` |
| Source commit | `50058d10` |

## What is in this package

| File | What it is |
| --- | --- |
| `minifw-ai_2.2.13-finance_amd64.deb` | The installer |
| `SHA256SUMS` | Checksums of every file in this package |
| `handover.pdf` | This document |
| `setup-guide.pdf` | Installation and configuration, step by step |
| `recovery-procedure.pdf` | Unblocking, turning the AI off, backup, restore and rollback |
| `release-notes.pdf` | Changes, the 18 known limitations, and the test summary |
| `policy/policy.json` | The tested Financial policy. The installer ships the same file. |

Before you install, check the files:

```bash
sha256sum -c SHA256SUMS
```

Every line must end in `OK`.

## State at handover

- **Rule blocks are on from day one.** A client that looks up a deny-listed domain or scans ports is blocked for 24 hours.
- **The connection-rate AI runs in shadow mode.** It scores every client but isolates nobody until your site approves it (setup guide, section 15).
- **The exempt list is empty.** Your servers, monitoring and polling systems, proxies and shared NAT addresses are not yet known. If isolation were on, a system that opens about one new connection a second would be isolated within about 40 seconds.

## Your steps

1. Check the files (above).
2. Install and open the dashboard: setup guide, sections 4 to 9.
3. **Licence.** Copy the deployment ID from the dashboard's **License** page and send it to us privately (setup guide, section 10). Do not post it in public tickets, chat channels or code repositories. We sign a licence for that deployment ID and return it privately. Until it is installed, the page shows **Unlicensed**; protection keeps working.
4. Replace the example subnets with your own: setup guide, section 11.
5. Turn on DNS query logging and confirm AI-enhanced protection: sections 7 and 13.
6. **Shadow period, a few days.** Once a day, list the clients the AI would have isolated (section 14). Add legitimate automation to the exempt list (section 12).
7. **Turn on AI isolation** when your site approves it: section 15. Record who approved it and when. The first time a client is isolated, confirm the block ends after 15 minutes.

## Tested policy

`policy/policy.json` is the policy used in the vendor's tests. It ships with these settings:

- **Segments:** `internal`, `guest`, `trading` and `dmz`. Their subnets are examples, so replace them (setup guide, section 11).
- **AI scope:** `internal`, `guest` and `default`. `trading` and `dmz` are out of AI scope.
- **AI exempt list:** empty.
- **AI isolation time:** 15 minutes. Rule blocks last 24 hours.

## Known limitations

All 18 are in the release notes. The most important:

1. **Connections, not passwords.** The AI counts new connections from one client to one server and port. It does not see logins or failed passwords, and clients slower than about 37 new connections a minute are not caught.
2. **Benign automation.** A poller opening a new connection every second looks the same as an attack, so it must be exempt before isolation is turned on.
3. **DNS needed.** The AI runs only while the DNS log is healthy. With no DNS query for about two minutes, the engine falls back to rule blocks only.
4. **Forwarded client IPv4 only.** IPv6 clients are scored but not blocked. A reboot clears active blocks.
5. **Address spoofing.** A device that forges a neighbour's address can get the neighbour isolated. Use anti-spoofing on the access switches.
6. **Lab evidence only.** No false-isolation rate has been measured on a real network. That is why the shadow period comes first.

## Receipt

Please complete and return this page.

| | Customer | Vendor |
| --- | --- | --- |
| Name | | |
| Organisation | | |
| Date | | |
| Checksums all `OK` | ☐ Yes ☐ No | ☐ Checked before sending |
| All documents and the policy received | ☐ Yes ☐ No | |
| Signature | | |
