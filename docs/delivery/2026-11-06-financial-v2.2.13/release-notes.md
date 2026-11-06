# MiniFW-AI Financial v2.2.13: release notes

| Item | Value |
| --- | --- |
| Edition | Financial (`minifw_financial`) |
| Version | 2.2.13 |
| Source commit | `50058d10` |
| Installer | `minifw-ai_2.2.13-finance_amd64.deb`, SHA-256 `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` |
| Connection-rate AI model | `client_window_v1.json`, SHA-256 `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` |
| Previous public release | v2.2.10 (26 October 2026) |
| State at handover | Connection-rate AI in shadow mode (isolation off); rule blocks on. The site turns AI isolation on after the shadow period (setup guide, sections 14–15). |

Read with the setup guide and the recovery procedure.

## What changed since v2.2.10

### Detection and enforcement

- **Measured connection data.** Connection-tracking samples keep each connection's original client, destination and ports, with separate counters for each direction. The engine turns on connection-tracking accounting at start, so rates come from measured counters rather than estimates.
- **Deny-listed domains isolate the client.** A DNS query for a deny-listed domain blocks that client's forwarded IPv4 traffic for 24 hours.
- **Restarts no longer re-block.** After an engine restart, including dashboard **Apply saved changes**, connections that were already open are treated as existing. They no longer count as new connections or as port-scan ports, so a client is not blocked again from old connections. A real scan after the restart still blocks.
- **No more 24-hour blocks for ordinary downloads.** The packet-rate gate (more than 200 packets a second on one connection) now runs only with a packet sensor, as the burst and packet-timing gates already did. On connection-tracking data, one ordinary download or stream faster than about 2.3 Mbit/s could trip it and block the client for 24 hours. In the lab this happened to a 20 MB download and a 2.5 Mbit/s stream with full-size packets.
- **Optional packet sensor.** With `MINIFW_PACKET_INTERFACE` set, the engine reads packet metadata (no payload). That enables the packet-rate, burst and timing gates, TLS minimum-version policy and WireGuard pattern detection. The packet-based model stays in shadow mode and never blocks.

### New: connection-rate AI (`client-window-v1`)

- It counts new TCP connections from one client to one server and port within 60 seconds. It isolates the client for 15 minutes when the count is high enough: in the lab, about 37–40 new connections a minute or more.
- It is off until the site approves it. Isolation requires all of these:
  - the exact model hash in `/etc/minifw/minifw.env`;
  - the client's segment listed in the policy's `ai_enforcement.segments`;
  - the client not listed in `exempt`.

  Until then it scores in shadow mode only.
- Each event records the AI's count, probability and mode (`not_run`, `shadow_only` or `enforcing`). `enforcing` means the model is approved and this client is in AI scope.
- An AI block is credited to "AI Engine (client window)" in events, exports and the dashboard.

### Dashboard

- Runs as an unprivileged `minifw-web` user. It does not follow symbolic links in folders that user can write to.
- **Apply saved changes** restarts the engine with the saved policy and feeds.
- A warning banner shows when engine inputs stop reporting.
- The **Firewall Status** card shows the real detection mode (AI-enhanced or baseline) and the connection-rate AI status (enforcing, shadow only, model missing, or off). Both are read from the engine's health file.
- Labels describe what triggered each decision ("Deny-list domain match", "Hard gate", "AI connection-rate isolation (15 min)"). Earlier invented labels and a randomly generated "time to block" figure are removed. Status comes from the engine's actual action, not from score bands.
- MLP and YARA appear as score contributors ("Policy score (MLP contributed)"), not as the deciding engine.
- CSV and PDF exports label the score "Score (all signals, 0-100)", not "AI Score". They add decision-owner and AI-mode columns, and mark the kernel status as status at export time.
- Domain names, sources and reasons are escaped before display. Before this, a crafted DNS name from a LAN client could inject script into the admin's browser.

### Operations

- The engine's JSONL logs are rotated by a packaged logrotate policy.
- `backup.sh` and `restore.sh` work on this version. A backup restores only onto the same version and edition. The version shipped before this one could not back up or restore at all.
- Upgrades add the commented AI approval lines to `/etc/minifw/minifw.env` if they are missing. Upgrades and the engine both warn when the policy in use has no `ai_enforcement` block.
- If an `ai_enforcement.exempt` entry is invalid, the AI isolates nobody, and the engine says so at start.

## Known limitations

**Connection-rate AI**

1. **It counts connections, not passwords.** It does not see logins or failed attempts. Several attempts over one connection count once. Clients slower than about 37 new connections a minute are not caught; 30–36 a minute was never isolated in the lab.
2. **Benign automation looks the same.** A poller opening a new connection every second was isolated after about 40–44 seconds. Servers, monitoring and polling systems, proxies and shared NAT addresses must be listed in `exempt` before isolation is turned on. Pollers that reuse one connection are not affected.
3. **It runs only in AI-enhanced protection,** which needs a healthy DNS log. With no DNS query for about two minutes (a quiet network, for example at night), the engine falls back to baseline and the AI pauses. It resumes about one to one and a half minutes after queries return.
4. **A shared address is one client.** Clients behind a shared NAT address count together.
5. **Lab evidence only.** All AI results come from a lab with scripted clients. There is no measured false-isolation rate on a real network. A shadow period of a few days before approval is recommended.

**Enforcement scope**

6. **Forwarded client IPv4 only.** IPv6 clients are scored but not blocked. Traffic to the gateway's own services is not blocked.
7. **Address spoofing.** A LAN device that forges a neighbour's address can get that neighbour isolated: 15 minutes by the AI, or 24 hours by the port-scan rule. Use anti-spoofing on the access switches (DHCP snooping with IP source guard).
8. **Blocks live only in the kernel.** A reboot clears them. An nftables `flush ruleset` removes the MiniFW-AI table until the engine restarts.
9. **Without a packet sensor (the default),** the packet-rate, burst and timing gates, TLS minimum-version policy and WireGuard detection do not run. The MLP model also needs packet timing, so it does not run either.
10. **Domain matching needs the DNS log** (and Zeek SNI where a sensor exists). The Financial policy ships with Zeek SNI on. Without a Zeek sensor the dashboard warning banner stays until it is turned off (setup guide, section 13).
11. **Rule blocks have no per-client exception.** The exempt list affects only the AI.

**Operations**

12. **Manual changes are not audited.** `ai_enforcement` has no dashboard editor and is edited by hand as root. Subnet edits from the dashboard and hand-made `nft` deletions are not written to the audit log.
13. **Dashboard access and certificate.** The dashboard listens only on `127.0.0.1:8443`, so it needs an SSH tunnel. Its self-signed certificate lasts 365 days, and there is no renewal step yet.
14. **The installer changes the host.** It needs internet access to PyPI, and it stops and disables CUPS. Do not run `uninstall.sh` on a working gateway: it removes the dnsmasq settings and stops dnsmasq.
15. **Backup limits.**
    - A backup does not include `/var/lib/minifw-ai/installation-id`, so keep a private copy.
    - A backup restores only onto the same version.
    - After a rollback to the previous version, its own restore tool cannot be used.
16. **Log rotation covers only the engine's JSONL logs.** `/var/log/dnsmasq.log` and backups are not rotated by this package.
17. **Large exports are slow.** An all-events PDF of about 64,000 events took about 60 seconds in the lab.
18. **Licences cannot be revoked** by the product.

## Test summary

All results come from the vendor's lab on 6 November 2026: two Debian 12 VMs, scripted clients, and a lab server. The vendor keeps the raw evidence and can provide it on request. Version 2.2.12, mentioned below, was an internal test build and was not released.

| Check | Result on 2.2.13 |
| --- | --- |
| Reproducible build | The same installer, byte for byte, built on two VMs |
| Upgrade from 2.2.12 | Install succeeded, `dpkg --verify` clean, policy kept, approval comments added once, services active |
| Regression suite on the gateway | 659 passed, 0 failed |
| Large downloads and streams with full-size packets (20 MB at 4 MB/s, 2.5 Mbit/s stream, 20 MB unpaced, 2 MB) | None isolated. On 2.2.12 the first two were isolated for 24 hours. |
| Large dashboard exports (14 MB CSV, 10 MB PDF) | Exporting address not isolated |
| Port scan | Isolated in 6.6 s; again in 3.3 s after a manual unblock |
| Restart with open connections (Apply) | No re-block (also 3 of 3 runs on 2.2.12) |
| Connection-rate AI boundary, 150 s runs | 36/min 0 of 3, 37/min 0 of 4, 38/min 4 of 4 (about 80-86 s), 39/min 59 s, 60/min 39 s |
| Benign poller, one new connection a second | Isolated in about 39 s; not isolated when exempt |
| Baseline gates | Licence valid; tampered licence rejected; Save → Apply changed enforcement; deny-listed domain isolated the client; labelled normal traffic not isolated |
| Backup and restore | Both succeeded; all archive entries matched after restore; login worked |
| Shadow review command (setup guide, section 14) | Read 171,188 events from the current, rotated and compressed logs in about 2 s; listed the two lab clients that crossed the isolation point |

Checked on 2.2.12, unchanged in 2.2.13:

- With no `ai_enforcement` block, the engine warned and the client stayed in shadow mode at 60 connections a minute.
- The dashboard status rows matched the engine in baseline and in AI-enhanced, enforcing states.
- No invented labels appeared.
- CSV and PDF exports parsed with the new columns.
- HTML escaping was checked by code review only.

A second engineer then repeated the main checks independently on a clean Debian 12 guest, with the same results. The checks covered:

- installation, first login, licence and Save → Apply;
- recovery after a kill and a reboot, and backup and restore;
- AI isolation, its 15-minute expiry, and exemptions;
- restart behaviour and large downloads;
- a full log volume;
- loss and return of DNS;
- a missing or corrupt model.
