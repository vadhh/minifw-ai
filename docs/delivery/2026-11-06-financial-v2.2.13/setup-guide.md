# MiniFW-AI Financial v2.2.13: setup guide

| Item | Value |
| --- | --- |
| Product | MiniFW-AI, Financial edition (sector `finance`, product mode `minifw_financial`) |
| Version | 2.2.13 (candidate C22) |
| Source commit | `50058d10` |
| Installer | `minifw-ai_2.2.13-finance_amd64.deb` |
| Installer SHA-256 | `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` |
| Connection-rate AI model | `/opt/minifw_ai/models/client_window_v1.json`, SHA-256 `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee` |

This guide covers a new installation. Every command runs as root, so it starts with `sudo`.
Example addresses come from the documentation range `192.0.2.0/24`. Replace them with your own.
Values in angle brackets, such as `<gateway-address>`, are placeholders.

The companion document `recovery-procedure.md` covers unblocking, turning the AI off, backup, restore and rollback.

---

## 1. Where MiniFW-AI runs and what it can block

- It uses a single network interface. It runs on the site's existing Linux router or gateway (Debian 12, amd64). It is not a separate box placed in line between two networks.
- The host must already route (and, if needed, NAT) between the client networks and the internet. MiniFW-AI does not set up routing.
- dnsmasq on this host must resolve DNS for the protected clients. Its query log is the main input to the engine.
- Enforcement uses the nftables `forward` chain. A blocked client's address goes into the set `minifw_block_v4` in table `inet minifw`, and a rule drops packets from addresses in that set.
- So it only drops traffic that this host routes: forwarded client IPv4. It does not block IPv6. It does not block traffic to the gateway's own services.
- Blocks exist only in the kernel. A reboot clears them. The engine re-creates the table and rule when it starts.

## 2. Protection states

The engine has two protection states.

| State | When | What runs |
| --- | --- | --- |
| AI-enhanced protection | The DNS log is healthy | Rules, threat feeds, hard gates, and the AI |
| Baseline protection | The DNS log is not healthy | Rules, threat feeds and hard gates keep enforcing. The AI does not run. |

Hard gates on a gateway without a packet sensor (the default): the port-scan gate runs. The packet-rate, burst and packet-timing gates need real packet timing from a packet sensor (`MINIFW_PACKET_INTERFACE`), so they do not run on connection-tracking data alone. A fast download or stream therefore does not trip them.

- "Healthy" means dnsmasq wrote a DNS query line in the last 60 seconds.
- The engine checks every 30 seconds. After 2 failed checks it switches to baseline protection. After 3 good checks in a row it switches back to AI-enhanced protection.
- Domain deny-list matching takes domain names from DNS log lines (and from Zeek SNI, if a Zeek sensor exists). While the DNS log is missing, DNS-based domain matches cannot happen. Address-based feeds and hard gates are not affected.
- A quiet network also counts as unhealthy. If no client makes a DNS query for a minute (for example at night), the engine drops to baseline. It returns by itself when queries resume.
- The current state is saved in `/opt/minifw_ai/logs/deployment_state.json` and survives engine restarts.

The dashboard's **Firewall Status** card shows two rows read from the engine's runtime health:

| Row | Text | Meaning |
| --- | --- | --- |
| Detection Mode | `AI enhanced` | DNS log healthy; the AI runs |
| Detection Mode | `Baseline (AI off: DNS log not healthy)` | Baseline protection |
| Detection Mode | `Unknown (engine not reporting)` | The engine is not running or not writing its health file |
| Connection-rate AI | `Off (baseline)` | Baseline protection; the AI does not run |
| Connection-rate AI | `Model missing` | The model file is missing or was rejected |
| Connection-rate AI | `Shadow only (model not approved)` | The AI scores but never isolates |
| Connection-rate AI | `Shadow only (approved, no segments in policy)` | Approved, but the policy gives the AI no segments, or an exempt entry is invalid |
| Connection-rate AI | `Enforcing in internal, guest, default` | The AI may isolate clients in the listed segments |

## 3. The connection-rate AI

### What it measures

- It counts new TCP connections from one client to one server and port within 60 seconds.
- It does not see passwords, logins or failed attempts. A tool that sends many requests over one connection is counted once.
- The model isolates a client when that count reaches 39 or more in its 60-second window.
- An AI block lasts 15 minutes. Rule blocks (for example a deny-listed domain or a port scan) last 24 hours.

### Lab results

These come from a lab with fictional traffic, not from your network.

- Clients were isolated at about 37-40 new connections a minute or more. 38 a minute was isolated in every run. 37 a minute was isolated in 1 of 3 five-minute runs (after 104 seconds). The exact point depends on the 5-second connection-tracking reads.
- Clients at 30-36 new connections a minute were never isolated.
- A benign poller opening a new connection every second was isolated after about 40-44 seconds.
- A poller reusing one kept-alive connection was not isolated.
- A poller listed as exempt was not isolated.

Benign automation at about one new connection a second looks the same as an attack to this AI. That is why the exempt list (section 12) and a shadow period (section 14) matter.

### When it may isolate a client

The AI isolates a client only when all of these hold:

1. `/etc/minifw/minifw.env` contains `MINIFW_AI_ENFORCE_MODEL_SHA256` equal to the SHA-256 of `/opt/minifw_ai/models/client_window_v1.json` (`d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee`).
2. The client's segment is listed in the policy's `ai_enforcement.segments`. Financial ships `internal`, `guest` and `default`. `dmz` and `trading` are out of scope.
3. The client is not in `ai_enforcement.exempt`.

The code also requires:

4. The engine is in AI-enhanced protection.
5. The client address is IPv4.
6. Every entry in `ai_enforcement.exempt` is a valid address or network. One invalid entry turns AI isolation off for every client, and the engine logs a warning at start.
7. The rules have not already blocked the client.

Otherwise the AI scores in shadow only. Each event records `ai_window_mode` (`not_run`, `shadow_only` or `enforcing`) and `ai_window_probability`.

We recommend a few days in shadow mode first, reviewing which clients would have been flagged (section 14).

---

## 4. Before you start

You need:

1. A Debian 12 amd64 host that already routes for the client networks, and root access to it.
2. dnsmasq on that host, resolving DNS for the protected clients (clients get this host as their DNS server).
3. Internet access to PyPI during installation. The installer runs `pip install` for the Python dependencies. Without access, the installation fails.
4. The package dependencies: `python3` (3.10 or later), `python3-venv`, `nftables`, `openssl`, `conntrack`, `logrotate`, `adduser`. `dnsmasq` and `zeek` are only recommended, not required. Installing with `apt` (section 6) pulls in the dependencies.
5. Decisions from the site:
   - Which subnets belong to which segment (`internal`, `guest`, `trading`, `dmz`).
   - Which addresses the AI must never isolate: servers, monitoring and polling systems, proxies, and shared NAT addresses.
   - Who approves turning AI isolation on, and how long the shadow period lasts.
6. Anti-spoofing on the access switches (DHCP snooping with IP source guard). See section 18.

The installer also changes the host:

- It stops and disables the CUPS print services (`cups`, `cups-browsed`).
- It loads the `nf_conntrack` kernel module and adds `/etc/modules-load.d/minifw-conntrack.conf`.
- If Grafana is installed, it binds Grafana to `127.0.0.1` and restarts it.
- If Zeek is installed, it adds the SSL log to Zeek's site config and runs `zeekctl deploy`.
- It creates a system user `minifw-web` (no login) for the dashboard.

## 5. Check the installer

```bash
sha256sum minifw-ai_2.2.13-finance_amd64.deb
```

The output must start with `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9`. If it does not, stop and contact the vendor.

## 6. Install

1. Install the package:

   ```bash
   sudo apt install ./minifw-ai_2.2.13-finance_amd64.deb
   ```

2. Watch the output. It prints the initial admin password once, in a line like `*** ADMIN PASSWORD: ... ***`. Save it in your password manager. It is also stored in `/etc/minifw/minifw.env`, which only root can read.

3. Check the result:

   ```bash
   dpkg-query -W -f='${Version}\n' minifw-ai
   systemctl is-active minifw-ai minifw-ai-web minifw-ai-apply.path
   systemctl show -p Environment minifw-ai | tr ' ' '\n' | grep -E 'MINIFW_SECTOR|PRODUCT_MODE|MINIFW_POLICY'
   sudo nft list chain inet minifw forward
   ```

   Expected:
   - Version `2.2.13-finance`.
   - `active` three times.
   - `MINIFW_SECTOR=finance`, `PRODUCT_MODE=minifw_financial` and `MINIFW_POLICY=/opt/minifw_ai/config/modes/minifw_financial/policy.json`.
   - A rule containing `ip saddr @minifw_block_v4` and `drop`, with the comment `MiniFW-AI-Blocklist`.

The policy the engine and dashboard use is `/opt/minifw_ai/config/modes/minifw_financial/policy.json`. This guide calls it "the policy file".

## 7. Turn on DNS query logging

The policy reads DNS queries from `/var/log/dnsmasq.log` (`collectors.dnsmasq_log_path`).

1. Check whether dnsmasq already logs queries:

   ```bash
   grep -E '^(log-queries|log-facility=)' /etc/dnsmasq.conf
   ```

2. If either line is missing, add it to `/etc/dnsmasq.conf`:

   ```text
   log-queries
   log-facility=/var/log/dnsmasq.log
   ```

3. Restart dnsmasq and check the log:

   ```bash
   sudo systemctl restart dnsmasq
   sudo tail -n 3 /var/log/dnsmasq.log
   ```

   You should see lines containing `query[A] <name> from <client address>`.

If you use a different log path, set the same path in the dashboard under **Policy Configuration → Data Collectors → DNSmasq Log Path**.

**Warning about the helper script.** The package includes `/opt/minifw_ai/scripts/enable_dnsmasq_logging.sh`. The installer does not run it. On an existing gateway, do not run it without reading it first. It:

- deletes existing `interface=` and `bind-interfaces` lines in `/etc/dnsmasq.conf` and replaces them with the first active wired interface it finds;
- adds the upstream servers `8.8.8.8` and `8.8.4.4` if no `server=` line exists;
- disables the systemd-resolved stub listener and rewrites `/etc/resolv.conf`.

Adding the two lines by hand, as above, changes nothing else.

Do not run `/opt/minifw_ai/scripts/uninstall.sh` on a working gateway either. It removes those dnsmasq lines and stops and disables dnsmasq, which stops DNS for the clients.

## 8. Open the dashboard

The dashboard listens only on `127.0.0.1:8443` on the gateway. It is not reachable from the network directly.

1. From an admin workstation, open an SSH tunnel to the gateway:

   ```bash
   ssh -L 8443:127.0.0.1:8443 <admin-user>@<gateway-address>
   ```

2. Browse to `https://localhost:8443`.

3. The certificate is self-signed and valid for 365 days from installation, so the browser warns. To check that you reach the right host, compare the browser's certificate fingerprint with:

   ```bash
   sudo openssl x509 -in /etc/minifw/tls/server.crt -noout -fingerprint -sha256 -enddate
   ```

## 9. First login

1. Log in as `admin` with the initial password from section 6. If you lost it:

   ```bash
   sudo grep '^MINIFW_ADMIN_PASSWORD=' /etc/minifw/minifw.env
   ```

2. The dashboard sends you to a password change page. You cannot use other pages until you change the password. The new password must:
   - have at least 8 characters;
   - be no longer than 72 bytes;
   - differ from the current password.

3. After the change you are logged out. Log in again with the new password.

The env file still contains the initial password. It no longer works for login once you have changed it.

## 10. Licence

1. In the sidebar, under **ADMINISTRATION**, open **License**. You need an admin account.
2. Copy the **Deployment ID**. It is created the first time this page opens and stored in `/var/lib/minifw-ai/installation-id`.
3. Send the deployment ID to the vendor privately. Do not post it in public tickets, chat channels or code repositories.
4. The vendor returns a signed licence file (JSON, at most 64 KiB). It is bound to this deployment ID and to product mode `minifw_financial`.
5. On the **License** page, choose the file under **Install or renew license** and press **Install license**.
6. Check that the status reads **Valid**.

Notes:

- Other statuses: **Grace** (up to 14 days after expiry), **Expired**, **Invalid** (with a reason, for example a different deployment), **Unlicensed**.
- The page states: "License status never stops firewall enforcement."
- Keep a private copy of `/var/lib/minifw-ai/installation-id` off the gateway. The backup tool saves the licence file but not this file (see the recovery procedure).

## 11. Map segments to your subnets

The shipped `segment_subnets` are examples. Replace them with your real subnets.

| Segment | Shipped example | AI may isolate here |
| --- | --- | --- |
| `internal` | `192.168.1.0/24`, `10.0.0.0/8` | Yes |
| `guest` | `192.168.100.0/24` | Yes |
| `trading` | `10.50.0.0/24` | No |
| `dmz` | `10.10.0.0/24` | No |
| `default` | any address not listed above | Yes |

How a client gets its segment:

- The most specific matching subnet wins.
- An address that matches no subnet falls into `default`, which is in AI scope.
- So `trading` and `dmz` clients stay out of AI scope only if every trading and DMZ subnet is listed.

To edit in the dashboard:

1. Open **Policy Configuration → Network Segments**.
2. On a segment's row, press the subnets button (network icon).
3. Enter one network per line in CIDR form, for example `192.0.2.0/25`. Press **Save Subnets**.
4. When all edits are saved, press **Apply saved changes** at the top of the page. This restarts the engine. Existing kernel blocks remain.

Subnet edits made in the dashboard are not written to the audit log. Record them in your own change log.

You can also edit the policy file by hand. Run the check in section 12 afterwards.

## 12. Fill the AI exempt list

There is no dashboard field for `ai_enforcement`. Edit the policy file as root.

1. Open `/opt/minifw_ai/config/modes/minifw_financial/policy.json`.
2. In the `ai_enforcement` block, list addresses or networks in `exempt`. Example:

   ```json
   "exempt": ["192.0.2.10", "192.0.2.20/32", "192.0.2.128/28"],
   ```

3. Include:
   - servers;
   - monitoring and polling systems;
   - proxies;
   - shared NAT addresses (many users behind one address);
   - any automation that opens a new connection for every request.

4. Check the file. This loads the JSON and every subnet and exempt entry the same way the engine does:

   ```bash
   sudo python3 -c '
   import ipaddress, json
   p = json.load(open("/opt/minifw_ai/config/modes/minifw_financial/policy.json"))
   for cidrs in p.get("segment_subnets", {}).values():
       for c in cidrs:
           ipaddress.ip_network(c, strict=False)
   ai = p.get("ai_enforcement")
   if not ai or not ai.get("segments"):
       raise SystemExit("No ai_enforcement segments: the AI will not isolate anyone. See section 17.")
   for c in ai.get("exempt", []):
       ipaddress.ip_network(c, strict=False)
   print("OK. AI segments:", ai.get("segments"), "exempt entries:", len(ai.get("exempt", [])))
   '
   ```

   If it prints an error, fix the entry it names and run it again.

5. Apply: press **Apply saved changes** on the Policy Configuration page, or run:

   ```bash
   sudo systemctl restart minifw-ai
   ```

6. Check the engine's startup messages:

   ```bash
   sudo journalctl -u minifw-ai -n 200 --no-pager | grep AI_WINDOW
   ```

   You should see `[AI_WINDOW] Loaded /opt/minifw_ai/models/client_window_v1.json sha256=d06ce40e...`. You should not see `Invalid ai_enforcement.exempt entry` or `has no ai_enforcement segments`.

The exempt list only affects the AI. It does not stop rule blocks such as a deny-listed domain or a port scan.

## 13. Confirm the DNS log and AI-enhanced protection

1. On the dashboard **Firewall Status** card, check:
   - **Firewall Engine**: `Active`
   - **Detection Mode**: `AI enhanced`
   - **Connection-rate AI**: `Shadow only (model not approved)`

2. The same from the command line:

   ```bash
   sudo python3 -c 'import json; h = json.load(open("/opt/minifw_ai/logs/runtime-health.json")); print(h["protection_state"], h["ai_window"])'
   ```

   Expected: `AI_ENHANCED_PROTECTION` and `'approved': False`.

3. If Detection Mode shows `Baseline (AI off: DNS log not healthy)`, go back to section 7. See also "DNS log lost" in the recovery procedure.

**The yellow banner.** Dashboard pages show "Protection checks unavailable. ..." whenever any engine input has been quiet for more than 30 seconds. The Financial policy has Zeek SNI collection on. Without a Zeek sensor, that input never reports, so the banner stays. If the site has no Zeek sensor:

1. Open **Policy Configuration → Data Collectors**.
2. Turn off **Enable Zeek SNI Collection** and press **Update Collectors**.
3. Press **Apply saved changes**.

## 14. Shadow period (recommended: a few days)

Leave the approval line commented out. The AI scores every client but never isolates.

Once a day, list the clients the AI would have isolated:

```bash
sudo sh -c 'zcat -f /opt/minifw_ai/logs/events.jsonl*' | python3 -c '
import collections, json, sys
seen = collections.Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("ai_window_mode") == "shadow_only" and (e.get("ai_window_probability") or 0) >= 0.9:
        seen[(e["segment"], e["client_ip"], e["dst_ip"], e["dst_port"])] += 1
for (segment, client, server, port), n in seen.most_common():
    print(n, segment, client, "->", f"{server}:{port}")
'
```

- Each line shows how many events crossed the isolation point, the segment, the client, and the server and port it connected to.
- A probability of 0.9 or more is the model's isolation point (39 or more new connections in the window).
- During the shadow period every client scores `shadow_only`, including `trading` and `dmz`. Ignore rows from segments outside AI scope.
- For each client listed, decide whether it is benign automation. If it is, add it to `exempt` (section 12).
- Clients already exempt also score `shadow_only` after approval. Expect them to keep appearing in this list.

## 15. Approve the model and turn on AI isolation

Turning on AI isolation is the site's decision. Record who approved it and when.

1. Check the model file:

   ```bash
   sha256sum /opt/minifw_ai/models/client_window_v1.json
   ```

   It must print `d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee`.

2. Edit `/etc/minifw/minifw.env` as root. Find the line `#MINIFW_AI_ENFORCE_MODEL_SHA256=` and change it to:

   ```text
   MINIFW_AI_ENFORCE_MODEL_SHA256=d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee
   ```

   No `#`, no spaces.

3. Check there is exactly one active line:

   ```bash
   sudo grep -c '^MINIFW_AI_ENFORCE_MODEL_SHA256=' /etc/minifw/minifw.env
   ```

   Expected: `1`.

4. Restart the engine:

   ```bash
   sudo systemctl restart minifw-ai
   ```

5. Confirm the dashboard shows **Connection-rate AI**: `Enforcing in internal, guest, default`. The command in section 13 should now print `'approved': True`.

If it shows something else:

| Dashboard text | Likely cause |
| --- | --- |
| `Shadow only (model not approved)` | Line still commented, wrong hash, or the engine was not restarted |
| `Shadow only (approved, no segments in policy)` | `ai_enforcement` missing or empty, or an invalid exempt entry (run the check in section 12) |
| `Model missing` | Model file missing or rejected; see the journal |
| `Off (baseline)` | DNS log not healthy (section 7) |

## 16. What a block looks like

- Every decision is one JSON line in `/opt/minifw_ai/logs/events.jsonl`.
- An AI block has `"action": "block"`, the reason `ai_window_rate` and decision owner `AI Engine (client window)`. It lasts 15 minutes.
- Rule blocks have other reasons, for example `port_scan` (15 or more destination ports from one client), or `dns_denied_domain` with `deny_domain_client_ipv4_isolation`. They last 24 hours.
- List the addresses blocked right now:

  ```bash
  sudo nft list set inet minifw minifw_block_v4
  ```

- To unblock a client, follow section 1 of the recovery procedure. The order of the steps matters.

## 17. Upgrades

- The Financial policy file is a dpkg conffile. If you changed it, an upgrade keeps your version. If dpkg asks, keep your version. The new shipped file is saved next to it as `policy.json.dpkg-dist`.
- If your kept policy has no `ai_enforcement` block, the AI will not isolate anyone:
  - the installer prints `WARNING: ... has no ai_enforcement block, so the AI will not isolate any client.`;
  - the engine logs `[AI_WINDOW] Policy ... has no ai_enforcement segments`;
  - the dashboard shows `Shadow only (approved, no segments in policy)` once the model is approved.
- To fix it, copy the `ai_enforcement` block from `/opt/minifw_ai/config/modes/minifw_financial/policy.json.dpkg-dist` into your policy file. Fill `exempt`, run the check in section 12, and apply.
- Upgrades add the commented approval lines to `/etc/minifw/minifw.env` if they are missing. Nothing is turned on.
- Take a backup before upgrading (recovery procedure, section 6). A backup restores only onto the same version.

## 18. Known limits

- **Address spoofing.** A LAN device that forges a neighbour's address can get that neighbour isolated: 15 minutes by the AI, or 24 hours by the port-scan rule. Turn on anti-spoofing on the access switches (DHCP snooping with IP source guard).
- **Connections, not passwords.** The AI counts new TCP connections. It does not see passwords, logins or failed attempts. Slower rates are not caught.
- **IPv4 routed traffic only.** IPv6 clients are scored but not blocked. Traffic to the gateway's own services is not blocked.
- **Reboot.** A reboot clears all current blocks.
- **Dashboard access.** The dashboard is reachable only from the gateway itself or through an SSH tunnel.
- **Certificate.** The dashboard certificate is valid for 365 days from installation.

---

## Not yet verified

These points come from reading the code and have not been tested yet.

1. A fresh install of this exact installer on a clean Debian 12 amd64 host: first login, licence install, Save and Apply.
2. With no Zeek sensor and **Enable Zeek SNI Collection** turned off, the "Protection checks unavailable" banner clears while DNS and connection tracking are active.
3. What an installation without PyPI access leaves behind, and whether running `apt install` again completes it.
4. How to renew the dashboard certificate after 365 days. The code creates it only when it is missing; no renewal step exists.
5. Whether a client's new connections to the gateway's own services count toward the connection-rate AI. If they do, isolation would cut only that client's routed traffic.
6. Whether `/var/log/dnsmasq.log` is rotated on the site. The MiniFW-AI log rotation covers only its own logs.
7. How long the switch to baseline and back takes on the site's network.
8. The shadow review command in section 14 against a real, rotated events log.

## Sources (commit `50058d10`)

- `scripts/build_deb.sh:133-146` sector policy path baked into both units; `:158-159` Depends and Recommends; `:204-210` venv and `pip install`; `:213-228` `minifw-web` user and `/var/lib/minifw-ai`; `:236-251` secrets and printed admin password; `:252-262` commented approval lines; `:263-268` missing `ai_enforcement` warning; `:271-287` self-signed certificate, 365 days; `:289-326` admin user with `must_change_password`; `:359-369` `nf_conntrack`; `:371-384` Grafana; `:386-408` Zeek; `:410-414` CUPS; `:416-421` services started; `:469-510` conffiles (Financial `:478-480`).
- `systemd/minifw-ai.service:7,16,21,23,24`; `systemd/minifw-ai-web.service:25,29-31` (listens on `127.0.0.1:8443`); `systemd/minifw-ai-apply.path:5`; `systemd/minifw-ai-apply.service:6-7`.
- `config/modes/minifw_financial/policy.json:31-36` example subnets; `:46-52` set, table and chain, 24 h timeout; `:53-58` `ai_enforcement`; `:59-64` collectors, Zeek on.
- `models/client_window_v1.json:10` `block_probability` 0.9.
- `app/minifw_ai/client_window.py:24-28` window, model path, 900 s; `:42-56` counting; `:93-95` approval; `:98-115` scope and exempt.
- `app/minifw_ai/main.py:93-101` unmatched address goes to `default`; `:496-501` set and table names; `:537-538` Zeek source; `:555-567` DNS source; `:584-605` AI config, invalid exempt, missing segments, health snapshot; `:681-684` TCP only; `:811` Financial deny-domain isolation; `:840-851` AI decision; `:853-855` IPv6 not blocked; `:856-859` AI vs rule timeout; `:903-906` event fields.
- `app/minifw_ai/enforce.py:183-213` `forward` drop rule on `ip saddr @minifw_block_v4`.
- `app/minifw_ai/state_manager.py:76-79` healthy within 60 s; `:110` state file; `:117-120` 30 s checks, 3 up, 2 down; `:176-203` transitions.
- `app/minifw_ai/runtime_health.py:47-55` readiness needs every input within 30 s.
- `app/minifw_ai/collector_flow.py:536-546` connection tracking read every 5 s; `:423-439` port scan; `app/minifw_ai/main.py:523` 15-port default.
- `app/controllers/admin/dashboard_controller.py:117-142` Detection Mode and Connection-rate AI texts.
- `app/web/templates/admin/base.html:14-16,41` banner; `app/web/templates/admin/policy.html:9-10` Apply; `:207-208` Zeek switch; `:266-273` subnet editor.
- `app/web/routers/auth.py:165,280,287,304,310` and `app/middleware/auth_middleware.py:70-78` forced password change.
- `app/minifw_ai/licensing.py:19` 14-day grace; `:34-46` deployment ID file; `:99-105` deployment and product mode checks; `app/web/templates/admin/license.html:18,21`; `systemd/minifw-ai-web.service:30` licence path.
- `app/services/policy/update_policy_service.py:105-138` subnet save; `app/web/routers/admin.py:793-802` no audit call for subnet edits.
- `scripts/enable_dnsmasq_logging.sh:19-34,55-71,73-79`; `scripts/uninstall.sh:64-82`.
