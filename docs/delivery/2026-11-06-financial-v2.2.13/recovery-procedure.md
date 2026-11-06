# MiniFW-AI Financial v2.2.13: recovery procedure

| Item | Value |
| --- | --- |
| Version | 2.2.13-finance (candidate C22, commit `50058d10`) |
| Installer | `minifw-ai_2.2.13-finance_amd64.deb`, SHA-256 `6192bdd79e4094ec3c841217afe1c335c9ac36df9220a6e91a3857e3013d92c9` |

Every command runs as root, so it starts with `sudo`.
`192.0.2.10` stands for the affected client. Replace it with the real address.
Section numbers like "setup guide §12" refer to `setup-guide.md`.

## Names and paths used below

| What | Name or path |
| --- | --- |
| Engine service | `minifw-ai` |
| Dashboard service | `minifw-ai-web` (listens on `127.0.0.1:8443` only) |
| Apply helper | `minifw-ai-apply.path` / `minifw-ai-apply.service` (restarts `minifw-ai` when the dashboard's **Apply saved changes** is pressed) |
| Block list | nftables table `inet minifw`, set `minifw_block_v4`, chain `forward` |
| Policy file | `/opt/minifw_ai/config/modes/minifw_financial/policy.json` |
| Secrets and AI approval | `/etc/minifw/minifw.env` (root only) |
| Dashboard database, licence, deployment ID | `/var/lib/minifw-ai/minifw.db`, `/var/lib/minifw-ai/license.json`, `/var/lib/minifw-ai/installation-id` |
| Logs | `/opt/minifw_ai/logs/` |
| Backups | `/opt/minifw_ai/backups/` |

---

## 1. Unblock a wrongly isolated client

The running engine keeps counting a client's connections. If you delete a block while the engine still counts that client, it can add the client back within seconds. So fix the cause and restart the engine first, then delete the block.

### Step 1: find out why the client was blocked

1. Check that the client is blocked:

   ```bash
   sudo nft get element inet minifw minifw_block_v4 '{ 192.0.2.10 }'
   ```

   If this prints the element, the client is blocked. An error means it is not in the set.

2. Find the block decision:

   ```bash
   sudo grep '"client_ip": "192.0.2.10"' /opt/minifw_ai/logs/events.jsonl | grep '"action": "block"' | tail -n 3
   ```

3. Read `reasons` and `decision_owner`:

   | Reason | Type | Block length |
   | --- | --- | --- |
   | `ai_window_rate` (owner `AI Engine (client window)`) | AI | 15 minutes |
   | `port_scan`, `pps_saturation`, `burst_flood`, `bot_like_small_packets`, `bot_regular_timing` (owner `Hard Gate`) | Rule | 24 hours |
   | `dns_denied_domain` or `tls_sni_denied_domain` with `deny_domain_client_ipv4_isolation` | Rule | 24 hours |
   | Anything else (score, protocol or sector rule) | Rule | 24 hours |

### Step 2: stop it coming back

- **AI block.** Add the client to `ai_enforcement.exempt` in the policy file. Run the policy check from setup guide §12.
- **Rule block.** The exempt list does not help. It only affects the AI. There is no per-client exception for rules. Fix the cause instead, for example:
  - remove a wrong entry from a deny list (dashboard deny pages), or add the domain to the allow list;
  - stop the tool that scanned many ports.

  If the client keeps doing the same thing, a rule will block it again.

### Step 3: restart the engine

```bash
sudo systemctl restart minifw-ai
```

Or press **Apply saved changes** on the dashboard's Policy Configuration page. It restarts the engine the same way.

After a restart:

- the engine loads the saved policy and feeds;
- connections that were already open count as existing, not new, and are not counted as scan ports;
- the AI ignores connections first seen in the first 10 seconds.

### Step 4: delete the block

```bash
sudo nft delete element inet minifw minifw_block_v4 '{ 192.0.2.10 }'
```

### Step 5: verify

1. Check the element is gone:

   ```bash
   sudo nft get element inet minifw minifw_block_v4 '{ 192.0.2.10 }'
   ```

   This must now return an error.

2. Run the same command again after a few minutes. It must still return an error.

3. Check the client's newest events. They should show `"action": "allow"`. If you exempted the client, AI-scored events show `"ai_window_mode": "shadow_only"`.

   ```bash
   sudo grep '"client_ip": "192.0.2.10"' /opt/minifw_ai/logs/events.jsonl | tail -n 3
   ```

### Step 6: record it

Deleting an element by hand is not written to the MiniFW-AI audit log. Record who unblocked which address, when, and why.

---

## 2. Turn AI isolation off immediately

**This reduces protection.** Rules, threat feeds and hard gates keep enforcing, but the AI stops isolating clients. Do this only on the site's decision. Record who decided and when. The product does not log edits to the env file.

1. Edit `/etc/minifw/minifw.env` as root. Put a `#` in front of the approval line:

   ```text
   #MINIFW_AI_ENFORCE_MODEL_SHA256=d06ce40ea3276d2cedac9e354075c4aa74aa3987e08b35e40a95451d4e69d6ee
   ```

2. Check that no active line is left:

   ```bash
   sudo grep -c '^MINIFW_AI_ENFORCE_MODEL_SHA256=' /etc/minifw/minifw.env
   ```

   Expected: `0`.

3. Restart the engine:

   ```bash
   sudo systemctl restart minifw-ai
   ```

4. Verify:
   - The dashboard shows **Connection-rate AI**: `Shadow only (model not approved)`.
   - Or from the command line:

     ```bash
     sudo python3 -c 'import json; print(json.load(open("/opt/minifw_ai/logs/runtime-health.json"))["ai_window"])'
     ```

     Expected: `'approved': False`.

5. AI blocks that already exist stay until they expire (at most 15 minutes). To remove them sooner, find them and delete each one with section 1, step 4:

   ```bash
   sudo grep '"ai_window_rate"' /opt/minifw_ai/logs/events.jsonl | grep '"action": "block"' | tail -n 20
   ```

The AI keeps scoring in shadow mode. To turn isolation back on, follow setup guide §15.

---

## 3. Engine not running, or a broken policy

### Signs

- **Firewall Engine** shows `Stopped`, and **Detection Mode** shows `Unknown (engine not reporting)`.
- **Apply saved changes** answers "Engine restart could not be verified. ..."
- If the policy file is not valid JSON, the **Policy Configuration** page itself fails to load. Its error names `Invalid JSON in policy file`.
- The yellow banner "Protection checks unavailable. ..." also appears. It appears for other reasons too, such as a quiet input, so do not rely on it alone.

### What still works

- Existing blocks stay in the kernel and still expire on schedule.
- New detections stop until the engine runs again.
- systemd tries to start the engine again every 5 seconds.

### Steps

1. Read the engine status and its last messages:

   ```bash
   systemctl status minifw-ai --no-pager
   sudo journalctl -u minifw-ai -n 80 --no-pager
   ```

   - A Python traceback that mentions JSON or the policy file means the policy is broken. Go to step 2.
   - `FATAL: Could not initialize firewall rules` means nftables could not be set up. Check that `nftables` is installed, then contact the vendor with the journal output.
   - `[SECTOR_LOCK] FATAL` means the sector configuration is wrong. Contact the vendor.

2. Check the policy file:

   ```bash
   sudo python3 -m json.tool /opt/minifw_ai/config/modes/minifw_financial/policy.json > /dev/null && echo JSON OK
   ```

   Then run the full check from setup guide §12. That check also catches an invalid subnet, which stops the engine, and an invalid exempt entry, which turns AI isolation off.

3. Keep a copy of the broken file for later analysis:

   ```bash
   sudo cp /opt/minifw_ai/config/modes/minifw_financial/policy.json /root/policy-broken.json
   ```

4. Fix the file by hand, or go back to a known-good copy:

   - The dashboard saves a copy before each of its own saves:

     ```bash
     sudo sh -c 'ls -lt /opt/minifw_ai/logs/policy.json.backup.*'
     sudo cp /opt/minifw_ai/logs/policy.json.backup.<date_time> /opt/minifw_ai/config/modes/minifw_financial/policy.json
     ```

   - After an upgrade, the shipped version may exist as `/opt/minifw_ai/config/modes/minifw_financial/policy.json.dpkg-dist`.

   - The shipped version is also inside the installer:

     ```bash
     sudo dpkg-deb -x minifw-ai_2.2.13-finance_amd64.deb /root/minifw-pkg
     sudo cp /root/minifw-pkg/opt/minifw_ai/config/modes/minifw_financial/policy.json /opt/minifw_ai/config/modes/minifw_financial/policy.json
     ```

     The shipped file has example subnets and an empty exempt list. Put your site's values back (setup guide §11 and §12) before you restart.

   - A backup archive also contains the policy (section 6).

5. Run the checks from step 2 again. Both must pass.

6. Restart the engine:

   ```bash
   sudo systemctl restart minifw-ai
   ```

   If `systemctl status` says the start request repeated too quickly, run `sudo systemctl reset-failed minifw-ai` first.

   Once the Policy Configuration page loads again, **Apply saved changes** does the same restart.

7. Verify:

   ```bash
   systemctl is-active minifw-ai
   sudo journalctl -u minifw-ai -n 200 --no-pager | grep -E 'AI_WINDOW|FATAL'
   sudo nft list chain inet minifw forward
   ```

   - The service is `active`.
   - The journal shows `[AI_WINDOW] Loaded ...` and no `FATAL`, `Invalid` or `has no ai_enforcement segments`.
   - The chain still has the `ip saddr @minifw_block_v4 ... drop` rule.
   - The dashboard shows **Firewall Engine** `Active`, and **Detection Mode** is no longer `Unknown`.

---

## 4. DNS log lost (baseline protection)

### Signs

- **Detection Mode**: `Baseline (AI off: DNS log not healthy)`.
- **Connection-rate AI**: `Off (baseline)`.
- The journal shows `[STATE_TRANSITION] AI_ENHANCED_PROTECTION -> BASELINE_PROTECTION | trigger=telemetry_lost`.
- `/opt/minifw_ai/logs/audit.jsonl` has a state transition record.

### What still works

- Rules, threat feeds and hard gates keep enforcing. The AI does not run.
- Domain deny-list matches from DNS cannot happen while there are no DNS log lines.

The engine checks every 30 seconds whether dnsmasq wrote a query line in the last 60 seconds. After 2 failed checks it switches to baseline. A network with no DNS queries for a minute (for example at night) also switches to baseline. That is not a fault, and it switches back by itself.

### Steps

1. Check dnsmasq:

   ```bash
   systemctl status dnsmasq --no-pager
   ```

2. Check that query lines are being written now:

   ```bash
   date; sudo tail -n 5 /var/log/dnsmasq.log
   ```

   Look for recent lines containing `query[` and `from <client address>`.

3. Check that query logging is on, and that the policy reads the same file:

   ```bash
   grep -E '^(log-queries|log-facility=)' /etc/dnsmasq.conf
   sudo grep dnsmasq_log_path /opt/minifw_ai/config/modes/minifw_financial/policy.json
   ```

4. Check that clients still use this host for DNS (the DNS server handed out by DHCP).

5. Fix what you found, then restart dnsmasq:

   ```bash
   sudo systemctl restart dnsmasq
   ```

   You do not need to restart the engine. It follows the log file when it is rotated, truncated, deleted or re-created.

6. Verify:
   - After about 1.5 minutes of DNS traffic (3 good checks), **Detection Mode** shows `AI enhanced`.
   - The journal shows `[STATE_TRANSITION] BASELINE_PROTECTION -> AI_ENHANCED_PROTECTION | trigger=telemetry_restored`.

   ```bash
   sudo journalctl -u minifw-ai --since "15 min ago" --no-pager | grep STATE_TRANSITION
   ```

---

## 5. Log storage full

### What grows

| Path | Rotated |
| --- | --- |
| `/opt/minifw_ai/logs/events.jsonl`, `audit.jsonl`, `flow_records.jsonl` | Yes: daily or above 100 MB, 14 kept, compressed (`/etc/logrotate.d/minifw-ai`) |
| `/opt/minifw_ai/logs/policy.json.backup.*` (one per dashboard save) | No |
| `/opt/minifw_ai/backups/` | No |
| `/var/log/dnsmasq.log` | Not by MiniFW-AI |
| systemd journal | By journald's own limits |

Size limits are checked only when logrotate runs, which is normally once a day.

### What the code does when it cannot write

- A block is added to the kernel before its event line is written. A failed event write is logged in the journal as `Unhandled exception in main event loop`.
- A failed audit write is logged as `[AUDIT] Failed to write audit record`.
- If the engine cannot write its health file, the dashboard shows `Unknown (engine not reporting)`. The yellow banner also asks you to check log storage.

### Steps

1. Check free space and the largest files:

   ```bash
   df -h /opt/minifw_ai/logs /var/lib/minifw-ai /var/log
   sudo sh -c 'du -sh /opt/minifw_ai/logs/* /opt/minifw_ai/backups /var/log/dnsmasq.log' | sort -h | tail -n 15
   ```

   The logs folder is readable only by root and the dashboard group. That is why commands with `*` in that folder run inside `sudo sh -c '...'`.

2. If the site must keep logs (for example for audit retention), copy the rotated files off the host first.

3. Free space, in this order:

   1. Delete old rotated MiniFW-AI logs (after copying them off):

      ```bash
      sudo sh -c 'rm -f /opt/minifw_ai/logs/*.jsonl.[0-9]*.gz'
      ```

   2. Shrink the journal:

      ```bash
      sudo journalctl --vacuum-size=500M
      ```

   3. Where needed:
      - delete old `policy.json.backup.*` files, keeping the newest few;
      - move old archives out of `/opt/minifw_ai/backups/`;
      - empty the DNS log with `sudo truncate -s 0 /var/log/dnsmasq.log`. The engine handles a truncated file.

   4. Only then rotate the current logs. Rotation copies each file before emptying it, so it needs free space:

      ```bash
      sudo logrotate -f /etc/logrotate.d/minifw-ai
      ```

4. Do not delete:
   - the current `audit.jsonl`;
   - `runtime-health.json` or `deployment_state.json`;
   - anything in `/var/lib/minifw-ai`.

5. Verify:
   - `df -h` shows free space.
   - New lines arrive: `sudo tail -n 1 /opt/minifw_ai/logs/events.jsonl`.
   - **Detection Mode** is no longer `Unknown`.

---

## 6. Backup and restore

### What a backup contains

- Everything under `/opt/minifw_ai/config/` (policies, feeds, licence public key), `/opt/minifw_ai/models/`, `/opt/minifw_ai/yara_rules/` and `/etc/minifw/tls/`.
- `/var/lib/minifw-ai/minifw.db` (dashboard users and settings), `/var/lib/minifw-ai/license.json`, `/etc/minifw/minifw.env`.
- The two main service units, `minifw-ai.service` and `minifw-ai-web.service`.

It does **not** contain:

- the deployment ID file `/var/lib/minifw-ai/installation-id`;
- logs;
- program code;
- current blocks.

**The archive is secret.** It holds the dashboard secret key, the initial admin password, the TLS private key, password hashes and the licence. Store it like a password.

### Make a backup

1. Run:

   ```bash
   sudo /opt/minifw_ai/scripts/backup.sh
   ```

   - It stops `minifw-ai-web` and `minifw-ai` while it copies. New detections pause; existing blocks stay.
   - It starts the services that were running before.
   - It prints `BACKUP <path> SHA256 <hash>`. The archive is `/opt/minifw_ai/backups/minifw-backup-<UTC time>.tar.gz`, readable by root only.

2. Copy the archive to protected storage off the gateway. Record its SHA-256.

3. Copy `/var/lib/minifw-ai/installation-id` to the same protected place.

4. To see which version an archive belongs to:

   ```bash
   sudo tar -xzOf <archive> minifw-backup.json | python3 -c 'import json, sys; m = json.load(sys.stdin); print(m["version"], m["created"], len(m["entries"]), "files")'
   ```

### Restore

A backup restores only onto the same version and edition. A 2.2.13-finance archive restores only onto 2.2.13-finance.

1. Check the installed version. It must match the archive's version:

   ```bash
   dpkg-query -W -f='${Version}\n' minifw-ai
   ```

2. The archive must be owned by root and readable only by root. If you copied it back from elsewhere:

   ```bash
   sudo chown root:root <archive>
   sudo chmod 600 <archive>
   ```

3. Restore:

   ```bash
   sudo /opt/minifw_ai/scripts/restore.sh <archive>
   ```

   - It checks the whole archive first: version, file list and checksums. If a check fails, nothing is changed.
   - It stops both services, writes the files, and starts the services that were running before.
   - If writing fails partway, it puts the previous files back.
   - On success it prints `RESTORED 2.2.13-finance ; dynamic nftables blocks and package code were not restored`.

4. A restore brings back the state at backup time, including:
   - dashboard users and passwords;
   - the policy and feeds;
   - the licence;
   - the AI approval line in `minifw.env` (on or off).

   Check the approval line afterwards (setup guide §15) and confirm it matches the site's current decision.

5. Verify:

   ```bash
   systemctl is-active minifw-ai minifw-ai-web
   sudo journalctl -u minifw-ai -n 200 --no-pager | grep -E 'AI_WINDOW|FATAL'
   ```

   Then log in to the dashboard and check:
   - **License** status;
   - **Policy Configuration**;
   - **Detection Mode** and **Connection-rate AI**.

### Restoring onto a rebuilt gateway

- Install the same version first.
- The deployment ID file is not in the archive. A new installation creates a new deployment ID the first time the License page opens. The restored licence then shows `Invalid`: "License is issued for a different deployment".
- Either put back the saved `installation-id` file before restoring (to confirm in the lab, and agree it with the vendor), or ask the vendor for a licence for the new deployment ID.

---

## 7. Roll back to a previous package version

### Before you start

1. Make a backup on the current version (section 6). You will need it if you return to 2.2.13.
2. Know the restore limits:
   - A 2.2.13 backup cannot be restored onto an older version.
   - The backup tool in 2.2.11 refuses every backup and restore.
   - The backup tool in 2.2.10 accepts only 2.2.10.
   - So after a rollback, you rely on the files dpkg leaves in place.
3. Get the previous installer from the vendor. Check its SHA-256 against the vendor's value.
4. The host needs PyPI access, because the installer runs `pip install` again.

### What dpkg leaves in place

Installing another version does not remove or replace:

- `/etc/minifw/` (secrets, AI approval line, TLS certificate);
- `/var/lib/minifw-ai/` (dashboard database, `license.json`, `installation-id`);
- `/opt/minifw_ai/logs/` and `/opt/minifw_ai/backups/`;
- the Python environment in `/opt/minifw_ai/venv`.

The install step does adjust some of them. It runs `pip install` into the existing Python environment, resets ownership of `/var/lib/minifw-ai` to the dashboard user, and may add commented lines to `minifw.env`.

The policy files and feeds are conffiles. `--force-confold` keeps your edited versions without asking.

Versions 2.2.10 and 2.2.11 read the licence and the deployment ID from the same paths as 2.2.13. So the deployment ID should not change, and the licence should stay valid (to confirm in the lab, item 6).

### Steps

1. Install the previous version:

   ```bash
   sha256sum minifw-ai_<previous-version>-finance_amd64.deb
   sudo dpkg -i --force-confold minifw-ai_<previous-version>-finance_amd64.deb
   ```

   The current package's removal step stops and disables the services. The previous package's install step starts them again.

2. Verify:

   ```bash
   dpkg-query -W -f='${Version}\n' minifw-ai
   systemctl is-active minifw-ai minifw-ai-web minifw-ai-apply.path
   sudo nft list chain inet minifw forward
   ```

   Then log in to the dashboard and check the **License** status.

3. To return to 2.2.13:

   ```bash
   sudo dpkg -i --force-confold minifw-ai_2.2.13-finance_amd64.deb
   ```

   If needed, restore the 2.2.13 backup (section 6).

### Do not use these for a rollback

- `dpkg -P minifw-ai` (purge) deletes:
  - `/var/lib/minifw-ai`, including the licence and the deployment ID;
  - `/etc/minifw`, including secrets and the TLS certificate;
  - the logs and the Python environment.

  A reinstall then gets a new deployment ID and needs a new licence.
- `/opt/minifw_ai/scripts/uninstall.sh`:
  - deletes all of `/opt/minifw_ai`, including `backups/`, and `/etc/minifw`;
  - removes dnsmasq's `interface=`, `server=8.8.8.8`, `server=8.8.4.4` and logging lines;
  - stops and disables dnsmasq, which stops DNS for the clients.
- `dpkg -r minifw-ai` removes the program but keeps `/etc/minifw` and `/var/lib/minifw-ai`. Use it only to remove the product.

---

## 8. After a reboot

All blocks are cleared at reboot. Nothing saves the block list.

The engine starts with the system, then re-creates the table, set and drop rule. A client is blocked again only if it triggers again.

To check after a reboot:

```bash
systemctl is-active minifw-ai minifw-ai-web minifw-ai-apply.path
sudo nft list chain inet minifw forward
```

The engine creates the table, set and drop rule only when it starts. If they are removed while it runs, blocking stops until the engine restarts. This can happen, for example, when the host's own nftables rules are reloaded with `flush ruleset`. The engine checks every 2 seconds that the rule is present, so the yellow banner shows. **Detection Mode** does not change.

To fix it, restart the engine and check the chain again:

```bash
sudo systemctl restart minifw-ai
sudo nft list chain inet minifw forward
```

---

## 9. Where the logs are

| What | Where |
| --- | --- |
| Every engine decision, one JSON line each (action, score, reasons, decision owner, `ai_window_mode`, `ai_window_probability`) | `/opt/minifw_ai/logs/events.jsonl` |
| Audit trail: engine start and stop, policy load, firewall setup, protection state changes, blocks, logins, 2FA, logouts, password changes, policy changes, user changes | `/opt/minifw_ai/logs/audit.jsonl` |
| Flow records | `/opt/minifw_ai/logs/flow_records.jsonl` |
| Engine health read by the dashboard | `/opt/minifw_ai/logs/runtime-health.json` |
| Protection state and the last 100 changes | `/opt/minifw_ai/logs/deployment_state.json` |
| Policy copies made before each dashboard save | `/opt/minifw_ai/logs/policy.json.backup.<date_time>` |
| Engine messages | `sudo journalctl -u minifw-ai` |
| Dashboard messages | `sudo journalctl -u minifw-ai-web` |
| Apply requests | `sudo journalctl -u minifw-ai-apply` |
| DNS queries (dnsmasq) | `/var/log/dnsmasq.log` |

Useful commands:

```bash
sudo journalctl -u minifw-ai --since "1 hour ago" --no-pager
sudo tail -n 5 /opt/minifw_ai/logs/events.jsonl
sudo tail -n 20 /opt/minifw_ai/logs/audit.jsonl
sudo nft list set inet minifw minifw_block_v4
```

Rotated files sit next to the originals (`events.jsonl.1`, `events.jsonl.2.gz`, ...). Read them with `zcat -f`.

---

## Not yet verified

These points come from reading the code and have not been tested yet. Treat them with care.

1. The order in section 1 (fix, restart, then delete) for an AI block. For a port-scan block it was confirmed in the lab: after a restart the client was not re-blocked (4 of 4 runs), while deleting the block on a running engine let the engine re-add the client within 1-5 seconds.
2. The exact error text `nft get element` prints for an address that is not in the set.
3. Behaviour when `/opt/minifw_ai/logs` or `/var/lib/minifw-ai` is full: blocking continues, the dashboard login still works, and recovery after space is freed.
4. Whether a broken-policy restart loop ever reaches systemd's start limit, so that `reset-failed` is needed.
5. Restoring a backup onto a rebuilt gateway with the saved `installation-id` put back first: the licence shows Valid. Agree this with the vendor before relying on it.
6. A downgrade from 2.2.13 to the previous Financial version: services start; the dashboard database, licence and deployment ID still work; the policy is kept; the AI approval line has no unwanted effect.
7. Whether `/var/log/dnsmasq.log` is rotated on the site.
8. The time from DNS loss to baseline, and from DNS return to AI-enhanced, on the site.
9. The dashboard banner and status rows when the log disk is full.
10. Whether the site's own nftables service or scripts reload rules with `flush ruleset` (for example at boot or on a manual reload), which would remove the MiniFW-AI table until the engine restarts.

## Sources (commit `50058d10`)

- `config/modes/minifw_financial/policy.json:46-52` set `minifw_block_v4`, table `inet minifw`, chain `forward`, 86400 s; `:53-58` `ai_enforcement`, 900 s.
- `app/minifw_ai/main.py:378` policy loaded at start, no error handling; `:496-501` set and table names; `:507-516` fatal nftables setup; `:540` subnets parsed at start; `:584-599` exempt check, missing segments warning, AI timeout, 10 s ignore after start; `:840-851` AI decision; `:856-863` block added before the event is written; `:928` event write; `:945-946` loop error message.
- `app/minifw_ai/enforce.py:80-86` membership check with `nft get element`; `:183-213` drop rule.
- `app/minifw_ai/client_window.py:105-115` exempt applies to the AI only.
- `app/minifw_ai/collector_flow.py:31,85,315,423-439` connections open at restart are not new or scan ports.
- `app/minifw_ai/state_manager.py:76-79,117-120,176-216` health checks, transitions, journal text.
- `app/minifw_ai/collector_dnsmasq.py:85-98,113-136` missing, deleted, truncated or rotated DNS log.
- `app/minifw_ai/runtime_health.py:47-55,102-103` readiness and health-file write failure.
- `app/minifw_ai/audit.py:56-61,99-171` audit write failure and recorded actions.
- `app/minifw_ai/maintenance.py:17-21` services and backup contents; `:30-34` Financial or Education only; `:62-63` scope note; `:86-87` same version; `:158-168` root, folder, archive name; `:173-176` archive must be root-owned 0600; `:177-212` stop, write, roll back, restart.
- `git show 9148fad1:app/minifw_ai/maintenance.py` lines 30-34: the 2.2.11 tool accepts only 2.2.10. `git show f04977ed:app/minifw_ai/maintenance.py` lines 30-34: the 2.2.10 tool accepts only 2.2.10.
- `git show f04977ed:systemd/minifw-ai-web.service` and `git show 9148fad1:systemd/minifw-ai-web.service`: licence at `/var/lib/minifw-ai/license.json`; `licensing.py:36` at both commits: deployment ID at `/var/lib/minifw-ai/installation-id`.
- `scripts/build_deb.sh:210,296,334,253-262` install step re-runs `pip`, re-owns `/var/lib/minifw-ai`, adds commented lines; `:335-337` logs folder `2750`.
- `app/minifw_ai/main.py:507-509` table and rule created only at start; `app/minifw_ai/runtime_health.py:74-81` rule checked every 2 s.
- `app/minifw_ai/licensing.py:34-46,102-103` deployment ID file and the "different deployment" check.
- `app/controllers/admin/dashboard_controller.py:117-142`; `app/controllers/admin/policy_controller.py:53-54`; `app/services/policy/get_policy_service.py:15-16`; `app/services/policy/apply_policy_service.py:9-33`; `app/services/policy/update_policy_service.py:8-29`.
- `app/web/templates/admin/base.html:14-16,41`; `app/web/templates/admin/policy.html:9-10`.
- `systemd/minifw-ai.service:28-29` restart every 5 s; `systemd/minifw-ai-web.service:29-31`; `systemd/minifw-ai-apply.service:6-7`.
- `scripts/build_deb.sh:435-448` prerm; `:451-466` postrm purge; `:469-510` conffiles; `:204-210` `pip install`.
- `scripts/backup.sh:3-4`, `scripts/restore.sh:3-4`, `scripts/minifw-ai.logrotate:5-15`, `scripts/uninstall.sh:45-52,64-82`.
