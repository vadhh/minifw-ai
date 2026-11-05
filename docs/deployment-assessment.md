# MiniFW-AI production deployment assessment

Prepared for the CEO and deployment team. Read `START_HERE.md` for the sector,
version, source revision, build command, and package contents.

## Decision requested

Approve an isolated gateway pilot after the checks below pass. Production
acceptance remains pending: these ZIPs contain source deployment kits, not
prebuilt Debian installers or evidence of a successful live deployment.

| Area | Included or established | Evidence still required |
| --- | --- | --- |
| Deployment | Native Ubuntu 22.04 / Debian 12 amd64 package builder and systemd units | Fresh Linux build, install, reboot, and recovery |
| Education | School policy, student/staff/guest/admin segments, school feed, education YARA rules | Site subnet mapping, learning platform access, filtering and VPN bypass tests |
| Financial | Financial policy, trading/internal/guest/DMZ segments, fraud and crypto feeds, financial rule engine | Trading/payment availability, Tor controls, TLS/SNI collector coverage, false positives |
| Detection | Bundled MLP model, DNS/flow collectors, YARA rules and nftables enforcement code | Measured detection accuracy, throughput, latency and resource use on target hardware |
| Administration | Local HTTPS dashboard, generated credentials, roles, audit and license UI | Login, password change, role checks, trusted TLS and operational access |
| Licensing | Vendor public keyring and offline verification code | License issued for the installed deployment UUID and sector |
| Integrity | File manifest and SHA-256 checksums | Approved release signing and reviewed source revision before customer production rollout |

Policy labels such as SafeSearch, strict TLS, or PCI-DSS describe intended
controls. They are not acceptance evidence or compliance certification.

## Requirements and deployment effects

- Use a dedicated Linux amd64 gateway with systemd, Python 3.10+, root access,
  and routed interfaces. The repository recommends 4+ cores, 8 GB RAM and
  100 GB disk; size production hardware from measured load.
- Build with Bash, GNU sed, `dpkg-deb` and `sha256sum` on Linux. Building does
  not install services; installation does, and starts enforcement immediately.
- Installation requires APT access and Python package access. The post-install
  script runs pip; this kit is not an offline dependency bundle. Some dashboard
  fonts, icons and login assets also load from a public CDN.
- Installation creates `/opt/minifw_ai`, `/etc/minifw`, two root systemd
  services, a database and a self-signed TLS certificate. It loads conntrack,
  disables CUPS and changes Grafana's bind address if Grafana is installed.
- The DNS helper can replace resolver settings, select an active interface and
  add public upstream resolvers. Review it against the site's approved DNS and
  LAN interface before running it. Limit DNS service access to intended clients.
- Both sector packages have Debian package name `minifw-ai`: use separate
  gateways or VM snapshots to assess them. Installing one over the other is an
  upgrade/replacement, not a second independent instance.

## Install on an isolated Linux gateway

1. Save a VM snapshot or appliance image and the current network, DNS and
   firewall configuration. Keep console access and a route back to the original
   gateway. Verify the kit's `SHA256SUMS` before executing included code.
2. Follow `START_HERE.md` to build the selected sector's `.deb`. Inspect its
   metadata and contents before installation:

   ```bash
   dpkg-deb --info build/*.deb
   dpkg-deb --contents build/*.deb
   ```

3. Install the single package built in this kit:

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv nftables openssl conntrack dnsmasq curl
   sudo apt install ./build/*.deb
   ```

   Dependencies are fetched online. An installation success message alone does
   not establish that the admin account, collectors or packet enforcement work;
   some post-install failures are warnings.
4. Save the generated admin password securely, log in as `admin`, and change
   the password. Secrets are stored in `/etc/minifw/minifw.env`, mode 0600.
   The dashboard binds to `127.0.0.1:8443`. Use a browser on the gateway or an
   SSH tunnel from the assessment workstation:

   ```bash
   ssh -L 8443:127.0.0.1:8443 admin@gateway
   ```

   Replace `admin@gateway` with the site's SSH account and hostname, then open
   `https://localhost:8443`. The initial certificate is self-signed; verify it
   through the gateway console. Plan trusted TLS and restricted management access
   before production exposure.
5. Review `scripts/enable_dnsmasq_logging.sh`, configure approved upstream DNS
   and LAN bindings, then enable query logging. The sector policy expects
   `/var/log/dnsmasq.log`. Confirm real client queries reach this file.
6. Financial assessment requires a working Zeek deployment and readable
   `/var/log/zeek/ssl.log` for the configured TLS/SNI signals. Zeek is optional
   at package level; its absence reduces detection coverage. Education ships
   with `collectors.use_zeek_sni=false`. Validate actual collector coverage.
7. Replace example subnets and review thresholds in
   `/opt/minifw_ai/config/modes/PRODUCT_MODE/policy.json`, using the product mode
   from `START_HERE.md`. Check overlapping networks; the Financial template
   includes `10.0.0.0/8` alongside more specific trading and DMZ subnets.
   Restart the engine after approved changes.
8. Configure routing, forwarding, return routes and any required NAT for the
   site's topology. Clients must use this host as their traffic gateway and
   reach the DNS collector. Installation alone does not establish this path.
   Do not treat mirrored traffic or a populated dashboard as proof of blocking.

## Acceptance evidence to collect

Record operator, date, hardware, OS, source and artifact hashes, traffic rate,
expected outcome, observed outcome and a link to evidence for each item.

- [ ] Both services remain active after installation and reboot. Record
  `systemctl status minifw-ai minifw-ai-web` and
  `journalctl -u minifw-ai -u minifw-ai-web --since boot`.
- [ ] `systemctl cat minifw-ai minifw-ai-web` shows the selected sector/product
  mode; the engine uses the matching sector policy. Dashboard branding agrees.
- [ ] Admin login, required password change, authorized role access and audit
  records work. The license page shows the correct deployment ID/product mode;
  install a vendor-issued license if evaluating license activation.
- [ ] DNS query logs and conntrack flows show real test-client traffic. Financial
  TLS tests also populate the configured Zeek SSL log.
- [ ] A controlled lab block produces an event, the expected nftables set entry,
  matching rule counters, and an actual failed forwarded connection from the
  test client. Record `sudo nft list table inet minifw` before and after.
- [ ] Known benign school services or financial applications remain usable.
  Record false positives and approve allowlists before broadening the pilot.
- [ ] Test each intended sector control, including bypass attempts and missing
  collector data. Confirm which controls are actually enforced at the client.
- [ ] Measure CPU, memory, disk growth, throughput and latency at expected load.
  Define acceptable values before testing; no performance SLA is established here.
- [ ] Test loss of DNS/Zeek data, service restart, reboot and gateway failure.
  Record the actual enforcement and network availability outcomes.
- [ ] Configure log rotation, retention, monitoring, feed update ownership and
  patching. Confirm the metrics endpoint is reachable only from approved networks.
- [ ] Complete backup and restore on a second isolated instance, then prove
  management access and permitted client traffic recover.

## Backup and rollback

The included `scripts/backup.sh` and `scripts/restore.sh` implement the existing
backup workflow. Inspect them before use. Backup archives contain secrets and
must be stored with restricted access. The backup helper includes the dashboard
database and `/var/lib/minifw-ai/license.json` (moved from `/etc/minifw/` when
the dashboard stopped running as root), but not
`/var/lib/minifw-ai/installation-id`; preserve that separately to retain license
binding. Preserve site DNS, routing and forwarding configuration separately too.

Before rollback, use console access and move clients back to the known working
gateway. Stop both services and restore the pre-install appliance/VM snapshot
and network configuration. Stopping services or removing the package alone does
not prove previously installed nftables rules are removed. Verify permitted
traffic and DNS afterward. Avoid package purge while evidence or rollback data
is needed: its post-remove script deletes the database, secrets, TLS and logs.

## Source and review limits

`MANIFEST.json` identifies the source revision, modified included files, shell
and service files normalized to Linux line endings, and every packaged file hash.
Local licensing additions are included; private keys,
customer licenses, credentials, databases, runtime logs, backup files, virtual
environments, Git history and agent configuration are excluded by file selection.

The supplied public keyring identifies a verification key; this assessment did
not establish ownership or access to its private signing key. Deployment-bound
licenses must be issued after installation; see `docs/licensing.md`.

Packaging checks cover ZIP integrity, file hashes, source syntax, shell syntax,
required build inputs, sector mapping and local static assets. They do not cover
a Linux package build, installation, browser session, live packet enforcement,
load testing or a full security audit. A go-live decision needs the acceptance
evidence above and an approved, signed release.
