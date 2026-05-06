# One-Line Installer Design

**Date:** 2026-05-06  
**Status:** Approved

## Overview

A single `install.sh` script published as a GitHub release asset that enables one-command installation of MiniFW-AI on any supported Debian/Ubuntu host.

```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/latest/download/install.sh | sudo bash
```

Or pinned to a specific version:

```bash
curl -fsSL https://github.com/vadhh/minifw-ai/releases/download/v2.2.0/install.sh | sudo bash
```

## File Location

`install.sh` at the repo root. Published as a GitHub release asset alongside the `.deb` files on every release.

## Script Flow

1. **Pre-flight checks** — verify running as root; detect OS (Ubuntu/Debian only, exit with clear message otherwise); check required tools (`curl`, `dpkg`, `gpg`, `sha256sum`)
2. **Sector selection** — display numbered menu of all six sectors (`hospital`, `education`, `government`, `finance`, `legal`, `establishment`); validate input; retry on invalid choice
3. **Version resolution** — query `https://api.github.com/repos/vadhh/minifw-ai/releases/latest`, parse `tag_name` (e.g. `v2.2.0`), strip `v` prefix to get bare version (`2.2.0`)
4. **Asset download** — download three files into a temp directory (`mktemp -d`):
   - `minifw-ai_<version>-<sector>_amd64.deb`
   - `minifw-ai_<version>-<sector>_amd64.deb.sha256`
   - `minifw-ai_<version>-<sector>_amd64.deb.asc`
   - `minifw-ai-release.asc` (GPG public key)
5. **SHA-256 verification** — `sha256sum -c` against the downloaded checksum file; hard fail on mismatch
6. **GPG verification (optional)** — import `minifw-ai-release.asc` into an isolated keyring at `/tmp/minifw-gpg-verify`; verify the `.asc` signature; on failure print a warning and continue; clean up temp keyring
7. **Install** — `dpkg -i <deb>`; install missing deps via `apt-get install -f -y` if dpkg reports dependency errors
8. **Post-install** — run in order (warn and continue on failure):
   - `/opt/minifw_ai/scripts/enable_dnsmasq_logging.sh`
   - `/opt/minifw_ai/scripts/install_systemd.sh`
9. **Status report** — print `systemctl status minifw-ai --no-pager`; print admin credentials location (`/etc/minifw/minifw.env`); print web panel URL (`https://<hostname>:8443`)

## Asset Naming Convention

Matches the existing `scripts/build_deb.sh` output:

```
minifw-ai_<VERSION>-<SECTOR>_amd64.deb
minifw-ai_<VERSION>-<SECTOR>_amd64.deb.sha256
minifw-ai_<VERSION>-<SECTOR>_amd64.deb.asc
minifw-ai-release.asc
install.sh
```

All uploaded to the GitHub release for each version tag.

## GPG Key Handling

- Key ID: `BDB471E1FB46F58A`
- The `minifw-ai-release.asc` public key is fetched from the same GitHub release (no keyserver dependency)
- Imported into an isolated temporary keyring (`--homedir /tmp/minifw-gpg-verify`) to avoid polluting the system keyring
- Temp keyring cleaned up after verification regardless of outcome

## Error Handling

| Failure | Behaviour |
|---|---|
| Not root | Exit 1 with message |
| Non-Debian OS | Exit 1 with message |
| Invalid sector input | Re-prompt |
| GitHub API unreachable | Exit 1 |
| Download fails | Exit 1 |
| SHA-256 mismatch | Exit 1, delete temp files |
| GPG verify fails | Warn, continue |
| dpkg dependency error | Run `apt-get install -f -y`, retry |
| Post-install script fails | Warn with script path, continue |

## README Update

The README "Installation" section should be updated to lead with the one-liner, keeping the manual `.deb` flow as an alternative for air-gapped or offline deployments.

## Out of Scope

- ARM / non-amd64 architectures (can be added later)
- Sector auto-detection
- Upgrade / uninstall via this script (uninstall already handled by `scripts/uninstall.sh`)
