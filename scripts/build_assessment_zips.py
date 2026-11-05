#!/usr/bin/env python3
"""Create the Education and Financial source kits without local runtime data."""

import ast
import hashlib
import json
import re
import stat
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "production-assessment"
SECTORS = {"education": "minifw_school", "financial": "minifw_financial"}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build():
    version = re.search(r'^version = "([0-9.]+)"', (ROOT / "pyproject.toml").read_text(), re.M)[1]
    tracked = set(git("ls-files", "-z").split("\0"))
    paths = {
        p for p in tracked
        if p.startswith(("app/", "prometheus/", "scheduler/", "config/feeds/", "yara_rules/"))
    }
    paths.update({
        "requirements.txt", "models/mlp_model.pkl", "config/policy.json",
        "config/license_public_keys.json", "app/minifw_ai/licensing.py",
        "app/web/templates/admin/license.html", "docs/licensing.md",
        "systemd/minifw-ai.service", "systemd/minifw-ai-web.service",
        "scripts/build_deb.sh", "scripts/backup.sh", "scripts/restore.sh",
        "scripts/create_admin.py", "scripts/train_mlp.py",
        "scripts/enable_dnsmasq_logging.sh", "scripts/uninstall.sh",
    })
    # Include only the dashboard's built AdminLTE runtime and its license.
    paths = {
        p for p in paths if not p.startswith("app/web/static/adminLTE/")
        or p.startswith("app/web/static/adminLTE/src/html/public/")
        or p == "app/web/static/adminLTE/LICENSE"
    }
    source = {}
    normalized = []
    for name in sorted(paths):
        path = ROOT / name
        assert path.is_file() and not path.is_symlink(), f"Missing or symlinked input: {name}"
        assert not any(part.startswith(".") or part in {"__pycache__", "node_modules", "logs"} for part in path.relative_to(ROOT).parts)
        assert path.suffix.lower() not in {".db", ".sqlite3", ".pem", ".key", ".pyc", ".jsonl"}
        data = path.read_bytes()
        assert not re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", data), f"Private key in {name}"
        if path.suffix in {".sh", ".service"} and b"\r\n" in data:
            data = data.replace(b"\r\n", b"\n")
            normalized.append(name)
        if path.suffix == ".py":
            ast.parse(data, filename=name)
        if path.suffix == ".sh":
            subprocess.run(["bash", "-n"], input=data, check=True)
        if path.suffix == ".json":
            json.loads(data)
        source[name] = data

    # Verify local static paths used by the templates are all included.
    for name, data in source.items():
        if name.endswith(".html"):
            for asset in re.findall(r"url_for\(['\"]static['\"],\s*path=['\"]([^'\"]+)", data.decode()):
                assert "app/web/static/" + asset in source, f"Missing static asset: {asset}"

    OUTPUT.mkdir(parents=True, exist_ok=True)
    hashes = []
    changed = set(git("diff", "HEAD", "--name-only").splitlines())
    for label, mode in SECTORS.items():
        sector = "finance" if label == "financial" else label
        name = f"minifw-ai-{label}-v{version}-source-assessment"
        policy_path = f"config/modes/{mode}/policy.json"
        policy = (ROOT / policy_path).read_bytes()
        assert json.loads(policy)["_mode"] == mode
        assert json.loads(policy)["_sector"] == sector
        payload = {**source, policy_path: policy}
        payload["ASSESSMENT.md"] = (ROOT / "docs/deployment-assessment.md").read_bytes()
        payload["START_HERE.md"] = f"""# MiniFW-AI {label.title()} deployment assessment

Version: {version} working-tree snapshot. Sector: `{sector}`.
Product mode: `{mode}`. Target: Linux amd64.

Start with [ASSESSMENT.md](ASSESSMENT.md) for the CEO decision brief,
deployment effects, installation, acceptance checklist and rollback.
This source kit requires a Linux build. It contains no prebuilt `.deb`, Python
environment, offline dependencies or simulated event data.

## Verify and build

From this extracted directory on Ubuntu 22.04 / Debian 12 amd64:

```bash
sha256sum -c SHA256SUMS
sudo apt update
sudo apt install -y dpkg-dev coreutils sed
bash scripts/build_deb.sh {sector} {version}
(cd build && sha256sum -c minifw-ai_{version}-{sector}_amd64.deb.sha256)
```

The output is `build/minifw-ai_{version}-{sector}_amd64.deb`.
Continue with the install and verification steps in `ASSESSMENT.md`.
Never install both sector packages on the same gateway for comparison.

## Source provenance

Base Git commit: `{git('rev-parse', 'HEAD')}`.
Included local changes and file hashes are recorded in `MANIFEST.json`.
This snapshot includes local licensing changes and is not a signed release.
Only the vendor public license verification key is included. A customer license
must be issued for this installation's deployment ID and `{mode}`.

The core engine and shared detection rules are common to the two kits.
The selected policy and the build command choose this sector.
Sample subnets, feeds, broad baseline YARA rules and thresholds need review
against the deployment network before live use.

## Contents

- `app/`, `prometheus/`, `scheduler/`: engine, admin UI and supporting modules.
- `config/`: base config, feeds, public license keys and this sector's policy.
- `models/`, `yara_rules/`: bundled MLP model and shared detection rules.
- `scripts/`, `systemd/`: native package builder, operational helpers and units.
- `docs/licensing.md`: offline licensing and renewal procedure.
- `MANIFEST.json`, `SHA256SUMS`: provenance and file integrity checks.

Checksums detect corruption; they do not authenticate the publisher.
""".encode()
        included_changes = sorted(p for p in payload if p in changed or (p in paths and p not in tracked))
        manifest = {
            "version": version, "sector": sector, "product_mode": mode,
            "artifact_type": "source-deployment-assessment",
            "base_commit": git("rev-parse", "HEAD"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "included_local_changes": included_changes,
            "normalized_lf_files": normalized,
            "checks": ["python_ast", "bash_syntax", "json_parse", "required_inputs", "sector_mapping", "template_static_assets", "zip_crc", "sha256"],
            "not_verified": ["linux_deb_build", "linux_install", "live_enforcement", "browser", "performance", "full_security_audit"],
            "files": {p: digest(data) for p, data in sorted(payload.items())},
        }
        payload["MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        payload["SHA256SUMS"] = "".join(f"{digest(data)}  {p}\n" for p, data in sorted(payload.items())).encode()
        target = OUTPUT / f"{name}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
            for p, data in sorted(payload.items()):
                info = zipfile.ZipInfo(f"{name}/{p}")
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o755 if p.endswith(".sh") else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        with zipfile.ZipFile(target) as archive:
            assert archive.testzip() is None
            assert len(archive.namelist()) == len(payload)
            for p, data in payload.items():
                assert digest(archive.read(f"{name}/{p}")) == digest(data), p
        hashes.append(f"{digest(target.read_bytes())}  {target.name}\n")
        print(f"PASS {target.relative_to(ROOT)}: {len(payload)} files, {target.stat().st_size:,} bytes")
    (OUTPUT / "SHA256SUMS").write_text("".join(hashes))


if __name__ == "__main__":
    build()
