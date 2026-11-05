"""Guarded C16-to-C17 upgrade; private backups and installer output stay on the guest."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys

edition, package = sys.argv[1:]
assert edition in {"education", "financial"}
assert socket.gethostname() == "minifw-monday-" + edition and os.geteuid() == 0
assert subprocess.check_output(["systemd-detect-virt"], text=True).strip() in {"kvm", "qemu"}
sector = "education" if edition == "education" else "finance"
mode = "minifw_school" if edition == "education" else "minifw_financial"
assert subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "minifw-ai"], text=True) == "2.2.10-" + sector
private = Path("/var/tmp/minifw-wednesday-private-backup")
private.mkdir(mode=0o700)
subprocess.run(["systemctl", "stop", "minifw-ai-web", "minifw-ai"], check=True)
paths = [Path("/var/lib/minifw-ai/minifw.db"), Path("/var/lib/minifw-ai/license.json"),
         Path("/var/lib/minifw-ai/installation-id"), Path("/etc/minifw/minifw.env"),
         Path(f"/opt/minifw_ai/config/modes/{mode}/policy.json")]
for index, path in enumerate(paths):
    if path.exists():
        shutil.copy2(path, private / str(index))

def preserved_state():
    with sqlite3.connect(paths[0]) as connection:
        assert connection.execute("pragma integrity_check").fetchone() == ("ok",)
        rows = connection.execute("select * from users order by id").fetchall()
    return {"users_sha256": hashlib.sha256(repr(rows).encode()).hexdigest(), "user_count": len(rows),
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None for path in paths[1:]}}

before = preserved_state()
with (private / "installer.log").open("w") as output:
    result = subprocess.run(["dpkg", "-i", package], stdout=output, stderr=subprocess.STDOUT)
assert result.returncode == 0, "Installer failed; inspect the private installer log"
subprocess.run(["systemctl", "stop", "minifw-ai-web", "minifw-ai"], check=True)
after = preserved_state()
assert before == after, "Upgrade changed preserved data; inspect private backups"
files = []
for folder in ["app", "venv", "models", "scripts", "prometheus", "scheduler", "yara_rules"]:
    for path in (Path("/opt/minifw_ai") / folder).rglob("*"):
        if path.is_file():
            stat = path.stat()
            assert stat.st_uid == 0 and not stat.st_mode & 0o022, str(path)
            files.append(str(path))
probes = ["/opt/minifw_ai/app/minifw_ai/main.py", "/opt/minifw_ai/venv/bin/python",
          "/opt/minifw_ai/models/mlp_model.pkl", "/opt/minifw_ai/scripts/backup.sh"]
code = """import json,sys
for path in json.load(sys.stdin):
 try:
  with open(path,'ab'): pass
 except PermissionError: continue
 raise AssertionError('Unprivileged write allowed: '+path)
print('write attempts denied')
"""
for user in ["lab", "minifw-web"]:
    result = subprocess.run(["runuser", "-u", user, "--", "python3", "-c", code],
                            input=json.dumps(probes), text=True, capture_output=True, check=True)
    print("WRITE_DENIED", user, result.stdout.strip())
assert subprocess.run(["systemctl", "is-enabled", "--quiet", "minifw-ai-apply.path"]).returncode == 0
print(json.dumps({"edition": edition, "package_sha256": hashlib.sha256(Path(package).read_bytes()).hexdigest(),
                  "upgrade_preserved": before, "root_owned_nonwritable_files": len(files), "apply_path_enabled": True}, indent=2))
