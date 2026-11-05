"""Destructive installation acceptance ONLY on the two disposable Monday QEMU guests.

Keeps a private on-guest state backup. Never exports secrets or database contents.
Usage: sudo python3 lab_install_upgrade.py education|financial C16.deb
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main(edition, package):
    assert edition in {"education", "financial"}
    assert socket.gethostname() == "minifw-monday-" + edition
    assert os.geteuid() == 0
    assert run("systemd-detect-virt") in {"kvm", "qemu"}
    sector = "education" if edition == "education" else "finance"
    mode = "minifw_school" if edition == "education" else "minifw_financial"
    assert run("dpkg-deb", "-f", package, "Version") == "2.2.10-" + sector
    backup = Path("/var/tmp/minifw-tuesday-private-backup")
    backup.mkdir(mode=0o700)  # Refuse to overwrite any previous execution.
    app = Path("/opt/minifw_ai")
    state = Path("/var/lib/minifw-ai")
    run("systemctl", "stop", "minifw-ai", "minifw-ai-web", "dnsmasq")
    paths = [p for p in ["etc/minifw", "var/lib/minifw-ai", "opt/minifw_ai/config",
                        "opt/minifw_ai/minifw.db", "etc/systemd/system/minifw-ai.service",
                        "etc/systemd/system/minifw-ai-web.service"] if Path("/" + p).exists()]
    run("tar", "czf", str(backup / "state.tar.gz"), "-C", "/", *paths)
    print("PRIVATE_STATE_BACKUP_RETAINED_ON_GUEST", flush=True)

    def install(deb, label):
        log = backup / (label + ".log")
        with log.open("w") as output:
            result = subprocess.run(["dpkg", "--force-confold", "-i", str(deb)], stdout=output,
                                    stderr=subprocess.STDOUT,
                                    env={**os.environ, "MINIFW_SECTOR": sector, "PRODUCT_MODE": mode})
        print(label, "dpkg_exit", result.returncode, flush=True)
        # Logs may contain generated passwords; retain privately and emit only status.
        result.check_returncode()
        time.sleep(3)
        assert run("systemctl", "is-active", "minifw-ai", "minifw-ai-web").splitlines() == ["active", "active"]

    def ownership(label):
        roots = [app / name for name in ("app", "models", "scripts", "prometheus", "scheduler", "yara_rules", "venv")]
        checked = 0
        for base in roots:
            for path in [base, *base.rglob("*")]:
                if path.is_symlink():
                    assert path.lstat().st_uid == 0, str(path)
                    continue
                st = path.stat()
                assert st.st_uid == 0 and not st.st_mode & 0o022, str(path)
                checked += 1
        for path in [Path("/"), Path("/opt"), app, app / "config", app / "config/feeds",
                     app / "config/modes", app / "requirements.txt", app / "config/license_public_keys.json",
                     Path("/etc"), Path("/etc/minifw"), Path("/etc/minifw/minifw.env"),
                     Path("/etc/systemd/system/minifw-ai.service"), Path("/usr/bin/python3").resolve()]:
            st = path.stat()
            assert st.st_uid == 0 and not st.st_mode & 0o022, str(path)
        probe = '''import os,sys
from pathlib import Path
bad=[]
for index,base in enumerate(sys.argv[1:]):
 p=Path(base)
 for f in [p,*p.rglob("*")] if index and p.is_dir() else [p]:
  if os.access(f,os.W_OK): bad.append(str(f))
assert not bad,bad[:10]
print("WRITE_ATTEMPTS_DENIED")
'''
        for user in ("debian", "minifw-web"):
            result = run("runuser", "-u", user, "--", "/usr/bin/python3", "-c", probe,
                         str(app), *map(str, roots), str(app / "requirements.txt"),
                         str(app / "config/license_public_keys.json"))
            # app itself is protected, but editable config/log descendants are intentional.
            print(label, user, result, flush=True)
        print(label, "ROOT_OWNERSHIP_FILES", checked, flush=True)

    # Fresh package state, retaining only cached dependencies (not a pristine OS).
    cached = backup / "cached-venv"
    shutil.move(str(app / "venv"), cached)
    run("dpkg", "--purge", "minifw-ai")
    shutil.rmtree(app)
    app.mkdir()
    shutil.move(cached, app / "venv")
    (app / "app").mkdir()
    run("chown", "debian:debian", str(app), str(app / "app"))
    install(package, "fresh")
    ownership("fresh")
    print("FRESH_PACKAGE_INSTALL_PASS_CACHED_DEPENDENCIES", flush=True)

    # Reset only disposable lab state for the old-layout C13 migration baseline.
    run("systemctl", "stop", "minifw-ai", "minifw-ai-web")
    shutil.rmtree(state)
    baseline = Path(f"/home/lab/v2210-c13-candidate/minifw-ai-{edition}-v2.2.10-source-assessment/build/minifw-ai_2.2.10-{sector}_amd64.deb")
    assert baseline.is_file()
    install(baseline, "baseline-c13")
    run("systemctl", "stop", "minifw-ai", "minifw-ai-web")
    db = app / "minifw.db"
    assert db.is_file()
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE tuesday_probe (value TEXT)")
        connection.execute("INSERT INTO tuesday_probe VALUES (?)", (edition,))
        admin = connection.execute("SELECT * FROM users WHERE username='admin'").fetchone()
        assert admin
    licence = Path("/etc/minifw/license.json")
    licence.write_text(json.dumps({"lab_migration_marker": edition}))
    licence.chmod(0o600)
    licence_hash = hashlib.sha256(licence.read_bytes()).hexdigest()
    policy = app / f"config/modes/{mode}/policy.json"
    contents = json.loads(policy.read_text())
    contents["tuesday_migration_marker"] = edition
    policy.write_text(json.dumps(contents, indent=2))
    policy_bytes = policy.read_bytes()
    # Reproduce the image ownership defect on pre-existing executable directories.
    run("chown", "debian:debian", str(app), str(app / "app"), str(app / "venv"))
    install(package, "upgrade-c13-c16")
    ownership("upgrade")
    with sqlite3.connect(state / "minifw.db") as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM tuesday_probe").fetchone() == (edition,)
        assert connection.execute("SELECT * FROM users WHERE username='admin'").fetchone() == admin
    assert not db.exists()
    assert hashlib.sha256((state / "license.json").read_bytes()).hexdigest() == licence_hash
    assert policy.read_bytes() == policy_bytes
    print("MIGRATION_PASS", edition, "database_integrity admin_row licence_bytes policy_bytes", flush=True)
    print("LICENCE_TEST_SCOPE byte preservation of lab fixture; activation not qualified", flush=True)
    # Restore package policy bytes for subsequent strict identity and routed tests.
    extracted = backup / "payload"
    run("dpkg-deb", "-x", package, str(extracted))
    policy.write_bytes((extracted / str(policy).lstrip("/")).read_bytes())
    assert run("dpkg", "--verify", "minifw-ai") == ""
    print("DPKG_VERIFY_CLEAN", flush=True)
    print("PACKAGE_SHA256", hashlib.sha256(Path(package).read_bytes()).hexdigest(), flush=True)
    print("INSTALL_UPGRADE_ACCEPTANCE_PASS", edition, flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
