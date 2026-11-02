"""Private, quiesced backups; restore only the same v2.2.10 edition."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone

APP = Path("/opt/minifw_ai")
SERVICES = ["minifw-ai-web", "minifw-ai"]
PREFIXES = ("opt/minifw_ai/config/", "opt/minifw_ai/models/", "opt/minifw_ai/yara_rules/", "etc/minifw/tls/")
# Dashboard state lives in /var/lib/minifw-ai since the dashboard runs as minifw-web.
FILES = {"var/lib/minifw-ai/minifw.db", "var/lib/minifw-ai/license.json", "etc/minifw/minifw.env",
         "etc/systemd/system/minifw-ai.service", "etc/systemd/system/minifw-ai-web.service"}


def allowed(name):
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and (
        name in FILES or any(name.startswith(prefix) for prefix in PREFIXES))


def package_version():
    version = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", "minifw-ai"], text=True).strip()
    if version not in {"2.2.10-finance", "2.2.10-education"}:
        raise ValueError("Only Financial/Education v2.2.10 is supported")
    return version


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def database_copy(source, target):
    with sqlite3.connect("file:" + str(source) + "?mode=ro", uri=True) as current:
        with sqlite3.connect(target) as snapshot:
            current.backup(snapshot)
            if snapshot.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ValueError("Database integrity check failed")


def create_archive(stage, destination, paths, version):
    entries = {}
    for path in paths:
        name = str(path).lstrip("/")
        if not path.is_file() or path.is_symlink() or not allowed(name):
            raise ValueError("Backup requires regular files in the declared scope")
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.name == "minifw.db":
            database_copy(path, target)
        else:
            shutil.copyfile(path, target)
        entries[name] = {"sha256": digest(target), "mode": stat.S_IMODE(path.stat().st_mode) & 0o777}
    metadata = {"schema": 1, "version": version, "created": datetime.now(timezone.utc).isoformat(),
                "entries": entries, "scope": "Configuration/models/database/env/TLS/base units; no package code or dynamic blocks"}
    with tarfile.open(destination, "x:gz") as archive:
        data = json.dumps(metadata).encode()
        member = tarfile.TarInfo("minifw-backup.json")
        member.size, member.mode = len(data), 0o600
        archive.addfile(member, io.BytesIO(data))
        for name in entries:
            archive.add(stage / name, arcname=name, recursive=False)
    destination.chmod(0o600)
    return metadata


def validate_archive(archive_path, stage, version):
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 20000 or sum(member.size for member in members) > 2 * 1024**3:
            raise ValueError("Backup exceeds restoration limits")
        names = [member.name for member in members]
        if len(names) != len(set(names)) or names.count("minifw-backup.json") != 1:
            raise ValueError("Duplicate/missing archive metadata")
        if any(not member.isfile() or (member.name != "minifw-backup.json" and not allowed(member.name)) for member in members):
            raise ValueError("Unsafe archive member")
        metadata = json.load(archive.extractfile("minifw-backup.json"))
        if metadata.get("schema") != 1 or metadata.get("version") != version:
            raise ValueError("Different backup schema or edition/version")
        if set(metadata["entries"]) != set(names) - {"minifw-backup.json"}:
            raise ValueError("Archive membership differs from manifest")
        for name, entry in metadata["entries"].items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(name) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            if digest(target) != entry["sha256"]:
                raise ValueError("Backup checksum mismatch")
            target.chmod(int(entry["mode"]) & 0o777)
        database = stage / "var/lib/minifw-ai/minifw.db"
        if database.exists():
            with sqlite3.connect(database) as connection:
                if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise ValueError("Corrupt backup database")
    return metadata


def read_regular(path):
    """(bytes, mode, uid, gid) of an existing regular file without following symlinks, else None.

    Restore runs as root inside directories the dashboard user can write, so a planted
    symlink or special file must never be read through or replaced in place."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ValueError(f"Restore destination is not a regular file: {path}") from error
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Restore destination is not a regular file: {path}")
        return handle.read(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid


def publish(target, data, mode, uid, gid):
    """Write via an unpredictable O_EXCL temp file in the target directory, then rename over it.

    Ownership and mode are set on the descriptor, and rename replaces a path rather than
    following it, so no symlink in the directory is ever dereferenced."""
    fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=target.parent)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def restart(services):
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    for service in reversed(services):
        subprocess.run(["systemctl", "start", service], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "restore"])
    parser.add_argument("archive", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Root is required for service quiescence and protected files")
    os.umask(0o077)
    version = package_version()
    folder = APP / "backups"
    folder.mkdir(mode=0o700, exist_ok=True)
    folder.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=folder) as temporary:
        stage = Path(temporary)
        archive = Path(args.archive).resolve() if args.archive else folder / (
            "minifw-backup-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".tar.gz")
        metadata = None
        if args.action == "restore":
            if args.archive is None:
                parser.error("Restore requires an explicit archive")
            info = archive.stat()
            if info.st_uid != 0 or info.st_mode & 0o077:
                parser.error("Restore archive must be root-owned and private (0600)")
            metadata = validate_archive(archive, stage, version)
        active = [service for service in SERVICES if subprocess.run(
            ["systemctl", "is-active", "--quiet", service]).returncode == 0]
        previous = {}
        try:
            subprocess.run(["systemctl", "stop", *SERVICES], check=True)
            if args.action == "backup":
                paths = [Path("/" + name) for name in FILES if Path("/" + name).is_file()]
                for prefix in PREFIXES:
                    paths.extend(path for path in Path("/" + prefix).rglob("*") if path.is_file())
                create_archive(stage, archive, paths, version)
                print("BACKUP", archive, "SHA256", digest(archive))
            else:
                for name, entry in metadata["entries"].items():
                    target = Path("/" + name)
                    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents):
                        raise ValueError("Restore destination has a symlink")
                    candidates = [target] + ([Path(str(target) + suffix) for suffix in ("-wal", "-shm")] if target.name == "minifw.db" else [])
                    for candidate in candidates:
                        previous[candidate] = read_regular(candidate)
                        if candidate != target:
                            candidate.unlink(missing_ok=True)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # Keep the installed owner (e.g. minifw-web state, dashboard-editable feeds);
                    # a file that did not exist takes its directory's owner.
                    owner = previous[target][2:] if previous[target] else (os.lstat(target.parent).st_uid, os.lstat(target.parent).st_gid)
                    publish(target, (stage / name).read_bytes(), int(entry["mode"]) & 0o777, *owner)
                print("RESTORED", version, "; dynamic nftables blocks and package code were not restored")
        except Exception:
            for target, saved in previous.items():
                if saved is None:
                    target.unlink(missing_ok=True)
                else:
                    publish(target, *saved)
            raise
        finally:
            restart(active)


if __name__ == "__main__":
    main()
