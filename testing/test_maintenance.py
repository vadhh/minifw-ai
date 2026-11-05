import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile

import pytest

from minifw_ai.maintenance import allowed, database_copy, validate_archive


def write_archive(path, name="opt/minifw_ai/config/policy.json", data=b"{}", version="2.2.10-finance", digest=None, link=False):
    metadata = {"schema": 1, "version": version, "entries": {
        name: {"sha256": digest or hashlib.sha256(data).hexdigest(), "mode": 0o600}}}
    with tarfile.open(path, "w:gz") as out:
        content = json.dumps(metadata).encode()
        member = tarfile.TarInfo("minifw-backup.json")
        member.size = len(content)
        out.addfile(member, io.BytesIO(content))
        member = tarfile.TarInfo(name)
        member.size = len(data)
        if link:
            member.type, member.linkname, member.size = tarfile.SYMTYPE, "/etc/shadow", 0
        out.addfile(member, None if link else io.BytesIO(data))


def test_restore_hash_and_edition(tmp_path):
    archive = tmp_path / "backup.tar.gz"
    write_archive(archive)
    metadata = validate_archive(archive, tmp_path / "out", "2.2.10-finance")
    target = tmp_path / "out/opt/minifw_ai/config/policy.json"
    assert target.read_bytes() == b"{}" and target.stat().st_mode & 0o777 == 0o600
    assert metadata["version"] == "2.2.10-finance"


@pytest.mark.parametrize("options", [{"version": "2.2.10-education"}, {"digest": "bad"},
    {"name": "../../etc/shadow"}, {"name": "/etc/shadow"}, {"name": "etc/shadow"}, {"link": True}])
def test_unsafe_restore_rejected(tmp_path, options):
    archive = tmp_path / "bad.tar.gz"
    write_archive(archive, **options)
    with pytest.raises(ValueError):
        validate_archive(archive, tmp_path / "out", "2.2.10-finance")


def test_database_backup_includes_committed_wal(tmp_path):
    source, target = tmp_path / "source.db", tmp_path / "copy.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE fixture (value TEXT)")
        connection.execute("INSERT INTO fixture VALUES ('committed')")
        connection.commit()
        database_copy(source, target)
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT value FROM fixture").fetchall() == [("committed",)]


@pytest.mark.parametrize("name", ["/opt/minifw_ai/config/a", "etc/shadow", "opt/minifw_ai/config/../app/a"])
def test_paths_are_restricted(name):
    assert not allowed(name)


def test_restore_publish_replaces_symlink_instead_of_following(tmp_path):
    import os
    from minifw_ai.maintenance import publish, read_regular
    victim = tmp_path / "victim"
    victim.write_bytes(b"untouched")
    target = tmp_path / "minifw.db"
    target.symlink_to(victim)
    with pytest.raises(ValueError):
        read_regular(target)  # a planted link is refused, never read through
    publish(target, b"restored", 0o640, os.getuid(), os.getgid())
    assert victim.read_bytes() == b"untouched"
    assert not target.is_symlink() and target.read_bytes() == b"restored"
    assert target.stat().st_mode & 0o777 == 0o640
    assert sorted(p.name for p in tmp_path.iterdir()) == ["minifw.db", "victim"]


def test_read_regular_returns_owner_and_mode(tmp_path):
    import os
    from minifw_ai.maintenance import read_regular
    path = tmp_path / "policy.json"
    path.write_bytes(b"{}")
    path.chmod(0o664)
    assert read_regular(path) == (b"{}", 0o664, os.getuid(), os.getgid())
    assert read_regular(tmp_path / "absent") is None


def test_read_regular_rejects_fifo_without_blocking(tmp_path):
    import os
    from minifw_ai.maintenance import read_regular
    fifo = tmp_path / "minifw.db"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        read_regular(fifo)
