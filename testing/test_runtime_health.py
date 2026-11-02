import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from minifw_ai import runtime_health as health


@pytest.fixture
def snapshot(monkeypatch):
    original = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda path, *a, **kw: "boot" if str(path).endswith("random/boot_id") else original(path, *a, **kw))
    monkeypatch.setattr(health, "process_identity", lambda pid: "123")
    return {"pid": 42, "process_start": "123", "boot_id": "boot", "heartbeat": 99,
            "kernel_ready": True, "kernel_checked": 98, "sources": {"packet": 99}}


def test_ready_requires_recent_decisions_and_kernel(snapshot):
    assert health.assess(snapshot, 100)["status"] == "ready"


@pytest.mark.parametrize("change", [
    {"boot_id": "old"}, {"process_start": "old"}, {"heartbeat": 90}, {"heartbeat": 101},
    {"kernel_ready": False}, {"kernel_checked": 80}, {"sources": {}},
    {"sources": {"packet": None}}, {"sources": {"packet": 60}},
    {"sources": {"packet": 99, "dns": None}}, {"heartbeat": float("nan")},
])
def test_unverified_is_not_ready(snapshot, change):
    snapshot.update(change)
    assert health.assess(snapshot, 100)["status"] == "not_ready"


def test_dead_process_fails_closed(snapshot, monkeypatch):
    monkeypatch.setattr(health, "process_identity", Mock(side_effect=FileNotFoundError))
    assert health.assess(snapshot, 100)["status"] == "not_ready"


def test_health_route_missing_file_is_503(tmp_path, monkeypatch):
    from app.web.routers.health import health_check
    monkeypatch.setenv("MINIFW_HEALTH_FILE", str(tmp_path / "absent"))
    assert health_check().status_code == 503


def test_publisher_is_atomic_and_group_readable(snapshot, tmp_path, monkeypatch):
    monitor = object.__new__(health.RuntimeHealth)
    monitor.path, monitor.snapshot = tmp_path / "health.json", snapshot
    monitor.kernel, monitor.last_write = (True, 99), 0
    monkeypatch.setattr(health.time, "monotonic", lambda: 100)
    monitor.observe("packet")
    assert json.loads(monitor.path.read_text())["sources"]["packet"] == 100
    # Group-readable for the non-root dashboard; never world-readable.
    assert monitor.path.stat().st_mode & 0o777 == 0o640
    assert list(tmp_path.iterdir()) == [monitor.path]


def test_kernel_requires_forward_source_drop_and_set(monkeypatch):
    objects = [{"set": {"name": "blocked", "type": "ipv4_addr"}},
               {"chain": {"name": "forward", "hook": "forward"}},
               {"rule": {"chain": "forward", "expr": [
                   {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blocked"}},
                   {"drop": None}]}}]
    result = Mock(stdout=json.dumps({"nftables": objects}))
    monkeypatch.setattr(health.subprocess, "run", Mock(return_value=result))
    assert health.kernel_ready("minifw", "forward", "blocked")
    objects[-1]["rule"]["expr"][-1] = {"accept": None}
    result.stdout = json.dumps({"nftables": objects})
    assert not health.kernel_ready("minifw", "forward", "blocked")
