"""Tests for financial demo scheduler event generation."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

# NOTE: sys.path manipulation for the financial package is intentionally NOT done at module
# level — it would shadow the root scheduler/ package and break test_retrain_scheduler.py
# collection. The scheduler module is loaded via importlib with an absolute file path, so
# no sys.path change is required here. The demo_scheduler.py itself handles its own path
# setup when exec_module() runs.
#
# MINIFW_SECTOR and PRODUCT_MODE are likewise NOT set at module level to avoid polluting
# the environment for other test files (e.g. test_sector_lock.py uses monkeypatch to control
# these). They are set per-test via the `financial_env` fixture below.


@pytest.fixture(autouse=True)
def financial_env(monkeypatch):
    """Set financial sector env vars only for the duration of each test."""
    monkeypatch.setenv("MINIFW_SECRET_KEY", "test-key-financial-demo")
    monkeypatch.setenv("MINIFW_SECTOR", "finance")
    monkeypatch.setenv("PRODUCT_MODE", "minifw_financial")


def test_scheduler_imports():
    """Scheduler module is importable from the package."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "write_normal_event")
    assert hasattr(mod, "write_attack_sequence")
    assert hasattr(mod, "NORMAL_TRAFFIC")
    assert hasattr(mod, "ATTACK_SEQUENCE")


def test_normal_events_are_allow(tmp_path):
    """Normal events written by scheduler have action=allow and score<45."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)

    for entry in mod.NORMAL_TRAFFIC:
        mod.write_normal_event(writer, entry)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == len(mod.NORMAL_TRAFFIC)
    for line in lines:
        ev = json.loads(line)
        assert ev["action"] == "allow", f"Normal event should be allow, got: {ev['action']}"
        assert ev["score"] < 45, f"Normal event score {ev['score']} should be < 45"
        assert ev["sector"] == "finance"


def test_attack_sequence_ends_with_block(tmp_path):
    """Attack sequence produces a block event with score >= 80 in trading segment."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)
    mod.write_attack_sequence(writer)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) > 0

    events = [json.loads(l) for l in lines]
    block_events = [e for e in events if e["action"] == "block"]
    assert len(block_events) >= 1, "Attack sequence must produce at least one block event"

    final_block = block_events[-1]
    assert final_block["score"] >= 80, f"Block score {final_block['score']} must be >= 80"
    assert final_block["segment"] == "trading"
    assert final_block["client_ip"] == "10.50.0.1"
    assert final_block["severity"] == "critical"


def test_event_fields_complete(tmp_path):
    """Every event written has all required EventWriter fields."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)
    mod.write_normal_event(writer, mod.NORMAL_TRAFFIC[0])
    mod.write_attack_sequence(writer)

    required_fields = {"ts", "segment", "client_ip", "domain", "action", "score", "reasons", "sector"}
    for line in Path(log_path).read_text().strip().splitlines():
        ev = json.loads(line)
        missing = required_fields - ev.keys()
        assert not missing, f"Event missing fields: {missing}"
