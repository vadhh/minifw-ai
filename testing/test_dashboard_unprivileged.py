"""The dashboard runs as minifw-web: no nft calls, state outside /opt/minifw_ai."""
import importlib
import json
from pathlib import Path

import pytest

from app.services.system import kernel_proof_service as proof

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_subprocess(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("dashboard must not run nft or other commands for kernel proof")
    monkeypatch.setattr("subprocess.run", refuse)


def test_kernel_proof_uses_engine_runtime_health(tmp_path, monkeypatch):
    health = tmp_path / "runtime-health.json"
    health.write_text("{}")
    monkeypatch.setenv("MINIFW_HEALTH_FILE", str(health))
    monkeypatch.setattr("minifw_ai.runtime_health.assess", lambda snapshot: {"status": "ready", "kernel_rule_present": True})
    assert proof.compute_kernel_proof()["active"] is True
    monkeypatch.setattr("minifw_ai.runtime_health.assess", lambda snapshot: {"status": "not_ready", "kernel_rule_present": False})
    result = proof.compute_kernel_proof()
    assert result["active"] is False and "missing" in result["detail"]


def test_kernel_proof_falls_back_to_audit_without_claiming_live(tmp_path, monkeypatch):
    monkeypatch.setenv("MINIFW_HEALTH_FILE", str(tmp_path / "absent.json"))
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"action": "firewall_init"}) + "\n")
    monkeypatch.setenv("MINIFW_AUDIT_LOG", str(audit))
    result = proof.compute_kernel_proof()
    assert result["active"] is True and "not currently verified" in result["label"]


def test_database_path_follows_environment(tmp_path, monkeypatch):
    import app.database as database
    monkeypatch.setenv("MINIFW_DB_PATH", str(tmp_path / "state" / "minifw.db"))
    try:
        assert importlib.reload(database).DATABASE_PATH == tmp_path / "state" / "minifw.db"
    finally:
        monkeypatch.delenv("MINIFW_DB_PATH")
        importlib.reload(database)


def test_web_unit_is_unprivileged_and_shares_engine_policy():
    web = (ROOT / "systemd" / "minifw-ai-web.service").read_text()
    assert "User=minifw-web" in web and "User=root" not in web
    assert "\nCapabilityBoundingSet=\n" in web and "CAP_NET_ADMIN" not in web
    assert "MINIFW_DB_PATH=/var/lib/minifw-ai/minifw.db" in web
    build = (ROOT / "scripts" / "build_deb.sh").read_text()
    # The build bakes the same sector policy into both units.
    assert '"${BUILD_DIR}/etc/systemd/system/minifw-ai.service" \\\n        "${BUILD_DIR}/etc/systemd/system/minifw-ai-web.service"' in build
