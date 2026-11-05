import json
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.services.policy import apply_policy_service as service


def test_apply_requires_a_new_engine_with_kernel_proof(tmp_path, monkeypatch):
    health = tmp_path / "health.json"
    health.write_text(json.dumps({"pid": 1}))
    marker = tmp_path / "apply-policy"
    monkeypatch.setattr(service, "APPLY_REQUEST", marker)
    monkeypatch.setenv("MINIFW_HEALTH_FILE", str(health))
    monkeypatch.setattr(service, "assess", lambda s: {"kernel_rule_present": s["pid"] == 2})

    def restart(_):
        assert marker.exists()
        marker.unlink()
        health.write_text(json.dumps({"pid": 2}))

    monkeypatch.setattr(service.time, "sleep", restart)
    assert service.apply_saved_policy()["engine_pid"] == 2


def test_apply_does_not_claim_success_if_restart_is_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "APPLY_REQUEST", tmp_path / "apply-policy")
    monkeypatch.setenv("MINIFW_HEALTH_FILE", str(tmp_path / "missing"))
    monkeypatch.setattr(service.time, "monotonic", Mock(side_effect=[0, 16]))
    with pytest.raises(TimeoutError):
        service.apply_saved_policy()
    with pytest.raises(FileExistsError):
        service.apply_saved_policy()


@pytest.mark.parametrize("permitted,origin", [(False, "https://test"), (True, "https://other"), (True, "")])
def test_apply_rejects_unprivileged_or_cross_origin_request(monkeypatch, permitted, origin):
    monkeypatch.setenv("MINIFW_SECRET_KEY", "wednesday-test-only-secret-key")
    pytest.importorskip("passlib")
    from app.web.routers.admin import apply_policy
    apply = Mock()
    monkeypatch.setattr(service, "apply_saved_policy", apply)
    user = Mock(is_active=True, is_locked=False)
    user.has_permission.return_value = permitted
    request = Request({"type": "http", "scheme": "https", "server": ("test", 443),
                       "path": "/admin/policy/apply", "headers": [(b"host", b"test"), (b"origin", origin.encode())]})
    with pytest.raises(HTTPException) as error:
        apply_policy(request, user, Mock())
    assert error.value.status_code == 403
    apply.assert_not_called()
