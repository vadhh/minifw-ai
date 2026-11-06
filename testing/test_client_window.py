import json

import pytest

from minifw_ai import client_window as cw


def model_bytes(coef=0.5, intercept=-15.0, block_probability=0.9, **extra):
    data = dict(schema=cw.SCHEMA, features=list(cw.FEATURES), coef=[coef], intercept=intercept,
                block_probability=block_probability, **extra)
    return json.dumps(data).encode()


def test_window_counts_per_server_port_and_expires():
    w = cw.ClientWindow()
    assert w.add("10.0.0.5", "1.1.1.1", 443, 100.0) == {"n60": 1}
    assert w.add("10.0.0.5", "1.1.1.1", 443, 130.0) == {"n60": 2}
    assert w.add("10.0.0.5", "1.1.1.1", 22, 131.0) == {"n60": 1}
    assert w.add("10.0.0.6", "1.1.1.1", 443, 131.0) == {"n60": 1}
    assert w.add("10.0.0.5", "1.1.1.1", 443, 170.5) == {"n60": 2}  # 100.0 expired


def test_window_ignores_warmup_snapshot():
    w = cw.ClientWindow(ignore_before=1000.0)
    assert w.add("10.0.0.5", "1.1.1.1", 443, 999.0) is None
    assert w.add("10.0.0.5", "1.1.1.1", 443, 1000.0) == {"n60": 1}


def test_model_probability_and_validation():
    m = cw.WindowModel(model_bytes())
    assert m.probability({"n60": 10}) < 0.01
    assert m.probability({"n60": 40}) > 0.99
    assert m.probability({"n60": 10**9}) == pytest.approx(1.0)
    for bad in (model_bytes(block_probability=1.0), model_bytes(coef=float("nan")),
                json.dumps({"schema": "packet14-v1"}).encode(), b"not json"):
        with pytest.raises((ValueError, KeyError)):
            cw.WindowModel(bad)


def test_load_model_missing_or_corrupt_returns_none(tmp_path):
    assert cw.load_model(str(tmp_path / "missing.json")) is None
    (tmp_path / "bad.json").write_bytes(b"\x00garbage")
    assert cw.load_model(str(tmp_path / "bad.json")) is None


def test_may_isolate_requires_exact_approval_segment_and_not_exempt(tmp_path, monkeypatch):
    path = tmp_path / "m.json"
    path.write_bytes(model_bytes())
    m = cw.load_model(str(path))
    cfg = {"segments": ["student"], "exempt": ["10.10.0.99/32"]}

    monkeypatch.delenv("MINIFW_AI_ENFORCE_MODEL_SHA256", raising=False)
    assert not cw.may_isolate(m, 0.99, "student", "10.10.0.20", cfg)  # shadow by default

    monkeypatch.setenv("MINIFW_AI_ENFORCE_MODEL_SHA256", "0" * 64)
    assert not cw.may_isolate(m, 0.99, "student", "10.10.0.20", cfg)  # approval names another model

    monkeypatch.setenv("MINIFW_AI_ENFORCE_MODEL_SHA256", m.sha256.upper())
    assert cw.may_isolate(m, 0.99, "student", "10.10.0.20", cfg)
    assert not cw.may_isolate(m, 0.89, "student", "10.10.0.20", cfg)  # below block_probability
    assert not cw.may_isolate(m, 0.99, "admin", "10.10.0.20", cfg)  # segment not listed
    assert not cw.may_isolate(m, 0.99, "student", "10.10.0.99", cfg)  # exempt
    assert not cw.may_isolate(m, 0.99, "student", "fd00::1", cfg)  # IPv4-only enforcement
    assert not cw.may_isolate(None, 0.99, "student", "10.10.0.20", cfg)

    assert cw.client_in_scope("student", "10.10.0.20", cfg)
    assert not cw.client_in_scope("admin", "10.10.0.20", cfg)  # segment not listed
    assert not cw.client_in_scope("student", "10.10.0.99", cfg)  # exempt
    assert not cw.client_in_scope("student", "fd00::1", cfg)  # IPv6
    assert not cw.client_in_scope("student", "10.10.0.20", {})  # policy without ai_enforcement
