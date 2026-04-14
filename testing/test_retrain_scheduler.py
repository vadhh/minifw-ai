"""
Retraining Scheduler Tests

Tests auto-labeling logic, model training, and atomic model file swap.
"""
import json
import os
import pickle
import tempfile
from pathlib import Path

import pytest

from scheduler.retrain_scheduler import (
    load_and_label_records,
    train_model_from_records,
    atomic_save_model,
    retrain_job,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_flow_record(action: str, label=None, features=None):
    """Create a single flow_records.jsonl entry."""
    if features is None:
        # 24 plausible feature values
        features = [
            5.0, 50.0, 75000.0, 15000.0, 10.0,  # duration, pkts, bytes, bps, pps
            1500.0, 200.0, 0.5,                    # avg_pkt, std, ratio
            20.0, 30000.0, 50.0, 10.0, 100.0, 0.1, # burst/iat
            1.0, 0.0, 0.0, 11.0, 0.0, 0.0,        # TLS
            1.0, 15.0, 1.0, 0.0,                   # DNS
        ]
    return {"action": action, "label": label, "features": features}


@pytest.fixture
def flow_records_file(tmp_path):
    """Create a flow_records.jsonl with mixed actions and labels."""
    records = (
        # 15 blocks (label=1), 15 allows (label=0), 5 monitors (skipped)
        [_make_flow_record("block") for _ in range(15)]
        + [_make_flow_record("allow") for _ in range(15)]
        + [_make_flow_record("monitor") for _ in range(5)]
    )
    path = tmp_path / "flow_records.jsonl"
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return str(path)


@pytest.fixture
def small_records_file(tmp_path):
    """Too few records for training."""
    records = [_make_flow_record("block") for _ in range(3)]
    path = tmp_path / "flow_records.jsonl"
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return str(path)


# ---------------------------------------------------------------------------
# load_and_label_records()
# ---------------------------------------------------------------------------

class TestLoadAndLabel:
    def test_labels_block_as_1(self, flow_records_file):
        records = load_and_label_records(flow_records_file)
        blocks = [r for r in records if r["label"] == 1]
        assert len(blocks) == 15

    def test_labels_allow_as_0(self, flow_records_file):
        records = load_and_label_records(flow_records_file)
        allows = [r for r in records if r["label"] == 0]
        assert len(allows) == 15

    def test_skips_monitor_records(self, flow_records_file):
        records = load_and_label_records(flow_records_file)
        # 15 block + 15 allow = 30 total (5 monitor skipped)
        assert len(records) == 30

    def test_returns_empty_for_missing_file(self):
        records = load_and_label_records("/nonexistent/path.jsonl")
        assert records == []

    def test_skips_malformed_json(self, tmp_path):
        path = tmp_path / "bad.jsonl"
        path.write_text("not json\n{bad json too\n")
        records = load_and_label_records(str(path))
        assert records == []

    def test_skips_records_without_features(self, tmp_path):
        path = tmp_path / "no_features.jsonl"
        path.write_text(json.dumps({"action": "block"}) + "\n")
        records = load_and_label_records(str(path))
        assert records == []

    def test_preserves_existing_labels(self, tmp_path):
        """If label is already set, use it instead of auto-labeling."""
        record = _make_flow_record("allow", label=1)  # allow but labeled as threat
        path = tmp_path / "pre_labeled.jsonl"
        path.write_text(json.dumps(record) + "\n")
        records = load_and_label_records(str(path))
        assert len(records) == 1
        assert records[0]["label"] == 1  # preserved, not overwritten to 0


# ---------------------------------------------------------------------------
# train_model_from_records()
# ---------------------------------------------------------------------------

class TestTrainModel:
    def test_trains_successfully(self, flow_records_file):
        records = load_and_label_records(flow_records_file)
        result = train_model_from_records(records)
        assert result is not None
        assert "model" in result
        assert "scaler" in result
        assert "metadata" in result
        assert result["metadata"]["n_samples"] == 30

    def test_returns_none_for_too_few_records(self):
        records = [
            {"features": [0.0] * 24, "label": 1},
            {"features": [1.0] * 24, "label": 0},
        ]
        result = train_model_from_records(records)
        assert result is None

    def test_returns_none_for_unbalanced_classes(self):
        # All same class
        records = [{"features": [float(i)] * 24, "label": 1} for i in range(25)]
        result = train_model_from_records(records)
        assert result is None


# ---------------------------------------------------------------------------
# atomic_save_model()
# ---------------------------------------------------------------------------

class TestAtomicSave:
    def test_model_file_written(self, tmp_path):
        model_path = str(tmp_path / "model.pkl")
        package = {"model": "fake_model", "scaler": "fake_scaler"}
        atomic_save_model(package, model_path)

        assert Path(model_path).exists()
        with open(model_path, "rb") as f:
            loaded = pickle.load(f)
        assert loaded["model"] == "fake_model"

    def test_overwrites_existing_model(self, tmp_path):
        model_path = str(tmp_path / "model.pkl")
        # Write v1
        atomic_save_model({"version": 1}, model_path)
        # Write v2
        atomic_save_model({"version": 2}, model_path)

        with open(model_path, "rb") as f:
            loaded = pickle.load(f)
        assert loaded["version"] == 2

    def test_no_temp_file_left_on_success(self, tmp_path):
        model_path = str(tmp_path / "model.pkl")
        atomic_save_model({"ok": True}, model_path)
        tmp_files = list(tmp_path.glob("mlp_model_*.tmp"))
        assert len(tmp_files) == 0


# ---------------------------------------------------------------------------
# retrain_job() end-to-end
# ---------------------------------------------------------------------------

class TestRetrainJob:
    def test_full_retrain_cycle(self, flow_records_file, tmp_path, monkeypatch):
        model_path = str(tmp_path / "output_model.pkl")
        monkeypatch.setenv("MINIFW_FLOW_RECORDS", flow_records_file)
        monkeypatch.setenv("MINIFW_MLP_MODEL", model_path)

        result = retrain_job()
        assert result is True
        assert Path(model_path).exists()

        with open(model_path, "rb") as f:
            package = pickle.load(f)
        assert "model" in package
        assert package["metadata"]["n_samples"] == 30

    def test_retrain_skips_when_no_records(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINIFW_FLOW_RECORDS", str(tmp_path / "empty.jsonl"))
        monkeypatch.setenv("MINIFW_MLP_MODEL", str(tmp_path / "model.pkl"))

        result = retrain_job()
        assert result is False
