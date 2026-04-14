"""
Automated ML Retraining Scheduler for MiniFW-AI

Periodically reads flow_records.jsonl, auto-labels unlabeled entries,
trains a new MLP model, and atomically swaps the model file.

Usage:
    python -m scheduler.retrain_scheduler          # run scheduler loop
    python -m scheduler.retrain_scheduler --once    # single retrain run
"""
from __future__ import annotations

import json
import logging
import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

import schedule

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_and_label_records(flow_records_path: str) -> list[dict]:
    """Read flow_records.jsonl and auto-label entries where label is None.

    Labeling rules:
        action == "block"   → label = 1 (threat)
        action == "allow"   → label = 0 (benign)
        action == "monitor" → skipped (ambiguous)

    Returns list of dicts with 'features' and 'label' keys.
    """
    path = Path(flow_records_path)
    if not path.exists():
        logger.warning("[RETRAIN] flow_records file not found: %s", flow_records_path)
        return []

    labeled = []
    skipped = 0

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("[RETRAIN] Skipping malformed JSON at line %d", line_no)
                continue

            features = record.get("features")
            if not features or not isinstance(features, list):
                continue

            # Use existing label if present, otherwise auto-label
            label = record.get("label")
            if label is None:
                action = record.get("action")
                if action == "block":
                    label = 1
                elif action == "allow":
                    label = 0
                else:
                    skipped += 1
                    continue

            labeled.append({"features": features, "label": int(label)})

    if skipped:
        logger.info("[RETRAIN] Skipped %d monitor/ambiguous records", skipped)
    logger.info("[RETRAIN] Loaded %d labeled records", len(labeled))
    return labeled


def train_model_from_records(records: list[dict]) -> dict[str, Any] | None:
    """Train an MLP model from labeled records.

    Returns a model package dict (model, scaler, metadata) or None on failure.
    """
    try:
        import numpy as np
        import pandas as pd
        from sklearn.neural_network import MLPClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
    except ImportError as e:
        logger.error("[RETRAIN] Missing ML dependencies: %s", e)
        return None

    if len(records) < 20:
        logger.warning(
            "[RETRAIN] Not enough records for training (%d < 20)", len(records)
        )
        return None

    X = np.array([r["features"] for r in records], dtype=np.float64)
    y = np.array([r["label"] for r in records], dtype=np.int64)

    # Check class balance
    n_positive = int(y.sum())
    n_negative = len(y) - n_positive
    if n_positive < 5 or n_negative < 5:
        logger.warning(
            "[RETRAIN] Insufficient class balance: %d positive, %d negative",
            n_positive,
            n_negative,
        )
        return None

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train
    model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=200,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.15,
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    accuracy = model.score(X_test_scaled, y_test)
    logger.info("[RETRAIN] Model accuracy: %.4f", accuracy)

    from datetime import datetime

    model_package = {
        "model": model,
        "scaler": scaler,
        "metadata": {
            "trained_at": datetime.now().isoformat(),
            "n_samples": len(records),
            "n_features": X.shape[1],
            "accuracy": accuracy,
            "class_distribution": {"benign": n_negative, "threat": n_positive},
            "model_type": "MLPClassifier",
            "hidden_layers": model.hidden_layer_sizes,
            "iterations": model.n_iter_,
        },
    }
    return model_package


def atomic_save_model(model_package: dict, model_path: str) -> None:
    """Atomically write model to disk (write .tmp, then os.replace)."""
    target = Path(model_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory (same filesystem for os.replace)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp", prefix="mlp_model_", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(model_package, f)
        os.replace(tmp_path, str(target))
        logger.info("[RETRAIN] Model atomically saved to: %s", model_path)
    except Exception:
        # Clean up temp file on error
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def retrain_job() -> bool:
    """Execute one retraining cycle. Returns True if model was updated."""
    flow_records_path = os.environ.get(
        "MINIFW_FLOW_RECORDS", "/opt/minifw_ai/logs/flow_records.jsonl"
    )
    model_path = os.environ.get(
        "MINIFW_MLP_MODEL", "/opt/minifw_ai/models/mlp_model.pkl"
    )

    logger.info("[RETRAIN] Starting retraining cycle")
    records = load_and_label_records(flow_records_path)
    if not records:
        logger.info("[RETRAIN] No records to train on, skipping")
        return False

    model_package = train_model_from_records(records)
    if model_package is None:
        logger.warning("[RETRAIN] Training failed or insufficient data")
        return False

    atomic_save_model(model_package, model_path)
    logger.info(
        "[RETRAIN] Retraining complete — %d records, model at %s",
        len(records),
        model_path,
    )
    return True


def run_scheduler(interval_hours: int = 24) -> None:
    """Run the retraining scheduler loop."""
    logger.info("[RETRAIN] Scheduler started (interval=%dh)", interval_hours)
    schedule.every(interval_hours).hours.do(retrain_job)

    # Also run once on startup
    retrain_job()

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MiniFW-AI ML Retraining Scheduler")
    parser.add_argument("--once", action="store_true", help="Run single retrain cycle")
    parser.add_argument(
        "--interval", type=int, default=24, help="Retraining interval in hours"
    )
    args = parser.parse_args()

    if args.once:
        retrain_job()
    else:
        run_scheduler(interval_hours=args.interval)
