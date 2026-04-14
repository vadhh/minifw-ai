import os
import pickle
import sys
from pathlib import Path

import pytest

# Ensure app/ is on the path for all tests
sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

pytest.register_assert_rewrite("testing")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (deselect with '-m \"not integration\"')",
    )


@pytest.fixture(scope="session")
def synthetic_mlp_model_path(tmp_path_factory):
    """
    Train a minimal MLPClassifier on synthetic 24-feature data and pickle it
    to a temp file. Returned path can be passed directly to MLPThreatDetector.

    Skips automatically if scikit-learn / numpy are not installed.
    """
    try:
        import numpy as np
        from sklearn.neural_network import MLPClassifier
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        pytest.skip("scikit-learn / numpy not installed")

    # Import here so the skip above fires before this runs
    import pandas as pd
    from minifw_ai.utils.mlp_engine import FEATURE_NAMES  # noqa: PLC0415

    rng = np.random.default_rng(42)

    # 100 "normal" samples — low feature values
    X_normal = rng.uniform(0.0, 0.3, size=(100, 24))
    # 100 "threat" samples — high feature values
    X_threat = rng.uniform(0.7, 1.0, size=(100, 24))

    X = np.vstack([X_normal, X_threat])
    y = np.array([0] * 100 + [1] * 100)

    # Fit scaler on a named DataFrame so the column contract matches inference:
    # mlp_engine.is_suspicious() calls scaler.transform(pd.DataFrame(..., columns=FEATURE_NAMES))
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)

    model = MLPClassifier(hidden_layer_sizes=(16, 8), max_iter=500, random_state=42)
    model.fit(X_scaled, y)

    tmp_dir = tmp_path_factory.mktemp("mlp_models")
    model_path = tmp_dir / "synthetic_mlp.pkl"

    with open(model_path, "wb") as f:
        pickle.dump({"model": model, "scaler": scaler}, f)

    return str(model_path)
