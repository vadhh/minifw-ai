#!/usr/bin/env python3
"""Reproducible experimental packet14 model; training data are synthetic, not sector validation."""
import pickle
from pathlib import Path
import sys

import numpy as np
import pandas as pd
import sklearn
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from generate_pretrained_model import generate_benign_flows, generate_threat_flows, FEATURE_NAMES


def main(output):
    rng = np.random.default_rng(42)
    names = FEATURE_NAMES[:14]
    data = pd.concat([generate_benign_flows(rng, 1000), generate_threat_flows(rng, 1000)], ignore_index=True)[names]
    labels = np.array([0] * 1000 + [1] * 1000)
    scaler = StandardScaler()
    values = scaler.fit_transform(data)
    model = MLPClassifier(hidden_layer_sizes=(32, 16), random_state=42, max_iter=500,
                          early_stopping=True).fit(values, labels)
    metadata = {"feature_schema": "packet14-v1", "feature_names": names,
                "training_data": "synthetic (generate_pretrained_model.py; first 14 measured packet features)",
                "n_samples": len(labels), "sklearn_version": sklearn.__version__,
                "validation": "No representative Financial or Education validation; experimental"}
    assert model.n_features_in_ == scaler.n_features_in_ == len(names) == 14
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pickle.dumps({"model": model, "scaler": scaler, "metadata": metadata}))
    print("EXPERIMENTAL_PACKET_MODEL", path, metadata)


if __name__ == "__main__":
    main(sys.argv[1])
