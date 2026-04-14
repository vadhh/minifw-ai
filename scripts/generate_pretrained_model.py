#!/usr/bin/env python3
"""
Generate a pre-trained MLP model for MiniFW-AI.

Creates a model trained on realistic synthetic flow data that covers
the full range of benign and threat traffic patterns. The model is
saved to models/mlp_model.pkl in the format expected by MLPThreatDetector.

Usage:
    python3 scripts/generate_pretrained_model.py
"""
import pickle
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

# Feature names must match build_feature_vector_24() in collector_flow.py
FEATURE_NAMES = [
    # Basic flow (8)
    "duration_sec", "pkt_count_total", "bytes_total", "bytes_per_sec",
    "pkts_per_sec", "avg_pkt_size", "pkt_size_std", "inbound_outbound_ratio",
    # Burst & periodicity (6)
    "max_burst_pkts_1s", "max_burst_bytes_1s", "interarrival_mean_ms",
    "interarrival_std_ms", "interarrival_p95_ms", "small_pkt_ratio",
    # TLS (6)
    "tls_seen", "tls_handshake_time_ms", "ja3_hash_bucket", "sni_len",
    "alpn_h2", "cert_self_signed_suspect",
    # DNS (4)
    "dns_seen", "fqdn_len", "subdomain_depth", "domain_repeat_5min",
]


def generate_benign_flows(rng, n=500):
    """Generate realistic benign traffic patterns."""
    data = {
        "duration_sec": rng.uniform(1.0, 300.0, n),
        "pkt_count_total": rng.uniform(10, 500, n),
        "bytes_total": rng.uniform(5000, 500000, n),
        "bytes_per_sec": rng.uniform(100, 10000, n),
        "pkts_per_sec": rng.uniform(0.5, 50, n),
        "avg_pkt_size": rng.uniform(200, 1400, n),
        "pkt_size_std": rng.uniform(50, 500, n),
        "inbound_outbound_ratio": rng.uniform(0.3, 3.0, n),
        "max_burst_pkts_1s": rng.uniform(1, 50, n),
        "max_burst_bytes_1s": rng.uniform(500, 50000, n),
        "interarrival_mean_ms": rng.uniform(20, 2000, n),
        "interarrival_std_ms": rng.uniform(10, 1000, n),
        "interarrival_p95_ms": rng.uniform(50, 5000, n),
        "small_pkt_ratio": rng.uniform(0.0, 0.4, n),
        "tls_seen": rng.choice([0.0, 1.0], n, p=[0.3, 0.7]),
        "tls_handshake_time_ms": rng.uniform(0, 200, n),
        "ja3_hash_bucket": rng.uniform(0, 100, n),
        "sni_len": rng.uniform(5, 30, n),
        "alpn_h2": rng.choice([0.0, 1.0], n, p=[0.5, 0.5]),
        "cert_self_signed_suspect": rng.choice([0.0, 1.0], n, p=[0.95, 0.05]),
        "dns_seen": rng.choice([0.0, 1.0], n, p=[0.2, 0.8]),
        "fqdn_len": rng.uniform(8, 25, n),
        "subdomain_depth": rng.choice([0.0, 1.0, 2.0], n, p=[0.3, 0.5, 0.2]),
        "domain_repeat_5min": rng.uniform(0, 5, n),
    }
    return pd.DataFrame(data, columns=FEATURE_NAMES)


def generate_threat_flows(rng, n=500):
    """Generate realistic threat traffic patterns (DDoS, scanning, C2, bots)."""
    data = {
        # Threats: short bursts, high PPS, high packet counts
        "duration_sec": rng.uniform(0.1, 10.0, n),
        "pkt_count_total": rng.uniform(200, 10000, n),
        "bytes_total": rng.uniform(10000, 2000000, n),
        "bytes_per_sec": rng.uniform(10000, 500000, n),
        "pkts_per_sec": rng.uniform(50, 500, n),
        "avg_pkt_size": rng.uniform(40, 200, n),  # small packets
        "pkt_size_std": rng.uniform(5, 50, n),  # uniform sizes (bot-like)
        "inbound_outbound_ratio": rng.uniform(0.01, 0.3, n),  # mostly outbound
        "max_burst_pkts_1s": rng.uniform(100, 500, n),
        "max_burst_bytes_1s": rng.uniform(50000, 500000, n),
        "interarrival_mean_ms": rng.uniform(1, 20, n),  # very fast
        "interarrival_std_ms": rng.uniform(0.5, 5, n),  # very regular (bot)
        "interarrival_p95_ms": rng.uniform(2, 30, n),
        "small_pkt_ratio": rng.uniform(0.7, 1.0, n),  # mostly small packets
        "tls_seen": rng.choice([0.0, 1.0], n, p=[0.6, 0.4]),
        "tls_handshake_time_ms": rng.uniform(0, 50, n),
        "ja3_hash_bucket": rng.uniform(0, 100, n),
        "sni_len": rng.uniform(0, 50, n),
        "alpn_h2": rng.choice([0.0, 1.0], n, p=[0.8, 0.2]),
        "cert_self_signed_suspect": rng.choice([0.0, 1.0], n, p=[0.5, 0.5]),
        "dns_seen": rng.choice([0.0, 1.0], n, p=[0.5, 0.5]),
        "fqdn_len": rng.uniform(15, 60, n),  # long DGA-like domains
        "subdomain_depth": rng.choice([0.0, 1.0, 2.0, 3.0, 4.0], n,
                                       p=[0.1, 0.2, 0.3, 0.2, 0.2]),
        "domain_repeat_5min": rng.uniform(5, 50, n),  # high repeat
    }
    return pd.DataFrame(data, columns=FEATURE_NAMES)


def main():
    rng = np.random.default_rng(42)

    print("[1/5] Generating synthetic training data...")
    benign = generate_benign_flows(rng, n=1000)
    threats = generate_threat_flows(rng, n=1000)

    X = pd.concat([benign, threats], ignore_index=True)
    y = np.array([0] * 1000 + [1] * 1000)

    print(f"  Total samples: {len(X)} (1000 benign + 1000 threat)")

    print("\n[2/5] Splitting and scaling...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(f"  Train: {len(X_train)}, Test: {len(X_test)}")

    print("\n[3/5] Training MLPClassifier...")
    model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        max_iter=300,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.15,
        verbose=False,
    )
    model.fit(X_train_scaled, y_train)
    print(f"  Converged in {model.n_iter_} iterations")

    print("\n[4/5] Evaluating...")
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1 Score:  {f1:.4f}")

    print("\n[5/5] Saving model...")
    output_path = Path(__file__).parent.parent / "models" / "mlp_model.pkl"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    model_package = {
        "model": model,
        "scaler": scaler,
        "metadata": {
            "trained_at": datetime.now().isoformat(),
            "n_samples": len(X),
            "n_features": len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "class_distribution": {"benign": 1000, "threat": 1000},
            "model_type": "MLPClassifier",
            "hidden_layers": model.hidden_layer_sizes,
            "iterations": model.n_iter_,
            "training_data": "synthetic (generate_pretrained_model.py)",
        },
    }

    with open(output_path, "wb") as f:
        pickle.dump(model_package, f)

    size_kb = output_path.stat().st_size / 1024
    print(f"  Saved to: {output_path}")
    print(f"  Size: {size_kb:.1f} KB")
    print("\nDone.")


if __name__ == "__main__":
    main()
