# MiniFW-AI Project Context

## Overview
**MiniFW-AI** is a gateway metadata protection layer designed for RitAPI-AI V-Sentinel. It operates as a client-installed firewall that analyzes network traffic metadata (DNS, TLS SNI) to detect and block threats without requiring TLS inspection (MITM) or browser proxies.

It features a hybrid detection engine:
1.  **Rule-based:** Policy enforcement based on DNS/SNI feeds.
2.  **Behavioral:** Burst detection for high-rate traffic.
3.  **AI/ML:** An MLP (Multi-Layer Perceptron) engine that scores traffic flows based on 24 extracted features.

## Architecture

### Core Components
*   **Collector (`app/minifw_ai/collector_*.py`):**
    *   **DNS:** Tails `dnsmasq` logs to capture DNS queries.
    *   **Zeek (Optional):** Tails Zeek SSL logs for TLS SNI visibility.
    *   **Flow:** Tracks network flows (5-tuple) and extracts features for the AI engine.
*   **Logic Engine (`app/minifw_ai/main.py`):**
    *   Central event loop.
    *   Aggregates signals (Blocklists, Burst, AI Score).
    *   Calculates a final "threat score" (0-100).
*   **AI Engine (`app/minifw_ai/utils/mlp_engine.py`):**
    *   Uses `scikit-learn` MLPClassifier.
    *   Analyzes flow features (duration, packet sizes, inter-arrival times, etc.).
*   **Enforcement (`app/minifw_ai/enforce.py`):**
    *   **Mechanism:** `nftables` + `ipset`.
    *   **Action:** Adds blocking IPs to the `minifw_block_v4` ipset with a timeout.
*   **Web Interface (`app/web/app.py`):**
    *   **Framework:** FastAPI (Note: Dependency is currently optional/commented out in `requirements.txt`).
    *   **Purpose:** Admin dashboard, status checks.

### Directory Structure
*   `app/minifw_ai/`: Core application logic.
*   `app/web/`: Web application (FastAPI) and static assets (AdminLTE).
*   `config/`: Configuration files (`policy.json`) and threat feeds (`feeds/*.txt`).
*   `scripts/`: Utility scripts for installation, training, and system management.
*   `testing/`: Integration and unit tests (`pytest`).
*   `models/`: Serialized ML models (`mlp_engine.pkl`).

## Key Technologies
*   **Language:** Python 3.x
*   **System Tools:** `dnsmasq`, `nftables`, `ipset`, `zeek` (optional)
*   **ML Libraries:** `scikit-learn`, `pandas`, `numpy`
*   **Web Framework:** FastAPI (Optional)

## Development & Usage

### Installation
The project is designed to run on Linux (Debian/Ubuntu) as a gateway.
```bash
sudo ./scripts/install.sh
```
*   Installs dependencies (system & python venv).
*   Deploys code to `/opt/minifw_ai`.

### Running the Service
```bash
sudo ./scripts/install_systemd.sh
sudo systemctl start minifw-ai
```

### Manual Execution (Dev)
```bash
# Set required env vars if not using defaults
export PYTHONPATH=$PYTHONPATH:$(pwd)/app
python3 -m app.minifw_ai.main
```

### AI Model Training
To train the MLP engine with new flow data:
```bash
python3 scripts/train_mlp.py --data data/testing_output/flow_records_labeled.csv --output models/mlp_engine.pkl
```

### Testing
Tests are located in `testing/`.
```bash
pytest testing/
# Or run specific integration tests
python3 testing/test_full_integration.py
```

## Conventions
*   **Type Hinting:** Extensive use of Python type hints (`def func(x: int) -> None:`).
*   **Configuration:** Environment variables override default paths (e.g., `MINIFW_POLICY`, `MINIFW_LOG`).
*   **Logging:** JSONL format for machine-readable event logs (`events.jsonl`).
*   **Path handling:** Use `pathlib` or `os.path` relative to project root or configured env vars.

## Critical Files
*   `app/minifw_ai/main.py`: The "brain" of the firewall. Handles the main event loop and scoring logic.
*   `app/minifw_ai/utils/mlp_engine.py`: Encapsulates the ML model loading and inference.
*   `config/policy.json`: Defines scoring weights and thresholds.
*   `requirements.txt`: Python dependencies (Check here for optional vs core pkgs).
