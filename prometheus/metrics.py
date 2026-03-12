"""
MiniFW-AI Prometheus Metrics Module

Exposes firewall engine metrics for Prometheus scraping.
Start the metrics HTTP server with start_metrics_server(port).
Call update_metrics() after each event decision to record counters/histograms.
"""
from __future__ import annotations

import logging
from typing import Any

from prometheus_client import Counter, Histogram, Gauge, start_http_server


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

flows_processed_total = Counter(
    "minifw_ai_flows_processed_total",
    "Total flow events processed by the engine",
)

hard_gate_blocks_total = Counter(
    "minifw_ai_hard_gate_blocks_total",
    "Total hard-gate block triggers by gate type",
    ["gate_type"],
)

decisions_total = Counter(
    "minifw_ai_decisions_total",
    "Total decisions by action (allow/monitor/block)",
    ["decision"],
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

threat_score_histogram = Histogram(
    "minifw_ai_threat_score",
    "Distribution of computed threat scores",
    buckets=[0, 10, 25, 40, 50, 60, 75, 90, 100],
)

mlp_inference_duration = Histogram(
    "minifw_ai_mlp_inference_duration_seconds",
    "MLP inference latency in seconds",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)

yara_scan_duration = Histogram(
    "minifw_ai_yara_scan_duration_seconds",
    "YARA scan latency in seconds",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------

active_blocks = Gauge(
    "minifw_ai_active_blocks_total",
    "Current number of actively blocked IPs",
)

active_flows = Gauge(
    "minifw_ai_active_flows",
    "Current number of tracked flows",
)

model_last_trained_timestamp = Gauge(
    "minifw_ai_model_last_trained_timestamp",
    "Unix timestamp of the last MLP model training",
)


def start_metrics_server(port: int = 9090) -> None:
    """Start the Prometheus HTTP metrics endpoint."""
    try:
        start_http_server(port)
        logging.info(f"[METRICS] Prometheus metrics server started on port {port}")
    except Exception as e:
        logging.error(f"[METRICS] Failed to start metrics server: {e}")


def update_metrics(
    event: Any,
    flow_count: int = 0,
    hard_gate_reason: str | None = None,
) -> None:
    """Update all metrics after an event decision.

    Args:
        event: An Event dataclass with action, score, etc.
        flow_count: Current number of active flows.
        hard_gate_reason: If a hard gate fired, the gate type string.
    """
    flows_processed_total.inc()
    decisions_total.labels(decision=event.action).inc()
    threat_score_histogram.observe(event.score)
    active_flows.set(flow_count)

    if hard_gate_reason:
        hard_gate_blocks_total.labels(gate_type=hard_gate_reason).inc()
