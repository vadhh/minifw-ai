"""
Financial Executive Demo Scheduler

Writes timed Event records directly to logs/events.jsonl.
Phase 1 (T+0  – T+60s): Normal financial traffic  — action=allow
Phase 2 (T+60s – T+75s): Attack build-up          — action=monitor then block
Phase 3 (T+75s+):        Post-block normal traffic — action=allow

Run via: python3 scheduler/demo_scheduler.py
Killed by run_demo.sh cleanup trap.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

# Make app importable from package root
_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG))
sys.path.insert(0, str(_PKG / "app"))

os.environ.setdefault("MINIFW_SECRET_KEY", os.environ.get("MINIFW_SECRET_KEY", "demo-financial-key-change-in-prod!!"))
os.environ.setdefault("MINIFW_SECTOR", "finance")
os.environ.setdefault("PRODUCT_MODE", "minifw_financial")

from app.minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402


NORMAL_TRAFFIC = [
    {"client_ip": "10.50.0.10", "domain": "data.bloomberg.com",   "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "feeds.reuters.com",    "segment": "trading"},
    {"client_ip": "10.50.0.12", "domain": "swift.trading.corp",   "segment": "trading"},
    {"client_ip": "10.50.0.10", "domain": "trading.corp",         "segment": "trading"},
    {"client_ip": "10.50.0.13", "domain": "api.refinitiv.com",    "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "market.nasdaq.com",    "segment": "trading"},
    {"client_ip": "10.50.0.12", "domain": "internal-auth.corp",   "segment": "internal"},
    {"client_ip": "10.50.0.10", "domain": "ocsp.digicert.com",    "segment": "trading"},
]

ATTACK_SEQUENCE = [
    {
        "client_ip": "10.50.0.1",
        "domain":    "tor-exit-4f2a.net",
        "segment":   "trading",
        "action":    "monitor",
        "score":     55,
        "reasons":   ["anonymizer_traffic", "trading_floor_anomaly"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "c2.trickbot-gate.com",
        "segment":   "trading",
        "action":    "monitor",
        "score":     70,
        "reasons":   ["dns_feed_match", "banking_trojan_c2", "financial_fraud_feed"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "monitor",
        "score":     78,
        "reasons":   ["dns_feed_match", "card_exfil_pattern", "pci_boundary_risk"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "block",
        "score":     95,
        "reasons":   ["dns_feed_match", "card_exfil_pattern", "pci_dss_violation", "trading_floor_block"],
        "severity":  "critical",
    },
]


def make_writer(log_path: str) -> EventWriter:
    return EventWriter(log_path)


def write_normal_event(writer: EventWriter, entry: dict) -> None:
    ev = Event(
        ts=now_iso(),
        segment=entry["segment"],
        client_ip=entry["client_ip"],
        domain=entry["domain"],
        action="allow",
        score=20,
        reasons=["normal_financial_traffic"],
        sector="finance",
        severity="info",
        trace_id=uuid.uuid4().hex[:8],
        decision_owner="Policy Engine",
    )
    writer.write(ev)


def write_attack_sequence(writer: EventWriter, delay: float = 0.0) -> None:
    for step in ATTACK_SEQUENCE:
        ev = Event(
            ts=now_iso(),
            segment=step["segment"],
            client_ip=step["client_ip"],
            domain=step["domain"],
            action=step["action"],
            score=step["score"],
            reasons=step["reasons"],
            sector="finance",
            severity=step["severity"],
            trace_id=uuid.uuid4().hex[:8],
            decision_owner="Policy Engine",
        )
        writer.write(ev)
        if delay > 0:
            time.sleep(delay)


def run(log_path: str) -> None:
    writer = make_writer(log_path)
    start = time.monotonic()

    print(f"[scheduler] Starting financial demo scheduler -> {log_path}")
    print("[scheduler] Phase 1: Normal traffic (T+0 - T+60s)")

    normal_idx = 0
    while time.monotonic() - start < 60:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(8)

    print("[scheduler] Phase 2: Attack sequence (T+60s - T+75s) -- BLOCK incoming")
    write_attack_sequence(writer, delay=5.0)
    print("[scheduler] Phase 3: Post-block normal traffic -- firewall holding")

    while True:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(10)


if __name__ == "__main__":
    log_path = os.environ.get("MINIFW_LOG", "logs/events.jsonl")
    run(log_path)
