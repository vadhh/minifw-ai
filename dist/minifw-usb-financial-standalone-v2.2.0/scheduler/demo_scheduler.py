"""
Financial Executive Demo Scheduler — ArborCrest Capital

Writes timed Event records directly to logs/events.jsonl.
Phase 1 (T+0   – T+90s):  Normal ArborCrest traffic      — action=allow
Phase 2 (T+90s – T+120s): 5-step attack sequence          — monitor → block
Phase 3 (T+120s+):        Post-block normal traffic        — action=allow

Run via: python3 scheduler/demo_scheduler.py
Killed by run_demo.sh cleanup trap.
"""
from __future__ import annotations

import os
import random
import sys
import time
import uuid
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PKG))
sys.path.insert(0, str(_PKG / "app"))

os.environ.setdefault("MINIFW_SECRET_KEY", os.environ.get("MINIFW_SECRET_KEY", "demo-financial-key-change-in-prod!!"))
os.environ.setdefault("MINIFW_SECTOR", "finance")
os.environ.setdefault("PRODUCT_MODE", "minifw_financial")

from app.minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402

NORMAL_TRAFFIC = [
    {"client_ip": "10.50.0.10", "domain": "bloomberg.com",                   "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "feeds.reuters.com",               "segment": "trading"},
    {"client_ip": "10.50.0.12", "domain": "swift.arborcrest.int",            "segment": "trading"},
    {"client_ip": "10.50.0.13", "domain": "api.refinitiv.com",               "segment": "trading"},
    {"client_ip": "10.50.0.11", "domain": "market.nasdaq.com",               "segment": "trading"},
    {"client_ip": "192.168.1.10", "domain": "oracle-erp.arborcrest.int",    "segment": "internal"},
    {"client_ip": "192.168.1.11", "domain": "sap.arborcrest.int",           "segment": "internal"},
    {"client_ip": "192.168.1.12", "domain": "internal-auth.arborcrest.int", "segment": "internal"},
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
        "score":     72,
        "reasons":   ["dns_feed_match", "banking_trojan_c2_beacon", "financial_fraud_feed"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "monitor",
        "score":     82,
        "reasons":   ["card_exfil_pattern", "oracle_erp_subnet_pivot", "pci_dss_boundary_crossed"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "monitor",
        "score":     89,
        "reasons":   ["card_exfil_pattern", "client_portfolio_exfil", "pci_dss_violation"],
        "severity":  "info",
    },
    {
        "client_ip": "10.50.0.1",
        "domain":    "exfil.payment-collect.io",
        "segment":   "trading",
        "action":    "block",
        "score":     95,
        "reasons":   ["dns_feed_match", "card_exfil_pattern", "pci_dss_violation", "erp_subnet_block"],
        "severity":  "critical",
    },
]


def _txn_id() -> str:
    return f"TXN-AC-{uuid.uuid4().hex[:8].upper()}"


def _swift_id() -> str:
    return f"SWIFT-MT103-{uuid.uuid4().hex[:8].upper()}"


def make_writer(log_path: str) -> EventWriter:
    return EventWriter(log_path)


def write_normal_event(writer: EventWriter, entry: dict) -> None:
    ev = Event(
        ts=now_iso(),
        segment=entry["segment"],
        client_ip=entry["client_ip"],
        domain=entry["domain"],
        action="allow",
        score=random.randint(18, 22),
        reasons=["normal_financial_traffic"],
        sector="finance",
        severity="info",
        trace_id=_txn_id(),
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
            trace_id=_swift_id(),
            decision_owner="PCI-DSS Policy Engine",
        )
        writer.write(ev)
        if delay > 0:
            time.sleep(delay)


def run(log_path: str) -> None:
    writer = make_writer(log_path)
    start = time.monotonic()

    print(f"[scheduler] Starting ArborCrest Capital demo scheduler -> {log_path}")
    print("[scheduler] Phase 1: Normal traffic (T+0 - T+90s)")

    normal_idx = 0
    while time.monotonic() - start < 90:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(11)

    print("[scheduler] Phase 2: Attack sequence (T+90s - T+120s) -- BLOCK incoming")
    write_attack_sequence(writer, delay=6.0)
    print("[scheduler] Phase 3: Post-block normal traffic -- firewall holding")

    while True:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(10)


if __name__ == "__main__":
    log_path = os.environ.get("MINIFW_LOG", "logs/events.jsonl")
    run(log_path)
