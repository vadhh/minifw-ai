"""
Five-Minute Demo Scheduler — St. Roch Memorial Hospital

Compressed timeline for a 5-minute executive demonstration.
Designed so a non-technical client understands what happened, what was blocked,
and why it matters — within the first 5 minutes.

Timeline:
  T+0   – T+30s:  3 normal clinical events (baseline — system is healthy)
  T+30s – T+60s:  Attack 1: IoMT device → BLOCK at score 47 (mednet threshold 45)
  T+60s – T+90s:  2 normal events (staff still working — no disruption)
  T+90s – T+120s: Attack 2: PHI exfil → BLOCK at score 82 (internal threshold 80)
  T+120s+:        Loop normal — both attackers blocked, clean network

Key story: Same engine, two different thresholds. IoMT blocked earlier.
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

os.environ.setdefault("MINIFW_SECRET_KEY", os.environ.get("MINIFW_SECRET_KEY", "demo-hospital-key-change-in-prod!!"))
os.environ.setdefault("MINIFW_SECTOR", "hospital")
os.environ.setdefault("PRODUCT_MODE", "minifw_hospital")

from app.minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402

NORMAL_TRAFFIC = [
    {"client_ip": "192.168.1.20", "domain": "emr.stroch.hospital.net",     "segment": "internal"},
    {"client_ip": "172.16.1.10",  "domain": "pacs.stroch.hospital.net",     "segment": "mednet"},
    {"client_ip": "192.168.1.21", "domain": "pharmacy.stroch.hospital.net", "segment": "internal"},
    {"client_ip": "172.16.1.11",  "domain": "fhir.stroch.hospital.net",     "segment": "mednet"},
    {"client_ip": "192.168.1.23", "domain": "lab.stroch.hospital.net",      "segment": "internal"},
]

# Attack 1 — compressed: 3 events at 8s intervals, block on 3rd
ATTACK_1 = [
    {"client_ip": "172.16.2.50", "domain": "c2.iomt-backdoor.net",     "segment": "mednet",
     "action": "monitor", "score": 39, "reasons": ["dns_feed_match", "iomt_device_external_call"],         "severity": "info"},
    {"client_ip": "172.16.2.50", "domain": "drop.medfware-c2.io",       "segment": "mednet",
     "action": "monitor", "score": 43, "reasons": ["ransomware_staging", "hipaa_phi_boundary_risk"],       "severity": "info"},
    {"client_ip": "172.16.2.50", "domain": "exfil.ransom-hospital.net", "segment": "mednet",
     "action": "block",   "score": 47, "reasons": ["dns_feed_match", "hipaa_phi_violation", "iomt_subnet_block"], "severity": "critical"},
]

# Attack 2 — compressed: 2 monitors then block
ATTACK_2 = [
    {"client_ip": "192.168.1.75", "domain": "api.phi-dump.io",         "segment": "internal",
     "action": "monitor", "score": 64, "reasons": ["dns_feed_match", "phi_bulk_export_pattern"],           "severity": "info"},
    {"client_ip": "192.168.1.75", "domain": "drop.patient-exfil.net",  "segment": "internal",
     "action": "monitor", "score": 75, "reasons": ["phi_staging_host", "ehr_credential_abuse"],            "severity": "info"},
    {"client_ip": "192.168.1.75", "domain": "drop.patient-exfil.net",  "segment": "internal",
     "action": "block",   "score": 82, "reasons": ["dns_feed_match", "hipaa_phi_violation", "patient_data_exfil_block"], "severity": "critical"},
]


def _trace() -> str:
    return f"HIPAA-PHI-{uuid.uuid4().hex[:8].upper()}"


def write_normal(writer, entry, idx):
    writer.write(Event(
        ts=now_iso(), segment=entry["segment"], client_ip=entry["client_ip"],
        domain=entry["domain"], action="allow", score=random.randint(18, 22),
        reasons=["normal_clinical_traffic"], sector="hospital",
        severity="info", trace_id=_trace(), decision_owner="Policy Engine",
    ))


def write_sequence(writer, sequence, delay=8.0):
    for step in sequence:
        writer.write(Event(
            ts=now_iso(), segment=step["segment"], client_ip=step["client_ip"],
            domain=step["domain"], action=step["action"], score=step["score"],
            reasons=step["reasons"], sector="hospital",
            severity=step["severity"], trace_id=_trace(),
            decision_owner="HIPAA Compliance Engine",
        ))
        if delay > 0:
            time.sleep(delay)


def run(log_path: str) -> None:
    writer = EventWriter(log_path)
    start = time.monotonic()
    idx = 0

    def elapsed() -> float:
        return time.monotonic() - start

    def normal_until(t: float) -> None:
        nonlocal idx
        while elapsed() < t:
            write_normal(writer, NORMAL_TRAFFIC[idx % len(NORMAL_TRAFFIC)], idx)
            idx += 1
            time.sleep(10)

    print(f"[5min-scheduler] Starting 5-minute demo → {log_path}")
    print("[5min-scheduler] T+0: Normal clinical traffic (30s)")
    normal_until(30)

    print("[5min-scheduler] T+30s: Attack 1 — IoMT ransomware — BLOCK at score 47")
    write_sequence(writer, ATTACK_1, delay=8.0)

    print("[5min-scheduler] T+60s: Normal traffic — staff unaffected")
    normal_until(90)

    print("[5min-scheduler] T+90s: Attack 2 — PHI exfil — BLOCK at score 82")
    write_sequence(writer, ATTACK_2, delay=8.0)

    print("[5min-scheduler] T+120s: Sustained normal — both attackers isolated")
    while True:
        write_normal(writer, NORMAL_TRAFFIC[idx % len(NORMAL_TRAFFIC)], idx)
        idx += 1
        time.sleep(10)


if __name__ == "__main__":
    run(os.environ.get("MINIFW_LOG", "logs/events.jsonl"))
