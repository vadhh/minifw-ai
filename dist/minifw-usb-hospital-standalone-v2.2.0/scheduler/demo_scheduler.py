"""
Hospital Executive Demo Scheduler — St. Roch Memorial Hospital

Writes timed Event records directly to logs/events.jsonl.

Phase 1 (T+0   – T+90s):   Normal clinical traffic              — action=allow
Phase 2 (T+90s – T+120s):  Attacker 1: IoMT device (mednet)    — monitor → block (172.16.2.50)
Phase 3 (T+120s – T+150s): Post-block normal traffic            — action=allow
Phase 4 (T+150s – T+180s): Attacker 2: staff workstation        — monitor → block (192.168.1.75)
Phase 5 (T+180s+):         Sustained normal — both IPs blocked  — action=allow (loop)

Key demo moment: mednet block threshold is 45 (vs 80 for internal).
Attacker 1 triggers BLOCK at score 47 — 38 points below the general threshold.
This is the HIPAA IoMT protection story.

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

os.environ.setdefault("MINIFW_SECRET_KEY", os.environ.get("MINIFW_SECRET_KEY", "demo-hospital-key-change-in-prod!!"))
os.environ.setdefault("MINIFW_SECTOR", "hospital")
os.environ.setdefault("PRODUCT_MODE", "minifw_hospital")

from app.minifw_ai.events import Event, EventWriter, now_iso  # noqa: E402

# Normal clinical traffic — St. Roch Memorial Hospital
# IPs: 172.16.1.x = mednet (patient monitoring, infusion pumps)
#      192.168.1.x = internal (clinical workstations, nursing stations)
NORMAL_TRAFFIC = [
    {"client_ip": "192.168.1.20", "domain": "emr.stroch.hospital.net",          "segment": "internal"},
    {"client_ip": "172.16.1.10",  "domain": "pacs.stroch.hospital.net",          "segment": "mednet"},
    {"client_ip": "192.168.1.21", "domain": "hl7.stroch.hospital.net",           "segment": "internal"},
    {"client_ip": "192.168.1.22", "domain": "pharmacy.stroch.hospital.net",      "segment": "internal"},
    {"client_ip": "172.16.1.11",  "domain": "fhir.stroch.hospital.net",          "segment": "mednet"},
    {"client_ip": "192.168.1.23", "domain": "lab.stroch.hospital.net",           "segment": "internal"},
    {"client_ip": "192.168.1.20", "domain": "mirth.stroch.hospital.net",         "segment": "internal"},
    {"client_ip": "172.16.1.12",  "domain": "monitor-hub.stroch.hospital.net",   "segment": "mednet"},
]

# Attacker 1 — compromised patient monitor on the mednet segment
# IP: 172.16.2.50 (mednet — block threshold 45, not the general 85)
# Story: Unpatched firmware on a bedside patient monitor was exploited via
#        a known CVE in the device management API. Attacker established C2,
#        then staged a ransomware dropper targeting the EMR system.
#        MiniFW-AI detects the C2 beacon and blocks at score 47 —
#        well below the 85 general threshold but above the IoMT-specific 45.
ATTACK_1 = [
    {
        "client_ip": "172.16.2.50",
        "domain":    "c2.iomt-backdoor.net",
        "segment":   "mednet",
        "action":    "monitor",
        "score":     33,
        "reasons":   ["mednet_anomaly", "iomt_device_external_call"],
        "severity":  "info",
    },
    {
        "client_ip": "172.16.2.50",
        "domain":    "drop.medfware-c2.io",
        "segment":   "mednet",
        "action":    "monitor",
        "score":     39,
        "reasons":   ["dns_feed_match", "iomt_exploit_pattern", "unknown_c2_from_patient_monitor"],
        "severity":  "info",
    },
    {
        "client_ip": "172.16.2.50",
        "domain":    "exfil.ransom-hospital.net",
        "segment":   "mednet",
        "action":    "monitor",
        "score":     43,
        "reasons":   ["ransomware_staging", "ehr_pivot_detected", "hipaa_phi_boundary_risk"],
        "severity":  "info",
    },
    {
        "client_ip": "172.16.2.50",
        "domain":    "exfil.ransom-hospital.net",
        "segment":   "mednet",
        "action":    "block",
        "score":     47,
        "reasons":   ["dns_feed_match", "ransomware_staging", "hipaa_phi_violation", "iomt_subnet_block"],
        "severity":  "critical",
    },
]

# Attacker 2 — compromised clinical workstation, insider / phishing angle
# IP: 192.168.1.75 (internal segment — block threshold 80)
# Story: Phishing email to a nursing coordinator. Credential harvesting tool
#        deployed via malicious attachment. Attacker then queried the FHIR
#        export API to bulk-pull patient records, then staged to an external host.
ATTACK_2 = [
    {
        "client_ip": "192.168.1.75",
        "domain":    "harvest.phi-stealer.net",
        "segment":   "internal",
        "action":    "monitor",
        "score":     52,
        "reasons":   ["credential_harvesting_tool", "internal_subnet_anomaly"],
        "severity":  "info",
    },
    {
        "client_ip": "192.168.1.75",
        "domain":    "api.phi-dump.io",
        "segment":   "internal",
        "action":    "monitor",
        "score":     64,
        "reasons":   ["dns_feed_match", "phi_bulk_export_pattern", "fhir_abuse_detected"],
        "severity":  "info",
    },
    {
        "client_ip": "192.168.1.75",
        "domain":    "drop.patient-exfil.net",
        "segment":   "internal",
        "action":    "monitor",
        "score":     75,
        "reasons":   ["phi_staging_host", "ehr_credential_abuse", "hipaa_phi_boundary_crossed"],
        "severity":  "info",
    },
    {
        "client_ip": "192.168.1.75",
        "domain":    "drop.patient-exfil.net",
        "segment":   "internal",
        "action":    "block",
        "score":     82,
        "reasons":   ["dns_feed_match", "phi_staging_host", "hipaa_phi_violation", "patient_data_exfil_block"],
        "severity":  "critical",
    },
]


def _case_id() -> str:
    return f"HIPAA-PHI-{uuid.uuid4().hex[:8].upper()}"


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
        reasons=["normal_clinical_traffic"],
        sector="hospital",
        severity="info",
        trace_id=_case_id(),
        decision_owner="Policy Engine",
    )
    writer.write(ev)


def write_attack_sequence(writer: EventWriter, sequence: list, delay: float = 0.0) -> None:
    for step in sequence:
        ev = Event(
            ts=now_iso(),
            segment=step["segment"],
            client_ip=step["client_ip"],
            domain=step["domain"],
            action=step["action"],
            score=step["score"],
            reasons=step["reasons"],
            sector="hospital",
            severity=step["severity"],
            trace_id=_case_id(),
            decision_owner="HIPAA Compliance Engine",
        )
        writer.write(ev)
        if delay > 0:
            time.sleep(delay)


def run(log_path: str) -> None:
    writer = make_writer(log_path)
    start = time.monotonic()
    normal_idx = 0

    def tick_normal(until: float) -> None:
        nonlocal normal_idx
        while time.monotonic() - start < until:
            write_normal_event(writer, NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)])
            normal_idx += 1
            time.sleep(11)

    print(f"[scheduler] Starting St. Roch Memorial Hospital demo scheduler -> {log_path}")

    print("[scheduler] Phase 1: Normal clinical traffic (T+0 – T+90s)")
    tick_normal(until=90)

    print("[scheduler] Phase 2: Attacker 1 — IoMT device mednet (172.16.2.50) — BLOCK at score 47")
    write_attack_sequence(writer, ATTACK_1, delay=6.0)

    print("[scheduler] Phase 3: Post-block normal traffic (T+120s – T+150s)")
    tick_normal(until=150)

    print("[scheduler] Phase 4: Attacker 2 — clinical workstation (192.168.1.75) — BLOCK at score 82")
    write_attack_sequence(writer, ATTACK_2, delay=6.0)

    print("[scheduler] Phase 5: Sustained normal — both IPs blocked")
    while True:
        write_normal_event(writer, NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)])
        normal_idx += 1
        time.sleep(10)


if __name__ == "__main__":
    log_path = os.environ.get("MINIFW_LOG", "logs/events.jsonl")
    run(log_path)
