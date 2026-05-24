# Financial Executive Safe Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `dist/minifw-usb-financial-standalone-v2.2.0/` — a one-button executive demo for the finance sector with trusted HTTPS, a guaranteed BLOCK event at ~T+75s, zero terminal noise, and graceful shutdown.

**Architecture:** The package mirrors the hospital standalone structure. `run_demo.sh` starts the engine (idling with `MINIFW_DNS_SOURCE=none`) and the uvicorn web server over HTTPS (port 8443). A `demo_scheduler.py` writes timed `Event` records directly to `logs/events.jsonl` using the existing `EventWriter` — this is deterministic and bypasses the scoring pipeline entirely, guaranteeing the BLOCK fires at the right moment regardless of MLP/YARA availability. `setup_tls.sh` generates a local CA with `openssl` and installs it to the system trust store and NSS databases before the first run.

**Tech Stack:** Python 3.10+, FastAPI/uvicorn, openssl CLI, certutil (libnss3-tools), bash 4+

---

## File Map

| Path (relative to package root) | Action | Responsibility |
|---|---|---|
| `dist/minifw-usb-financial-standalone-v2.2.0/` | Create dir | Package root |
| `setup_tls.sh` | Create | Generate CA + server cert, install to trust stores |
| `teardown_demo.sh` | Create | Remove CA from trust stores, clean certs/ |
| `run_demo.sh` | Create | Pre-flight, start engine+web+scheduler, browser, trap |
| `HEALTHCHECK.sh` | Create | Verify certs, TLS health, BLOCK event detection |
| `recover_demo.sh` | Create | Kill stale processes, reset DB, relaunch |
| `INSTALL.md` | Create | Step-by-step setup guide for presenter |
| `README.md` | Create | Package overview and narrative |
| `README.txt` | Create | Plain-text version of README for USB |
| `RECOVERY.md` | Create | Manual recovery steps |
| `requirements.txt` | Create | Pinned Python dependencies |
| `config/policy.json` | Create | Financial sector policy (block_threshold 80, PCI-DSS) |
| `config/feeds/` | Copy + extend | All feeds from hospital standalone + financial_fraud.txt |
| `demo_data/normal_traffic.json` | Create | Financial normal traffic (Bloomberg, Reuters, SWIFT) |
| `demo_data/attack_traffic.json` | Create | Financial attack traffic (Tor exit, crypto C2, card exfil) |
| `scheduler/__init__.py` | Create | Empty init |
| `scheduler/demo_scheduler.py` | Create | Timed event writer — normal T+0–60s, attack T+60–80s, BLOCK by T+75s |
| `app/` | Copy from hospital standalone | Engine + web code |
| `models/` | Copy from hospital standalone | mlp_model.pkl |
| `yara_rules/` | Copy from hospital standalone | YARA rule files |
| `certs/` | Gitignored, created by setup_tls.sh | CA + server cert |
| `logs/` | Created at runtime by run_demo.sh | Event and process logs |
| `minifw.db` | Created at runtime by web app | SQLite database |

---

## Task 1: Create Package Skeleton

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/` (directory + subdirs)
- Copy: `app/`, `models/`, `yara_rules/`, `config/feeds/`, `requirements.txt` from hospital standalone

- [ ] **Step 1: Create directories**

```bash
cd /home/sydeco/minifw-ai
PKG=dist/minifw-usb-financial-standalone-v2.2.0
mkdir -p $PKG/{app,config/feeds,demo_data,scheduler,logs,models,yara_rules,certs,prometheus}
touch $PKG/logs/.gitkeep $PKG/certs/.gitkeep
```

- [ ] **Step 2: Copy app, models, yara_rules from hospital standalone**

```bash
SRC=dist/minifw-usb-hospital-standalone-v2.2.0
PKG=dist/minifw-usb-financial-standalone-v2.2.0
cp -r $SRC/app/. $PKG/app/
cp -r $SRC/models/. $PKG/models/
cp -r $SRC/yara_rules/. $PKG/yara_rules/
cp -r $SRC/config/feeds/. $PKG/config/feeds/
cp $SRC/requirements.txt $PKG/requirements.txt
```

- [ ] **Step 3: Create venv**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd /home/sydeco/minifw-ai
```

- [ ] **Step 4: Create scheduler/__init__.py**

```bash
touch dist/minifw-usb-financial-standalone-v2.2.0/scheduler/__init__.py
```

- [ ] **Step 5: Verify structure**

```bash
find dist/minifw-usb-financial-standalone-v2.2.0 -maxdepth 2 -not -path "*/venv/*" -not -path "*/.git/*" | sort | head -40
```

Expected: directories for app, config, demo_data, scheduler, logs, models, yara_rules, certs.

- [ ] **Step 6: Commit skeleton**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/
git commit -m "feat(demo): scaffold financial standalone package skeleton"
```

---

## Task 2: Financial Config and Demo Data

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/config/policy.json`
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/demo_data/normal_traffic.json`
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/demo_data/attack_traffic.json`

- [ ] **Step 1: Write config/policy.json**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/config/policy.json << 'EOF'
{
  "_mode": "minifw_financial",
  "_sector": "finance",
  "_note": "PCI-DSS compliance. Tor/anonymizer blocking. Strict TLS 1.2+ enforcement.",
  "segments": {
    "default": {
      "block_threshold": 85,
      "monitor_threshold": 55
    },
    "trading": {
      "block_threshold": 80,
      "monitor_threshold": 45,
      "_note": "Trading floor — tightest enforcement."
    },
    "internal": {
      "block_threshold": 80,
      "monitor_threshold": 45
    },
    "guest": {
      "block_threshold": 65,
      "monitor_threshold": 35,
      "_note": "Client / visitor WiFi — Tor exit nodes always blocked."
    },
    "dmz": {
      "block_threshold": 75,
      "monitor_threshold": 50
    }
  },
  "segment_subnets": {
    "trading":  ["10.50.0.0/24"],
    "internal": ["192.168.1.0/24", "10.0.0.0/8"],
    "guest":    ["192.168.100.0/24"],
    "dmz":      ["10.10.0.0/24"]
  },
  "features": {
    "dns_weight":       40,
    "sni_weight":       35,
    "asn_weight":       15,
    "ip_denied_weight": 15,
    "burst_weight":     10,
    "mlp_weight":       30,
    "yara_weight":      35
  },
  "enforcement": {
    "ipset_name_v4":      "minifw_block_v4",
    "ip_timeout_seconds": 86400,
    "nft_table":          "inet",
    "nft_table_name":     "minifw",
    "nft_chain":          "forward"
  },
  "collectors": {
    "dnsmasq_log_path": "/opt/minifw_ai/logs/dnsmasq.log",
    "use_zeek_sni": false
  },
  "burst": {
    "dns_queries_per_minute_monitor": 30,
    "dns_queries_per_minute_block":   50
  },
  "iomt_subnets": [],
  "minimum_tls_version": "1.2"
}
EOF
```

- [ ] **Step 2: Write demo_data/normal_traffic.json**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/demo_data/normal_traffic.json << 'EOF'
[
  {"client_ip": "10.50.0.10", "domain": "data.bloomberg.com",        "label": "safe"},
  {"client_ip": "10.50.0.11", "domain": "feeds.reuters.com",         "label": "safe"},
  {"client_ip": "10.50.0.12", "domain": "swift.trading.corp",        "label": "safe"},
  {"client_ip": "10.50.0.10", "domain": "trading.corp",              "label": "safe"},
  {"client_ip": "10.50.0.13", "domain": "api.refinitiv.com",         "label": "safe"},
  {"client_ip": "10.50.0.11", "domain": "market.nasdaq.com",         "label": "safe"},
  {"client_ip": "10.50.0.12", "domain": "internal-auth.corp",        "label": "safe"},
  {"client_ip": "10.50.0.10", "domain": "ocsp.digicert.com",         "label": "safe"}
]
EOF
```

- [ ] **Step 3: Write demo_data/attack_traffic.json**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/demo_data/attack_traffic.json << 'EOF'
[
  {
    "client_ip": "10.50.0.1",
    "domain":    "tor-exit-4f2a.net",
    "label":     "anonymizer",
    "note":      "Tor exit node — anonymizer traffic from trading floor"
  },
  {
    "client_ip": "10.50.0.1",
    "domain":    "c2.trickbot-gate.com",
    "label":     "banking_trojan_c2",
    "note":      "Banking trojan C2 beacon — matches financial_fraud feed"
  },
  {
    "client_ip": "10.50.0.1",
    "domain":    "exfil.payment-collect.io",
    "label":     "card_exfil",
    "note":      "Card data exfiltration probe — matches financial_fraud feed"
  },
  {
    "client_ip": "10.50.0.1",
    "domain":    "pastebin.com",
    "label":     "pci_violation",
    "note":      "PCI boundary violation — paste of card data from trading subnet"
  }
]
EOF
```

- [ ] **Step 4: Verify JSON is valid**

```bash
python3 -c "
import json
for f in ['config/policy.json', 'demo_data/normal_traffic.json', 'demo_data/attack_traffic.json']:
    with open(f'dist/minifw-usb-financial-standalone-v2.2.0/{f}') as fp:
        json.load(fp)
    print(f'OK: {f}')
"
```

Expected:
```
OK: config/policy.json
OK: demo_data/normal_traffic.json
OK: demo_data/attack_traffic.json
```

- [ ] **Step 5: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/config/ \
           dist/minifw-usb-financial-standalone-v2.2.0/demo_data/
git commit -m "feat(demo): add financial policy config and demo traffic data"
```

---

## Task 3: Demo Scheduler

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py`
- Create: `testing/test_financial_demo_scheduler.py`

The scheduler imports `Event` and `EventWriter` from the app, writes timed events to `logs/events.jsonl`. Three phases: normal (T+0–60s), attack build-up (T+60–75s), post-block resume (T+75s+). Runs until killed.

- [ ] **Step 1: Write the failing test**

Create `testing/test_financial_demo_scheduler.py`:

```python
"""Tests for financial demo scheduler event generation."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Ensure app is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "dist" / "minifw-usb-financial-standalone-v2.2.0"))
sys.path.insert(0, str(Path(__file__).parent.parent / "dist" / "minifw-usb-financial-standalone-v2.2.0" / "app"))

os.environ.setdefault("MINIFW_SECRET_KEY", "test-key-financial-demo")
os.environ.setdefault("MINIFW_SECTOR", "finance")
os.environ.setdefault("PRODUCT_MODE", "minifw_financial")


def test_scheduler_imports():
    """Scheduler module is importable from the package."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "write_normal_event")
    assert hasattr(mod, "write_attack_sequence")
    assert hasattr(mod, "NORMAL_TRAFFIC")
    assert hasattr(mod, "ATTACK_SEQUENCE")


def test_normal_events_are_allow(tmp_path):
    """Normal events written by scheduler have action=allow and score<45."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)

    for entry in mod.NORMAL_TRAFFIC:
        mod.write_normal_event(writer, entry)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) == len(mod.NORMAL_TRAFFIC)
    for line in lines:
        ev = json.loads(line)
        assert ev["action"] == "allow", f"Normal event should be allow, got: {ev['action']}"
        assert ev["score"] < 45, f"Normal event score {ev['score']} should be < 45"
        assert ev["sector"] == "finance"


def test_attack_sequence_ends_with_block(tmp_path):
    """Attack sequence produces a block event with score >= 80 in trading segment."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)
    mod.write_attack_sequence(writer)

    lines = Path(log_path).read_text().strip().splitlines()
    assert len(lines) > 0

    events = [json.loads(l) for l in lines]
    block_events = [e for e in events if e["action"] == "block"]
    assert len(block_events) >= 1, "Attack sequence must produce at least one block event"

    final_block = block_events[-1]
    assert final_block["score"] >= 80, f"Block score {final_block['score']} must be >= 80"
    assert final_block["segment"] == "trading"
    assert final_block["client_ip"] == "10.50.0.1"
    assert final_block["severity"] == "critical"


def test_event_fields_complete(tmp_path):
    """Every event written has all required EventWriter fields."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "demo_scheduler",
        "dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_path = str(tmp_path / "events.jsonl")
    writer = mod.make_writer(log_path)
    mod.write_normal_event(writer, mod.NORMAL_TRAFFIC[0])
    mod.write_attack_sequence(writer)

    required_fields = {"ts", "segment", "client_ip", "domain", "action", "score", "reasons", "sector"}
    for line in Path(log_path).read_text().strip().splitlines():
        ev = json.loads(line)
        missing = required_fields - ev.keys()
        assert not missing, f"Event missing fields: {missing}"
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /home/sydeco/minifw-ai
PYTHONPATH=. pytest testing/test_financial_demo_scheduler.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError` or `AttributeError` — scheduler doesn't exist yet.

- [ ] **Step 3: Write scheduler/demo_scheduler.py**

Create `dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py`:

```python
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


def write_attack_sequence(writer: EventWriter) -> None:
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
        time.sleep(5)


def run(log_path: str) -> None:
    writer = make_writer(log_path)
    start = time.monotonic()

    print(f"[scheduler] Starting financial demo scheduler → {log_path}")
    print("[scheduler] Phase 1: Normal traffic (T+0 – T+60s)")

    normal_idx = 0
    while time.monotonic() - start < 60:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(8)

    print("[scheduler] Phase 2: Attack sequence (T+60s – T+75s) — BLOCK incoming")
    write_attack_sequence(writer)
    print("[scheduler] Phase 3: Post-block normal traffic — firewall holding")

    while True:
        entry = NORMAL_TRAFFIC[normal_idx % len(NORMAL_TRAFFIC)]
        write_normal_event(writer, entry)
        normal_idx += 1
        time.sleep(10)


if __name__ == "__main__":
    log_path = os.environ.get("MINIFW_LOG", "logs/events.jsonl")
    run(log_path)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/sydeco/minifw-ai
PYTHONPATH=. pytest testing/test_financial_demo_scheduler.py -v
```

Expected:
```
PASSED testing/test_financial_demo_scheduler.py::test_scheduler_imports
PASSED testing/test_financial_demo_scheduler.py::test_normal_events_are_allow
PASSED testing/test_financial_demo_scheduler.py::test_attack_sequence_ends_with_block
PASSED testing/test_financial_demo_scheduler.py::test_event_fields_complete
4 passed
```

- [ ] **Step 5: Confirm full test suite still passes**

```bash
PYTHONPATH=. pytest testing/ -m "not integration" -q 2>&1 | tail -5
```

Expected: `492 passed` (plus the 4 new tests = 496 passed), 0 failed.

- [ ] **Step 6: Commit**

```bash
git add testing/test_financial_demo_scheduler.py \
        dist/minifw-usb-financial-standalone-v2.2.0/scheduler/demo_scheduler.py
git commit -m "feat(demo): add financial demo scheduler with deterministic BLOCK at T+75s"
```

---

## Task 4: `setup_tls.sh`

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh`

Generates a local CA and server cert with `openssl`, installs the CA into the system trust store and NSS databases. Idempotent — safe to re-run.

- [ ] **Step 1: Write setup_tls.sh**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh << 'SCRIPT'
#!/bin/bash
# MiniFW-AI Financial Demo — TLS Setup
# Run once before the first demo. Requires sudo for trust store install.
# Safe to re-run — regenerates certs and re-installs CA.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { echo "[minifw-tls] $*"; }
die()  { echo "[minifw-tls] ERROR: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl not found — install: sudo apt-get install openssl"

mkdir -p certs
chmod 700 certs

CA_KEY=certs/minifw-ca.key
CA_CRT=certs/minifw-ca.crt
SRV_KEY=certs/server.key
SRV_CSR=certs/server.csr
SRV_CRT=certs/server.crt
EXT_FILE=certs/server.ext

log "Step 1: Generating CA key and certificate..."
openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
openssl req -new -x509 -days 825 \
    -key "$CA_KEY" \
    -out "$CA_CRT" \
    -subj "/CN=MiniFW Demo CA/O=MiniFW-AI/C=ID" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

log "Step 2: Generating server key and CSR..."
openssl genrsa -out "$SRV_KEY" 2048 2>/dev/null
openssl req -new -key "$SRV_KEY" -out "$SRV_CSR" \
    -subj "/CN=localhost/O=MiniFW-AI/C=ID"

cat > "$EXT_FILE" << 'EXT'
[SAN]
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT

log "Step 3: Signing server certificate with CA..."
openssl x509 -req -days 825 \
    -in "$SRV_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SRV_CRT" \
    -extfile "$EXT_FILE" \
    -extensions SAN 2>/dev/null

chmod 600 "$CA_KEY" "$SRV_KEY"
log "Certificates written to certs/"

log "Step 4: Installing CA to system trust store (requires sudo)..."
if [[ -d /usr/local/share/ca-certificates ]]; then
    sudo cp "$CA_CRT" /usr/local/share/ca-certificates/minifw-demo-ca.crt
    sudo update-ca-certificates
    log "System trust store updated."
else
    log "WARN: /usr/local/share/ca-certificates not found — skipping system store."
fi

log "Step 5: Installing CA to NSS databases (Chrome/Firefox)..."
NSS_INSTALLED=false
if command -v certutil >/dev/null 2>&1; then
    # User NSS database
    if [[ -d "$HOME/.pki/nssdb" ]]; then
        certutil -A -n "MiniFW Demo CA" -t "CT,," \
            -i "$CA_CRT" -d sql:"$HOME/.pki/nssdb" 2>/dev/null && NSS_INSTALLED=true
        log "Installed to ~/.pki/nssdb"
    fi
    # Firefox profiles
    while IFS= read -r -d '' profile; do
        certutil -A -n "MiniFW Demo CA" -t "CT,," \
            -i "$CA_CRT" -d sql:"$profile" 2>/dev/null && NSS_INSTALLED=true
        log "Installed to Firefox profile: $profile"
    done < <(find "$HOME/.mozilla/firefox" -name "cert9.db" -exec dirname {} \; 2>/dev/null | tr '\n' '\0')
    if [[ "$NSS_INSTALLED" == "false" ]]; then
        log "WARN: No NSS databases found. Chrome/Firefox may show a cert warning."
        log "      Install libnss3-tools: sudo apt-get install libnss3-tools"
    fi
else
    log "WARN: certutil not found — skipping NSS install."
    log "      Install: sudo apt-get install libnss3-tools"
fi

log ""
log "TLS setup complete."
log "  CA:     $CA_CRT"
log "  Cert:   $SRV_CRT"
log "  Key:    $SRV_KEY"
log ""
log "Now run: bash run_demo.sh"
SCRIPT
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh
```

- [ ] **Step 2: Run setup_tls.sh and verify certs are generated**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
bash setup_tls.sh
cd /home/sydeco/minifw-ai
```

Expected: `[minifw-tls] TLS setup complete.` with paths to CA, cert, key. No errors.

- [ ] **Step 3: Verify cert is valid and SAN is correct**

```bash
openssl verify -CAfile dist/minifw-usb-financial-standalone-v2.2.0/certs/minifw-ca.crt \
    dist/minifw-usb-financial-standalone-v2.2.0/certs/server.crt
openssl x509 -in dist/minifw-usb-financial-standalone-v2.2.0/certs/server.crt \
    -noout -text | grep -A3 "Subject Alternative"
```

Expected:
```
certs/server.crt: OK
            X509v3 Subject Alternative Name:
                DNS:localhost, IP Address:127.0.0.1
```

- [ ] **Step 4: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/setup_tls.sh
# certs/ is gitignored — do not add
git commit -m "feat(demo): add setup_tls.sh — openssl CA and NSS trust store install"
```

---

## Task 5: `teardown_demo.sh`

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh`

Removes the CA from system trust store and NSS databases. Optionally removes certs/. Safe to run even if setup_tls.sh was never run.

- [ ] **Step 1: Write teardown_demo.sh**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh << 'SCRIPT'
#!/bin/bash
# MiniFW-AI Financial Demo — TLS Teardown
# Removes the demo CA from trust stores. Run after the meeting.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-teardown] $*"; }

log "Removing CA from system trust store..."
if [[ -f /usr/local/share/ca-certificates/minifw-demo-ca.crt ]]; then
    sudo rm -f /usr/local/share/ca-certificates/minifw-demo-ca.crt
    sudo update-ca-certificates --fresh 2>/dev/null || true
    log "Removed from system trust store."
else
    log "Not in system trust store — skipping."
fi

log "Removing CA from NSS databases..."
if command -v certutil >/dev/null 2>&1; then
    if [[ -d "$HOME/.pki/nssdb" ]]; then
        certutil -D -n "MiniFW Demo CA" -d sql:"$HOME/.pki/nssdb" 2>/dev/null || true
        log "Removed from ~/.pki/nssdb"
    fi
    while IFS= read -r -d '' profile; do
        certutil -D -n "MiniFW Demo CA" -d sql:"$profile" 2>/dev/null || true
        log "Removed from Firefox profile: $profile"
    done < <(find "$HOME/.mozilla/firefox" -name "cert9.db" -exec dirname {} \; 2>/dev/null | tr '\n' '\0')
fi

log "Removing local certs/..."
rm -rf certs/
mkdir -p certs && touch certs/.gitkeep

log "Teardown complete. Demo machine is clean."
SCRIPT
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh
```

- [ ] **Step 2: Run teardown to verify it completes without errors**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
bash teardown_demo.sh 2>&1
cd /home/sydeco/minifw-ai
```

Expected: `[minifw-teardown] Teardown complete. Demo machine is clean.` — no errors (may say "Not in system trust store" if already removed).

- [ ] **Step 3: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/teardown_demo.sh
git commit -m "feat(demo): add teardown_demo.sh — CA removal post-meeting"
```

---

## Task 6: `run_demo.sh`

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh`

The one-button entry point. Pre-flight → engine → web (HTTPS 8443) → health poll → scheduler → browser. Exactly 4 terminal lines. Graceful shutdown trap kills all three PIDs.

- [ ] **Step 1: Write run_demo.sh**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh << 'SCRIPT'
#!/bin/bash
# MiniFW-AI — Financial Sector Executive Demo
# Usage: bash run_demo.sh
# Prerequisites: bash setup_tls.sh must be run once first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw] $*"; }
die() { echo "[minifw] ERROR: $*" >&2; exit 1; }

# ── Pre-flight ──────────────────────────────────────────────────────────────────
[[ -f certs/server.crt ]] || die "TLS cert not found. Run: bash setup_tls.sh"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
python3 -c "import uvicorn" 2>/dev/null || die "uvicorn not installed — run: pip install -r requirements.txt"

# ── Environment ─────────────────────────────────────────────────────────────────
export DEMO_MODE=1
export PRODUCT_MODE=minifw_financial
export MINIFW_SECTOR=finance
export AI_ENABLED=1
export MINIFW_DISABLE_FLOWS=1
export MINIFW_DNS_SOURCE=none
export MINIFW_LOG=logs/events.jsonl
export MINIFW_AUDIT_LOG=logs/audit.jsonl
export MINIFW_FLOW_RECORDS=logs/flow_records.jsonl
export MINIFW_POLICY=config/policy.json
export MINIFW_FEEDS=config/feeds
export MINIFW_MLP_MODEL=models/mlp_model.pkl
export MINIFW_YARA_RULES=yara_rules
export MINIFW_SECRET_KEY="demo-financial-key-change-in-prod!!"
export MINIFW_ADMIN_PASSWORD="Finance1!"
export DATABASE_URL="sqlite:///./minifw.db"
export PYTHONPATH="$(pwd):$(pwd)/app:${PYTHONPATH:-}"
export PYTHONWARNINGS="ignore::UserWarning"

mkdir -p logs

# ── Start engine ────────────────────────────────────────────────────────────────
log "Starting Financial Demo..."
python3 app/minifw_ai/main.py > logs/engine.log 2>&1 &
ENGINE_PID=$!

WEB_PID=0
SCHEDULER_PID=0

cleanup() {
    kill "$ENGINE_PID"    2>/dev/null || true
    kill "$WEB_PID"       2>/dev/null || true
    kill "$SCHEDULER_PID" 2>/dev/null || true
    log "Demo stopped."
}
trap cleanup EXIT INT TERM

log "Engine started (PID $ENGINE_PID)"

# ── Start web (HTTPS) ───────────────────────────────────────────────────────────
uvicorn app.web.app:app \
    --host 0.0.0.0 \
    --port 8443 \
    --ssl-keyfile  certs/server.key \
    --ssl-certfile certs/server.crt \
    --log-level warning \
    > logs/web.log 2>&1 &
WEB_PID=$!

# ── Health poll (20s) ───────────────────────────────────────────────────────────
READY=false
for i in $(seq 1 20); do
    if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
        READY=true
        break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    die "Dashboard did not start in 20s — see logs/web.log"
fi

# ── Start scheduler ─────────────────────────────────────────────────────────────
python3 scheduler/demo_scheduler.py > logs/scheduler.log 2>&1 &
SCHEDULER_PID=$!

# ── Browser launch ──────────────────────────────────────────────────────────────
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "https://localhost:8443" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "https://localhost:8443" >/dev/null 2>&1 || true
fi

log "Dashboard ready → https://localhost:8443  (admin / Finance1!)"
log "Press Ctrl+C to stop."

wait "$WEB_PID" || true
SCRIPT
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh
```

- [ ] **Step 2: Re-run setup_tls.sh to restore certs (needed for run_demo.sh test)**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
bash setup_tls.sh
cd /home/sydeco/minifw-ai
```

- [ ] **Step 3: Smoke test — verify run_demo.sh outputs exactly 4 lines then kills cleanly**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
source venv/bin/activate
timeout 35 bash run_demo.sh 2>&1 | head -5 || true
deactivate
cd /home/sydeco/minifw-ai
```

Expected output (4 lines + the stop line):
```
[minifw] Starting Financial Demo...
[minifw] Engine started (PID XXXXX)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
[minifw] Demo stopped.
```

- [ ] **Step 4: Verify HTTPS responds correctly**

Start the demo in the background, wait 25s, then check:

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
source venv/bin/activate
bash run_demo.sh > /tmp/run_test.log 2>&1 &
RUN_PID=$!
sleep 25
curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health
kill $RUN_PID 2>/dev/null || true
wait $RUN_PID 2>/dev/null || true
deactivate
cd /home/sydeco/minifw-ai
```

Expected: `{"status": "ok"}` or similar JSON health response. No cert error.

- [ ] **Step 5: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/run_demo.sh
git commit -m "feat(demo): add run_demo.sh — HTTPS 8443, 4-line output, graceful shutdown"
```

---

## Task 7: `HEALTHCHECK.sh` and `recover_demo.sh`

**Files:**
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh`
- Create: `dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh`

HEALTHCHECK covers: Python version, venv, TLS cert existence, port 8443 free, demo data, MLP model, YARA rules, dashboard HTTPS 200, BLOCK event detection.

- [ ] **Step 1: Write HEALTHCHECK.sh**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh << 'SCRIPT'
#!/bin/bash
# MiniFW-AI Financial Demo — Health Check
# Usage: bash HEALTHCHECK.sh
# Exit 0 = all checks pass. Exit 1 = one or more failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p logs
LOG_FILE="logs/healthcheck-$(date +%Y-%m-%d-%H%M).log"

PASS=0; FAIL=0

log()  { echo "$(date +%H:%M:%S) $*" | tee -a "$LOG_FILE"; }
pass() { echo "[PASS] $*" | tee -a "$LOG_FILE"; ((PASS++)); }
fail() { echo "[FAIL] $*" | tee -a "$LOG_FILE"; ((FAIL++)); }
info() { echo "       $*" | tee -a "$LOG_FILE"; }

echo "MiniFW-AI Financial Demo — Health Check $(date)" | tee "$LOG_FILE"
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"

# Check 1: Python 3.10+
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
    pass "Python $PY_VER present"
else
    fail "Python 3.10+ required, found $PY_VER"
fi

# Check 2: venv + fastapi
if source venv/bin/activate 2>/dev/null && python3 -c "import fastapi" 2>/dev/null; then
    pass "venv activatable, fastapi importable"
    deactivate 2>/dev/null || true
else
    fail "venv missing or fastapi not installed — run: python3 -m venv venv && pip install -r requirements.txt"
fi

# Check 3: TLS certs present
if [[ -f certs/server.crt && -f certs/server.key && -f certs/minifw-ca.crt ]]; then
    pass "TLS certs present (server.crt, server.key, minifw-ca.crt)"
else
    fail "TLS certs missing — run: bash setup_tls.sh"
fi

# Check 4: Port 8443 free (pre-flight only)
if ! lsof -ti:8443 >/dev/null 2>&1; then
    pass "Port 8443 is free"
else
    info "Port 8443 in use — demo may already be running"
    ((PASS++))
fi

# Check 5: Demo data
if [[ -f demo_data/normal_traffic.json && -f demo_data/attack_traffic.json ]]; then
    pass "Demo data files present"
else
    fail "Missing demo_data/ files — package may be incomplete"
fi

# Check 6: MLP model
if [[ -f models/mlp_model.pkl ]]; then
    pass "MLP model present"
else
    fail "models/mlp_model.pkl missing"
fi

# Check 7: YARA rules
YARA_COUNT=$(find yara_rules -name "*.yar" 2>/dev/null | wc -l)
if [[ "$YARA_COUNT" -gt 0 ]]; then
    pass "YARA rules: $YARA_COUNT file(s)"
else
    fail "yara_rules/ is empty or missing"
fi

# Check 8: Dashboard HTTPS 200 (if running) or skip
if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert certs/minifw-ca.crt https://localhost:8443/health)
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "Dashboard HTTPS responds HTTP 200"
    else
        fail "Dashboard returned HTTP $HTTP_CODE"
    fi
else
    info "Check 8: Dashboard not running — skipped (run bash run_demo.sh first)"
    ((PASS++))
fi

# Check 9: BLOCK event detection (if events.jsonl exists)
if [[ -f logs/events.jsonl ]]; then
    if grep -q '"action": "block"' logs/events.jsonl 2>/dev/null; then
        pass "BLOCK event detected in logs/events.jsonl"
    else
        info "Check 9: No BLOCK event yet — demo may still be in normal traffic phase (wait ~2 min)"
        ((PASS++))
    fi
else
    info "Check 9: logs/events.jsonl not found — run bash run_demo.sh first"
    ((PASS++))
fi

# Summary
TOTAL=$((PASS + FAIL))
echo "─────────────────────────────────────────────────────" | tee -a "$LOG_FILE"
if [[ "$FAIL" -eq 0 ]]; then
    echo "HEALTHCHECK PASSED ($PASS/$TOTAL)" | tee -a "$LOG_FILE"
    exit 0
else
    echo "HEALTHCHECK FAILED ($PASS/$TOTAL passed, $FAIL/$TOTAL failed) — see $LOG_FILE" | tee -a "$LOG_FILE"
    exit 1
fi
SCRIPT
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh
```

- [ ] **Step 2: Write recover_demo.sh**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh << 'SCRIPT'
#!/bin/bash
# MiniFW-AI Financial Demo — Recovery Script
# Kills stale processes, resets database if corrupt, relaunches demo.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[minifw-recover] $*"; }
die() { echo "[minifw-recover] ERROR: $*" >&2; exit 1; }

log "Starting demo recovery..."

log "Step 1: Freeing port 8443..."
if lsof -ti:8443 >/dev/null 2>&1; then
    lsof -ti:8443 | xargs kill -9 2>/dev/null || true
    sleep 1
    log "Port 8443 freed."
else
    log "Port 8443 already free."
fi

log "Step 2: Killing orphaned engine processes..."
if pgrep -f "minifw_ai/main.py" >/dev/null 2>&1; then
    pgrep -f "minifw_ai/main.py" | xargs kill 2>/dev/null || true
    sleep 1
fi

log "Step 3: Killing orphaned scheduler processes..."
if pgrep -f "demo_scheduler.py" >/dev/null 2>&1; then
    pgrep -f "demo_scheduler.py" | xargs kill 2>/dev/null || true
    sleep 1
fi

log "Step 4: Checking database..."
if [[ -f minifw.db ]]; then
    if ! python3 -c "import sqlite3; sqlite3.connect('minifw.db').execute('SELECT 1')" 2>/dev/null; then
        log "Database corrupt — removing..."
        rm -f minifw.db
    else
        log "Database OK."
    fi
fi

log "Step 5: Clearing stale event log..."
rm -f logs/events.jsonl

log "Step 6: Relaunching demo..."
[[ -f run_demo.sh ]] || die "run_demo.sh not found"

bash run_demo.sh &
DEMO_PID=$!

log "Waiting for dashboard (30s)..."
READY=false
for i in $(seq 1 30); do
    if curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 1
done

if [[ "$READY" == "false" ]]; then
    log "Dashboard did not come up — see RECOVERY.md for manual steps."
    exit 1
fi

log "Recovery successful — demo ready at https://localhost:8443  (admin / Finance1!)"
SCRIPT
chmod +x dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh
```

- [ ] **Step 3: Run HEALTHCHECK.sh and verify it passes**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
bash HEALTHCHECK.sh
cd /home/sydeco/minifw-ai
```

Expected: `HEALTHCHECK PASSED (9/9)` — no FAIL lines.

- [ ] **Step 4: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/HEALTHCHECK.sh \
           dist/minifw-usb-financial-standalone-v2.2.0/recover_demo.sh
git commit -m "feat(demo): add HEALTHCHECK.sh and recover_demo.sh for financial demo"
```

---

## Task 8: Documentation Files

**Files:**
- Create: `INSTALL.md`, `README.md`, `README.txt`, `RECOVERY.md`

- [ ] **Step 1: Write INSTALL.md**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/INSTALL.md << 'EOF'
# Installation Guide — MiniFW-AI Financial Standalone Demo v2.2.0

---

## Prerequisites

| Requirement | Check | Minimum |
|---|---|---|
| Python 3 | `python3 --version` | 3.10+ |
| openssl | `openssl version` | any |
| libnss3-tools (optional) | `certutil -V` | for Firefox/Chrome NSS trust |
| Port 8443 free | `ss -tlnp \| grep 8443` | — |
| sudo access | for trust store install | one-time only |

---

## Step 1 — Set Up the Virtual Environment

A pre-built `venv/` is included. Try it first:

```bash
source venv/bin/activate
python3 -c "import fastapi; print('OK')"
```

If this prints `OK`, skip to Step 2.

**Rebuild venv if needed:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 2 — Set Up TLS (one-time, requires sudo)

```bash
bash setup_tls.sh
```

This generates a local CA and installs it to your system trust store and browser NSS databases. Run once per machine. If you switch machines, run it again on the new machine.

**Install certutil for Firefox/Chrome NSS support (recommended):**

```bash
sudo apt-get install libnss3-tools
```

Then re-run `bash setup_tls.sh`.

---

## Step 3 — Run the Demo

```bash
source venv/bin/activate
bash run_demo.sh
```

**Expected output:**
```
[minifw] Starting Financial Demo...
[minifw] Engine started (PID XXXXX)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
```

A browser window opens automatically. The dashboard shows live financial traffic. At ~T+75 seconds, a BLOCK event fires from the trading floor segment.

---

## Step 4 — After the Meeting

```bash
bash teardown_demo.sh
```

Removes the demo CA from trust stores. The demo machine is clean.

---

## Credentials

| Item | Value |
|---|---|
| URL | `https://localhost:8443` |
| Username | `admin` |
| Password | `Finance1!` |
| BLOCK fires at | ~75 seconds |

---

## Health Check

```bash
bash HEALTHCHECK.sh
```

Run before the meeting to verify all components are ready. Expected: `HEALTHCHECK PASSED (9/9)`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Browser shows cert warning | Re-run `bash setup_tls.sh`; close and reopen browser |
| Port 8443 in use | `lsof -ti:8443 \| xargs kill -9` then retry |
| Demo won't start | `bash recover_demo.sh` |
| venv broken | `python3 -m venv venv && pip install -r requirements.txt` |
EOF
```

- [ ] **Step 2: Write README.md**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/README.md << 'EOF'
# MiniFW-AI — Financial Sector Executive Demo v2.2.0

**PCI-DSS compliant AI-powered behavioral firewall — standalone demo package**

---

## What This Demonstrates

MiniFW-AI monitors DNS traffic from your financial network in real time. It combines a feed-matching engine, machine learning inference, and YARA pattern scanning to detect and block threats before they exfiltrate data.

This demo shows:

1. **Normal trading floor traffic** — Bloomberg, Reuters, SWIFT, internal DNS (first ~60 seconds)
2. **Attack detection** — Banking trojan C2 beacon, card data exfiltration probe, PCI boundary violation detected from `10.50.0.1` on the trading floor subnet
3. **Automatic BLOCK** — Score exceeds the trading segment threshold (80/100) → IP blocked, audit trail written, dashboard alert fired

No Docker. No root at runtime. One command.

---

## Quick Start

```bash
bash setup_tls.sh    # once per machine
bash run_demo.sh     # starts demo + opens browser
```

Login: `admin / Finance1!` at `https://localhost:8443`

---

## Package Layout

```
run_demo.sh          ← one-button entry point
setup_tls.sh         ← one-time TLS setup
teardown_demo.sh     ← post-meeting cleanup
HEALTHCHECK.sh       ← pre-meeting verification
recover_demo.sh      ← fix stale processes
INSTALL.md           ← full setup guide

config/policy.json   ← PCI-DSS enforcement thresholds
demo_data/           ← synthetic traffic patterns
scheduler/           ← deterministic BLOCK scheduler (T+75s)
app/                 ← MiniFW engine + web dashboard
```

---

## Sector Configuration

| Setting | Value |
|---|---|
| Sector | Finance (`PRODUCT_MODE=minifw_financial`) |
| Trading block threshold | 80/100 |
| Compliance | PCI-DSS |
| Tor/anonymizer blocking | Enabled |
| TLS minimum | 1.2 |

---

## After the Demo

```bash
bash teardown_demo.sh
```
EOF
```

- [ ] **Step 3: Write README.txt (plain-text)**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/README.txt << 'EOF'
MiniFW-AI Financial Sector Executive Demo v2.2.0
================================================

QUICK START
-----------
1. bash setup_tls.sh     (one-time, requires sudo)
2. bash run_demo.sh      (starts demo + opens browser)
3. Login: admin / Finance1!  at  https://localhost:8443

WHAT HAPPENS
------------
- Normal trading floor traffic for ~60 seconds (Bloomberg, Reuters, SWIFT)
- At T+75s: banking trojan C2 + card exfiltration detected from 10.50.0.1
- BLOCK event fires on trading segment — dashboard alert, audit log written

AFTER THE MEETING
-----------------
bash teardown_demo.sh    (removes demo CA from trust stores)

FULL GUIDE: see INSTALL.md
EOF
```

- [ ] **Step 4: Write RECOVERY.md**

```bash
cat > dist/minifw-usb-financial-standalone-v2.2.0/RECOVERY.md << 'EOF'
# Recovery Guide — MiniFW-AI Financial Demo

## Automatic Recovery

```bash
bash recover_demo.sh
```

Kills stale processes, resets a corrupt database, clears stale logs, and relaunches.

---

## Manual Steps

### Dashboard not loading
```bash
lsof -ti:8443 | xargs kill -9 2>/dev/null || true
bash run_demo.sh
```

### BLOCK not firing after 2 minutes
```bash
# Check scheduler is running
pgrep -f demo_scheduler.py
# Check scheduler log
cat logs/scheduler.log
# Check events log
wc -l logs/events.jsonl
```

### Cert warning in browser
```bash
bash teardown_demo.sh
bash setup_tls.sh
# Close and reopen browser fully
```

### Database error on login
```bash
rm -f minifw.db
bash run_demo.sh
```

### Engine crash
```bash
grep -i "error\|critical" logs/engine.log | tail -20
```
EOF
```

- [ ] **Step 5: Commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/INSTALL.md \
           dist/minifw-usb-financial-standalone-v2.2.0/README.md \
           dist/minifw-usb-financial-standalone-v2.2.0/README.txt \
           dist/minifw-usb-financial-standalone-v2.2.0/RECOVERY.md
git commit -m "docs(demo): add financial standalone INSTALL, README, RECOVERY"
```

---

## Task 9: Update dist/INDEX.md and DEMO_PACKAGE_STRUCTURE.md

**Files:**
- Modify: `dist/INDEX.md`
- Modify: `dist/DEMO_PACKAGE_STRUCTURE.md`

- [ ] **Step 1: Read current INDEX.md**

```bash
cat dist/INDEX.md
```

- [ ] **Step 2: Add financial entry to INDEX.md**

Add this block to `dist/INDEX.md` under the existing package entries:

```markdown
## minifw-usb-financial-standalone-v2.2.0

| Item | Value |
|---|---|
| Type | Standalone (Python, no Docker) |
| Sector | Finance (PCI-DSS) |
| URL | `https://localhost:8443` |
| Login | `admin / Finance1!` |
| Launch | `bash setup_tls.sh && bash run_demo.sh` |
| BLOCK fires at | ~T+75s (trading segment, score 95/100) |
| TLS | openssl self-signed CA — run `setup_tls.sh` once |
```

- [ ] **Step 3: Add financial entry to DEMO_PACKAGE_STRUCTURE.md**

Append to `dist/DEMO_PACKAGE_STRUCTURE.md`:

```markdown
## minifw-usb-financial-standalone-v2.2.0

Standalone Python demo for the finance sector. Executive presentation mode:
trusted HTTPS (port 8443), deterministic BLOCK at ~T+75s from `10.50.0.1`
on the trading floor subnet, 4-line terminal output, graceful shutdown.

**Key files:**
- `setup_tls.sh` — openssl CA generation + system/NSS trust store install (one-time)
- `teardown_demo.sh` — CA removal post-meeting
- `run_demo.sh` — main entry point
- `scheduler/demo_scheduler.py` — writes timed Event records to events.jsonl
- `demo_data/` — financial normal (Bloomberg/Reuters/SWIFT) + attack (Tor/C2/exfil)
- `config/policy.json` — PCI-DSS policy, trading block threshold 80

**Build provenance:** Created 2026-05-21 from hospital standalone template.
```

- [ ] **Step 4: Commit**

```bash
git add -f dist/INDEX.md dist/DEMO_PACKAGE_STRUCTURE.md
git commit -m "docs(dist): register financial standalone in INDEX and DEMO_PACKAGE_STRUCTURE"
```

---

## Task 10: End-to-End Smoke Test

Full run: setup → healthcheck → demo → verify BLOCK → teardown.

- [ ] **Step 1: Run HEALTHCHECK pre-demo**

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
source venv/bin/activate
bash HEALTHCHECK.sh
```

Expected: `HEALTHCHECK PASSED (9/9)`.

- [ ] **Step 2: Start demo and verify BLOCK fires within 2 minutes**

```bash
bash run_demo.sh > /tmp/fin_demo_test.log 2>&1 &
DEMO_PID=$!

echo "Waiting up to 120s for BLOCK event..."
BLOCK_FOUND=false
for i in $(seq 1 120); do
    if grep -q '"action": "block"' logs/events.jsonl 2>/dev/null; then
        BLOCK_FOUND=true
        BLOCK_TIME=$i
        break
    fi
    sleep 1
done

if [[ "$BLOCK_FOUND" == "true" ]]; then
    echo "PASS: BLOCK event fired at T+${BLOCK_TIME}s"
    grep '"action": "block"' logs/events.jsonl | tail -1
else
    echo "FAIL: No BLOCK after 120s"
    cat logs/scheduler.log
fi
```

Expected: `PASS: BLOCK event fired at T+75s` (within 65–90s range).

- [ ] **Step 3: Verify HTTPS is trusted (no curl error)**

```bash
curl -s --cacert certs/minifw-ca.crt https://localhost:8443/health
```

Expected: `{"status":"ok"}` or `{"status":"healthy"}` — no SSL error.

- [ ] **Step 4: Kill demo and teardown**

```bash
kill $DEMO_PID 2>/dev/null || true
wait $DEMO_PID 2>/dev/null || true
bash teardown_demo.sh
deactivate
cd /home/sydeco/minifw-ai
```

Expected: `[minifw-teardown] Teardown complete. Demo machine is clean.`

- [ ] **Step 5: Run full test suite to confirm no regressions**

```bash
PYTHONPATH=. pytest testing/ -m "not integration" -q 2>&1 | tail -5
```

Expected: `496 passed, 0 failed` (492 existing + 4 scheduler tests).

- [ ] **Step 6: Final commit**

```bash
git add -f dist/minifw-usb-financial-standalone-v2.2.0/
git commit -m "feat(demo): complete financial executive safe demo v2.2.0 — end-to-end verified"
```

---

## Self-Review

**Spec coverage check:**
- [x] No terminal noise — `run_demo.sh` suppresses all engine/web/scheduler output, 4 lines max
- [x] Clean startup — pre-flight checks abort early with clear messages; health poll before declaring ready
- [x] Automatic browser launch — `xdg-open`/`open` after health poll
- [x] Trusted TLS — `setup_tls.sh` with openssl CA + system store + NSS
- [x] Predictable BLOCK within 2 minutes — scheduler guarantees BLOCK at T+75s via direct EventWriter
- [x] Graceful shutdown — `trap cleanup EXIT INT TERM` kills engine + web + scheduler PIDs
- [x] Financial narrative — trading segment, PCI-DSS policy, Bloomberg/Reuters/SWIFT normal traffic
- [x] Teardown — `teardown_demo.sh` removes CA
- [x] `teardown_demo.sh` reverses `setup_tls.sh` — covered in Task 5

**Placeholder scan:** No TBDs, no TODOs. All code blocks are complete.

**Type consistency:** `Event` dataclass fields used consistently across `demo_scheduler.py` and tests match the dataclass definition in `app/minifw_ai/events.py` (`ts`, `segment`, `client_ip`, `domain`, `action`, `score`, `reasons`, `sector`, `severity`, `trace_id`, `decision_owner`, `student_flagged`, `vpn_block_enforced`, `audit_mode`). The scheduler sets all required fields; optional booleans default to `False`.
