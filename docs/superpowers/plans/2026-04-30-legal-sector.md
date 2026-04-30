# Legal Sector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `minifw_legal` as a first-class sector with policy config, YARA rules, demo injector, Docker compose files, build script entries, and three documentation files — mirroring the education sector pattern.

**Architecture:** Legal sector follows the Core + Sector Overlay model. A new `PRODUCT_MODE=minifw_legal` is registered in `mode_context.py`, backed by `config/modes/minifw_legal/policy.json`. A Docker-based demo injector simulates 6 law firm threat scenarios. Build scripts (`build_usb.sh`, `scripts/build_deb.sh`) gain a `legal)` case. The attack simulator gains legal domain/reason tables for the web dashboard demo mode.

**Tech Stack:** Python 3.12, YARA, Docker Compose v2, bash, FastAPI (existing), AdminLTE 3 (existing)

---

## Scoring Notes (read before implementing)

The demo pipeline scores DNS events by summing weights:
- DNS feed match (`deny_domains.txt`): **+40**
- YARA match: **+35**
- ASN deny: **+15**
- IP deny: **+15**
- Burst: **+10**

Per-segment thresholds in `policy.json`. The associate block threshold is set to **72** (not 78) so that feed(40)+YARA(35)=75 fires a BLOCK cleanly. The `deny_domains.txt` additions are fake demo-only domains — safe to add globally.

**Phase scoring verification:**
| Phase | Domain | Score | Segment | Threshold | Result |
|-------|--------|-------|---------|-----------|--------|
| 2 — cloud upload | wetransfer-legal.io (feed only) | 40 | paralegal monitor=38 / block=70 | 38 < 40 < 70 | MONITOR ✓ |
| 3 — Tor exit | tor-exit-relay.onion-gw.net (feed+YARA) | 75 | client block=62 | 75 > 62 | BLOCK ✓ |
| 4 — Ransomware C2 | clio-encrypt.c2-server.ru (feed+YARA) | 75 | associate block=72 | 75 > 72 | BLOCK ✓ |
| 5 — Privilege breach | opposing-counsel.harvest.io (feed+YARA) | 75 | paralegal block=70 | 75 > 70 | BLOCK ✓ |

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| CREATE | `config/modes/minifw_legal/policy.json` | Per-segment thresholds, score weights, subnets |
| MODIFY | `app/minifw_ai/mode_context.py` | Add `minifw_legal` UI entry; update `_SECTOR_TO_MODE` |
| MODIFY | `app/services/demo/attack_simulator.py` | Add legal domain/reason tables |
| CREATE | `yara_rules/legal_rules.yar` | 4 YARA rules for legal threat landscape |
| MODIFY | `config/feeds/deny_domains.txt` | Add 4 legal demo domains |
| CREATE | `docker/demo-injector-legal/Dockerfile` | Minimal Python image for injector |
| CREATE | `docker/demo-injector-legal/inject.py` | 6-phase legal demo traffic loop |
| CREATE | `docker/docker-compose.legal.yml` | Source-build compose (port 8448) |
| CREATE | `docker/docker-compose.usb-legal.yml` | USB pre-loaded image compose |
| MODIFY | `build_usb.sh` | Add `legal)` case |
| MODIFY | `scripts/build_deb.sh` | Update header comment to include legal example |
| CREATE | `docs/legal/demo-guide.md` | Sales demo script |
| CREATE | `docs/legal/INSTALL.md` | Installation guide |
| CREATE | `docs/legal/README.md` | Tutorial (demo mode + production mode) |
| CREATE | `testing/test_legal_sector.py` | YARA compile + match tests |

---

## Task 1: Policy config and mode registration

**Files:**
- Create: `config/modes/minifw_legal/policy.json`
- Modify: `app/minifw_ai/mode_context.py`

- [ ] **Step 1.1: Write the failing test**

Create `testing/test_legal_sector.py`:

```python
import os
import pytest


def test_mode_context_resolves_minifw_legal(monkeypatch):
    monkeypatch.setenv("PRODUCT_MODE", "minifw_legal")
    monkeypatch.delenv("MINIFW_SECTOR", raising=False)
    from app.minifw_ai import mode_context
    import importlib
    importlib.reload(mode_context)
    ui = mode_context.get_mode_ui()
    assert ui.product_mode == "minifw_legal"
    assert ui.sector == "legal"
    assert ui.label == "Legal"


def test_sector_to_mode_maps_legal(monkeypatch):
    monkeypatch.delenv("PRODUCT_MODE", raising=False)
    monkeypatch.setenv("MINIFW_SECTOR", "legal")
    from app.minifw_ai import mode_context
    import importlib
    importlib.reload(mode_context)
    ui = mode_context.get_mode_ui()
    assert ui.product_mode == "minifw_legal"
```

- [ ] **Step 1.2: Run test to verify it fails**

```bash
cd /home/sydeco/minifw-ai
source .venv/bin/activate
pytest testing/test_legal_sector.py -v
```

Expected: FAIL — `AssertionError: assert '' == 'minifw_legal'` (legal falls back to establishment).

- [ ] **Step 1.3: Create the policy config**

```bash
mkdir -p config/modes/minifw_legal
```

Create `config/modes/minifw_legal/policy.json`:

```json
{
  "_mode": "minifw_legal",
  "_sector": "legal",
  "_note": "Attorney-client privilege protection, data exfiltration blocking, ransomware C2 detection. Associate block=72 ensures feed+YARA score of 75 fires cleanly.",
  "segments": {
    "default": {
      "block_threshold": 80,
      "monitor_threshold": 50
    },
    "partner": {
      "block_threshold": 85,
      "monitor_threshold": 55,
      "_note": "Senior counsel — most trusted, relaxed thresholds."
    },
    "associate": {
      "block_threshold": 72,
      "monitor_threshold": 45,
      "_note": "Junior lawyers — standard threshold. 72 ensures feed+YARA(75) triggers BLOCK."
    },
    "paralegal": {
      "block_threshold": 70,
      "monitor_threshold": 38,
      "_note": "Support staff — stricter. feed-only score(40) lands in MONITOR band."
    },
    "client": {
      "block_threshold": 62,
      "monitor_threshold": 30,
      "_note": "Client meeting rooms — tight thresholds, unknown devices."
    },
    "guest": {
      "block_threshold": 60,
      "monitor_threshold": 28,
      "_note": "Visitor WiFi — tightest thresholds."
    }
  },
  "segment_subnets": {
    "partner":   ["10.20.0.0/24"],
    "associate": ["10.20.1.0/24"],
    "paralegal": ["10.20.2.0/24"],
    "client":    ["192.168.200.0/24"],
    "guest":     ["192.168.100.0/24"]
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
    "zeek_ssl_log_path": "/var/log/zeek/ssl.log",
    "use_zeek_sni": false
  },
  "burst": {
    "dns_queries_per_minute_monitor": 30,
    "dns_queries_per_minute_block":   50
  },
  "iomt_subnets": [],
  "safesearch_domains": []
}
```

- [ ] **Step 1.4: Add `minifw_legal` to `mode_context.py`**

Open `app/minifw_ai/mode_context.py`. In `_MODE_UI`, add after the `"minifw_gambling"` entry:

```python
    "minifw_legal": ModeUI(
        product_mode="minifw_legal",
        label="Legal",
        sublabel="Attorney-Client Privilege · Data Exfiltration · Ransomware",
        color="#b45309",
        bg="rgba(180,83,9,0.10)",
        css_class="mode-legal",
        icon="bi-briefcase",
        sector="legal",
    ),
```

In `_SECTOR_TO_MODE`, change:

```python
    "legal":         "minifw_establishment",   # no dedicated legal mode yet
```

to:

```python
    "legal":         "minifw_legal",
```

- [ ] **Step 1.5: Run test to verify it passes**

```bash
pytest testing/test_legal_sector.py::test_mode_context_resolves_minifw_legal testing/test_legal_sector.py::test_sector_to_mode_maps_legal -v
```

Expected: 2 passed.

- [ ] **Step 1.6: Run full test suite to check for regressions**

```bash
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed, 0 failed.

- [ ] **Step 1.7: Commit**

```bash
git add config/modes/minifw_legal/policy.json app/minifw_ai/mode_context.py testing/test_legal_sector.py
git commit -m "feat(legal): add minifw_legal policy config and mode_context registration"
```

---

## Task 2: Attack simulator — legal domain and reason tables

**Files:**
- Modify: `app/services/demo/attack_simulator.py`

- [ ] **Step 2.1: Write the failing test**

Add to `testing/test_legal_sector.py`:

```python
def test_attack_simulator_has_legal_domains():
    from app.services.demo.attack_simulator import _DOMAINS, _REASONS, _PRODUCT_MODE_TO_SECTOR
    assert "legal" in _DOMAINS
    assert "malicious" in _DOMAINS["legal"]
    assert "benign" in _DOMAINS["legal"]
    assert len(_DOMAINS["legal"]["malicious"]) >= 4
    assert len(_DOMAINS["legal"]["benign"]) >= 4


def test_attack_simulator_has_legal_reasons():
    from app.services.demo.attack_simulator import _REASONS
    assert "legal" in _REASONS
    assert len(_REASONS["legal"]) >= 3


def test_attack_simulator_product_mode_maps_legal():
    from app.services.demo.attack_simulator import _PRODUCT_MODE_TO_SECTOR
    assert _PRODUCT_MODE_TO_SECTOR.get("minifw_legal") == "legal"
```

- [ ] **Step 2.2: Run to verify failure**

```bash
pytest testing/test_legal_sector.py::test_attack_simulator_has_legal_domains -v
```

Expected: FAIL — `AssertionError: assert 'legal' in {...}`.

- [ ] **Step 2.3: Add legal entries to attack_simulator.py**

Open `app/services/demo/attack_simulator.py`.

In `_DOMAINS`, add after the `"education"` entry:

```python
    "legal": {
        "malicious": [
            "clio-encrypt.c2-server.ru", "opposing-counsel.harvest.io",
            "case-data.darkweb.onion", "wetransfer-legal.io",
            "privilege-breach.leak.cc", "client-data.dump.io",
            "lexisnexis-ransom.cc", "tor-exit-relay.onion-gw.net",
        ],
        "benign": [
            "westlaw.com", "lexisnexis.com", "courts.gov",
            "microsoft.com", "office365.com", "teams.microsoft.com",
            "practicepanther.com", "clio.com",
        ],
    },
```

In `_REASONS`, add after the `"education"` entry:

```python
    "legal": [
        ["dns_denied_domain", "hard_threat_gate"],
        ["yara_match", "hard_threat_gate"],
        ["mlp_threat_score", "asn_denied"],
        ["tls_sni_denied_domain", "hard_threat_gate"],
        ["dns_tunnel", "burst_behavior"],
    ],
```

In `_PRODUCT_MODE_TO_SECTOR`, add:

```python
    "minifw_legal": "legal",
```

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
pytest testing/test_legal_sector.py -v
```

Expected: all pass (including the 2 from Task 1).

- [ ] **Step 2.5: Commit**

```bash
git add app/services/demo/attack_simulator.py testing/test_legal_sector.py
git commit -m "feat(legal): add legal domain/reason tables to attack simulator"
```

---

## Task 3: YARA rules

**Files:**
- Create: `yara_rules/legal_rules.yar`
- Modify: `config/feeds/deny_domains.txt`

- [ ] **Step 3.1: Write the failing YARA tests**

Add to `testing/test_legal_sector.py`:

```python
import yara


def _compile_legal_rules():
    with open("yara_rules/legal_rules.yar", "r") as f:
        src = f.read()
    return yara.compile(sources={"legal": src})


def test_legal_yara_compiles():
    rules = _compile_legal_rules()
    assert rules is not None


def test_legal_ransomware_c2_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"clio-encrypt.c2-server.ru")
    assert any(m.rule == "LegalRansomwareC2" for m in matches)


def test_legal_privilege_violation_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"opposing-counsel.harvest.io")
    assert any(m.rule == "LegalPrivilegeViolation" for m in matches)


def test_legal_tor_exit_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"tor-exit-relay.onion-gw.net")
    assert any(m.rule == "LegalTorExitRelay" for m in matches)


def test_legal_data_exfil_rule_matches():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"gdrive-exfil.upload.io")
    assert any(m.rule == "LegalDataExfiltration" for m in matches)


def test_legal_benign_no_match():
    rules = _compile_legal_rules()
    matches = rules.match(data=b"westlaw.com")
    assert len(matches) == 0


def test_legal_wetransfer_not_in_yara():
    # wetransfer-legal.io must score via feed-only (+40) to land in MONITOR, not BLOCK
    rules = _compile_legal_rules()
    matches = rules.match(data=b"wetransfer-legal.io")
    assert len(matches) == 0
```

- [ ] **Step 3.2: Run to verify failure**

```bash
pytest testing/test_legal_sector.py::test_legal_yara_compiles -v
```

Expected: FAIL — `FileNotFoundError: yara_rules/legal_rules.yar`.

- [ ] **Step 3.3: Create `yara_rules/legal_rules.yar`**

```yara
rule LegalRansomwareC2
{
    meta:
        category    = "legal_ransomware_c2"
        severity    = "critical"
        description = "Detects ransomware C2 beacons targeting legal document management systems"
        author      = "MiniFW-AI"

    strings:
        $r1 = "clio-encrypt"     nocase
        $r2 = "lexisnexis-ransom" nocase
        $r3 = "case-mgmt-c2"     nocase
        $r4 = "ransomware-legal" nocase

    condition:
        any of them
}

rule LegalDataExfiltration
{
    meta:
        category    = "legal_data_exfiltration"
        severity    = "high"
        description = "Detects unauthorized cloud upload and exfiltration of case files"
        author      = "MiniFW-AI"

    strings:
        $e1 = "gdrive-exfil"   nocase
        $e2 = "onedrive-leak"  nocase
        $e3 = "case-upload.io" nocase
        $e4 = "dropbox-case"   nocase

    condition:
        any of them
}

rule LegalPrivilegeViolation
{
    meta:
        category    = "legal_privilege_violation"
        severity    = "critical"
        description = "Detects attorney-client privilege breach and opposing counsel data harvesting"
        author      = "MiniFW-AI"

    strings:
        $p1 = "opposing-counsel.harvest" nocase
        $p2 = "case-data.darkweb"        nocase
        $p3 = "privilege-breach"         nocase
        $p4 = "client-data.dump"         nocase

    condition:
        any of them
}

rule LegalTorExitRelay
{
    meta:
        category    = "legal_tor_exit"
        severity    = "high"
        description = "Detects Tor exit relay queries from client meeting rooms and guest subnets"
        author      = "MiniFW-AI"

    strings:
        $t1 = "tor-exit-relay" nocase
        $t2 = "onion-gw"       nocase
        $t3 = ".onion-"        nocase

    condition:
        any of them
}
```

- [ ] **Step 3.4: Add legal demo domains to deny_domains.txt**

Append these four lines to `config/feeds/deny_domains.txt`:

```
clio-encrypt.c2-server.ru
tor-exit-relay.onion-gw.net
opposing-counsel.harvest.io
wetransfer-legal.io
```

- [ ] **Step 3.5: Run YARA tests to verify they pass**

```bash
pytest testing/test_legal_sector.py -v
```

Expected: all pass.

- [ ] **Step 3.6: Run full suite**

```bash
pytest testing/ -m "not integration" -q
```

Expected: all pass, 0 failed.

- [ ] **Step 3.7: Commit**

```bash
git add yara_rules/legal_rules.yar config/feeds/deny_domains.txt testing/test_legal_sector.py
git commit -m "feat(legal): add legal YARA rules and deny_domains entries"
```

---

## Task 4: Demo injector

**Files:**
- Create: `docker/demo-injector-legal/Dockerfile`
- Create: `docker/demo-injector-legal/inject.py`

- [ ] **Step 4.1: Create the Dockerfile**

Create `docker/demo-injector-legal/Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /injector
COPY inject.py .
CMD ["python", "-u", "inject.py"]
```

- [ ] **Step 4.2: Create the injector script**

Create `docker/demo-injector-legal/inject.py`:

```python
#!/usr/bin/env python3
"""
MiniFW-AI Legal Sector Demo Injector

Writes dnsmasq-format log lines to a shared volume so the firewall engine
processes them and generates visible block/monitor/allow events on the dashboard.
"""
import os
import time

DNS_LOG_PATH = os.environ.get("DNS_LOG_PATH", "/logs/dnsmasq.log")


def line(domain: str, ip: str) -> str:
    return f"dnsmasq[1]: query[A] {domain} from {ip}\n"


def emit(f, domain: str, ip: str, label: str) -> None:
    f.write(line(domain, ip))
    f.flush()
    print(f"[LEGAL-INJECTOR]  {label:60s}  {ip}", flush=True)


def main() -> None:
    print(f"[LEGAL-INJECTOR] Starting. Target log: {DNS_LOG_PATH}", flush=True)
    time.sleep(8)

    loop = 0
    with open(DNS_LOG_PATH, "a") as f:
        while True:
            loop += 1
            print(f"\n[LEGAL-INJECTOR] -- Loop {loop} --", flush=True)

            # 1. Legitimate legal research traffic -> ALLOW
            emit(f, "westlaw.com",      "10.20.0.10",   "ALLOW   | Westlaw legal research (partner)")
            time.sleep(1)
            emit(f, "lexisnexis.com",   "10.20.0.11",   "ALLOW   | LexisNexis research (partner)")
            time.sleep(1)
            emit(f, "courts.gov",       "10.20.1.10",   "ALLOW   | Federal court docket (associate)")
            time.sleep(2)

            # 2. Unauthorized cloud upload from paralegal -> MONITOR (feed +40, score=40 > monitor=38 < block=70)
            emit(f, "wetransfer-legal.io", "10.20.2.10", "MONITOR | Unauthorized cloud upload (paralegal, score=40)")
            time.sleep(2)

            # 3. Tor exit node from client meeting room -> BLOCK (feed+YARA=75 > client block=62)
            emit(f, "tor-exit-relay.onion-gw.net", "192.168.200.5", "BLOCK   | Tor exit relay (client room, score=75)")
            time.sleep(2)

            # 4. Ransomware C2 from associate net -> BLOCK (feed+YARA=75 > associate block=72)
            emit(f, "clio-encrypt.c2-server.ru", "10.20.1.20", "BLOCK   | Ransomware C2 beacon (associate, score=75)")
            time.sleep(2)

            # 5. Privilege breach from paralegal -> BLOCK (feed+YARA=75 > paralegal block=70)
            emit(f, "opposing-counsel.harvest.io", "10.20.2.50", "BLOCK   | Privilege violation (paralegal, score=75)")
            time.sleep(2)

            # 6. Ransomware burst attack -> BLOCK cascade
            print(f"\n[LEGAL-INJECTOR] -- Ransomware burst (200 x clio-encrypt.c2-server.ru) --", flush=True)
            for i in range(200):
                f.write(line("clio-encrypt.c2-server.ru", "10.20.1.99"))
                if i % 50 == 0:
                    f.flush()
                    print(f"[LEGAL-INJECTOR]  burst {i+1}/200", flush=True)
            f.flush()
            print(f"[LEGAL-INJECTOR]  burst complete -> BLOCK cascade", flush=True)
            time.sleep(5)

            print(f"[LEGAL-INJECTOR] Loop {loop} complete -- sleeping 10s", flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4.3: Verify the files exist**

```bash
ls docker/demo-injector-legal/
```

Expected: `Dockerfile  inject.py`

- [ ] **Step 4.4: Commit**

```bash
git add docker/demo-injector-legal/
git commit -m "feat(legal): add demo traffic injector with 6 law firm threat scenarios"
```

---

## Task 5: Docker Compose files

**Files:**
- Create: `docker/docker-compose.legal.yml`
- Create: `docker/docker-compose.usb-legal.yml`

- [ ] **Step 5.1: Create the source-build compose**

Create `docker/docker-compose.legal.yml`:

```yaml
name: minifw-legal
# PRODUCT_MODE: minifw_legal — legal / attorney-client privilege / data exfiltration / ransomware
# Start: docker compose -f docker/docker-compose.legal.yml up

volumes:
  minifw_legal_logs:

services:

  # -- Firewall Engine -----------------------------------------------------
  engine:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: minifw_legal_engine
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - minifw_legal_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
      - ../config/feeds:/opt/minifw_ai/config/feeds:ro
      - ../yara_rules:/opt/minifw_ai/yara_rules:ro
    entrypoint: ["/bin/bash", "/opt/minifw_ai/docker/entrypoint-engine.sh"]
    environment:
      PRODUCT_MODE: minifw_legal
      MINIFW_SECTOR: legal
      MINIFW_SECRET_KEY: "demo-legal-key-change-in-prod!!"
      MINIFW_POLICY: /opt/minifw_ai/config/modes/minifw_legal/policy.json
      MINIFW_FEEDS: /opt/minifw_ai/config/feeds
      MINIFW_LOG: /opt/minifw_ai/logs/events.jsonl
      MINIFW_FLOW_RECORDS: /opt/minifw_ai/logs/flow_records.jsonl
      MINIFW_AUDIT_LOG: /opt/minifw_ai/logs/audit.jsonl
      MINIFW_MLP_MODEL: /opt/minifw_ai/models/mlp_model.pkl
      MINIFW_YARA_RULES: /opt/minifw_ai/yara_rules
      MINIFW_DNS_SOURCE: file
      AI_ENABLED: "1"
      MINIFW_DISABLE_FLOWS: "1"
    healthcheck:
      test: ["CMD", "test", "-f", "/opt/minifw_ai/logs/audit.jsonl"]
      interval: 5s
      timeout: 3s
      retries: 20
    restart: unless-stopped

  # -- Web Dashboard -------------------------------------------------------
  web:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: minifw_legal_web
    depends_on:
      engine:
        condition: service_healthy
    volumes:
      - minifw_legal_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
    entrypoint: ["/bin/bash", "/opt/minifw_ai/docker/entrypoint-web.sh"]
    environment:
      PRODUCT_MODE: minifw_legal
      MINIFW_SECRET_KEY: "demo-legal-key-change-in-prod!!"
      MINIFW_ADMIN_PASSWORD: "Legal1!"
      MINIFW_AUDIT_LOG: /opt/minifw_ai/logs/audit.jsonl
      MINIFW_LOG: /opt/minifw_ai/logs/events.jsonl
      MINIFW_SECTOR: legal
      MINIFW_POLICY: /opt/minifw_ai/config/modes/minifw_legal/policy.json
      MINIFW_EXTERNAL_PORT: "8448"
      PYTHONPATH: /opt/minifw_ai/app
      DEMO_MODE: attack_simulation
    ports:
      - "8448:8443"
    restart: unless-stopped

  # -- Demo Traffic Injector -----------------------------------------------
  injector:
    build:
      context: demo-injector-legal/
    container_name: minifw_legal_injector
    depends_on:
      engine:
        condition: service_healthy
    volumes:
      - minifw_legal_logs:/logs
    environment:
      DNS_LOG_PATH: /logs/dnsmasq.log
    restart: unless-stopped
```

- [ ] **Step 5.2: Create the USB compose**

Create `docker/docker-compose.usb-legal.yml`:

```yaml
name: minifw-legal
# USB variant — uses pre-loaded images, no source build required.
# Images must be loaded first: docker load -i images/minifw-legal.tar
# Start via: demo.sh (USB root) — do not run directly.

volumes:
  minifw_legal_logs:

services:

  # -- Firewall Engine -----------------------------------------------------
  engine:
    image: minifw-ai-demo/legal:latest
    container_name: minifw_legal_engine
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - minifw_legal_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
      - ../config/feeds:/opt/minifw_ai/config/feeds:ro
      - ../yara_rules:/opt/minifw_ai/yara_rules:ro
    entrypoint: ["/bin/bash", "/opt/minifw_ai/docker/entrypoint-engine.sh"]
    environment:
      PRODUCT_MODE: minifw_legal
      MINIFW_SECTOR: legal
      MINIFW_SECRET_KEY: "demo-legal-key-change-in-prod!!"
      MINIFW_POLICY: /opt/minifw_ai/config/modes/minifw_legal/policy.json
      MINIFW_FEEDS: /opt/minifw_ai/config/feeds
      MINIFW_LOG: /opt/minifw_ai/logs/events.jsonl
      MINIFW_FLOW_RECORDS: /opt/minifw_ai/logs/flow_records.jsonl
      MINIFW_AUDIT_LOG: /opt/minifw_ai/logs/audit.jsonl
      MINIFW_MLP_MODEL: /opt/minifw_ai/models/mlp_model.pkl
      MINIFW_YARA_RULES: /opt/minifw_ai/yara_rules
      MINIFW_DNS_SOURCE: file
      AI_ENABLED: "1"
      MINIFW_DISABLE_FLOWS: "1"
    healthcheck:
      test: ["CMD", "test", "-f", "/opt/minifw_ai/logs/audit.jsonl"]
      interval: 5s
      timeout: 3s
      retries: 20
    restart: unless-stopped

  # -- Web Dashboard -------------------------------------------------------
  web:
    image: minifw-ai-demo/legal:latest
    container_name: minifw_legal_web
    depends_on:
      engine:
        condition: service_healthy
    volumes:
      - minifw_legal_logs:/opt/minifw_ai/logs
      - ../config/modes:/opt/minifw_ai/config/modes:ro
    entrypoint: ["/bin/bash", "/opt/minifw_ai/docker/entrypoint-web.sh"]
    environment:
      PRODUCT_MODE: minifw_legal
      MINIFW_SECRET_KEY: "demo-legal-key-change-in-prod!!"
      MINIFW_ADMIN_PASSWORD: "Legal1!"
      MINIFW_AUDIT_LOG: /opt/minifw_ai/logs/audit.jsonl
      MINIFW_LOG: /opt/minifw_ai/logs/events.jsonl
      MINIFW_SECTOR: legal
      MINIFW_POLICY: /opt/minifw_ai/config/modes/minifw_legal/policy.json
      MINIFW_EXTERNAL_PORT: "8448"
      PYTHONPATH: /opt/minifw_ai/app
      DEMO_MODE: attack_simulation
    ports:
      - "8448:8443"
    restart: unless-stopped

  # -- Demo Traffic Injector -----------------------------------------------
  injector:
    image: minifw-ai-demo/legal-injector:latest
    container_name: minifw_legal_injector
    depends_on:
      engine:
        condition: service_healthy
    volumes:
      - minifw_legal_logs:/logs
    environment:
      DNS_LOG_PATH: /logs/dnsmasq.log
    restart: unless-stopped
```

- [ ] **Step 5.3: Verify both files exist**

```bash
ls docker/docker-compose.legal.yml docker/docker-compose.usb-legal.yml
```

Expected: both listed.

- [ ] **Step 5.4: Commit**

```bash
git add docker/docker-compose.legal.yml docker/docker-compose.usb-legal.yml
git commit -m "feat(legal): add source and USB Docker Compose files (port 8448)"
```

---

## Task 6: Build script updates

**Files:**
- Modify: `build_usb.sh`
- Modify: `scripts/build_deb.sh`

- [ ] **Step 6.1: Add `legal)` case to `build_usb.sh`**

Open `build_usb.sh`. Find the `gambling)` case block (ends with `;;`). Insert the `legal)` case immediately after it, before the `*)` wildcard:

```bash
  legal)
    SOURCE_COMPOSE="docker/docker-compose.legal.yml"
    USB_COMPOSE="docker/docker-compose.usb-legal.yml"
    INJECTOR_DIR="docker/demo-injector-legal"
    IMAGE_TAG="minifw-ai-demo/legal:latest"
    INJECTOR_TAG="minifw-ai-demo/legal-injector:latest"
    IMAGE_TAR_NAME="minifw-legal.tar"
    CONFIG_MODE="minifw_legal"
    COMPOSE_PROJECT="minifw-legal"
    DASHBOARD_PORT="8448"
    ADMIN_PASS="Legal1!"
    ;;
```

- [ ] **Step 6.2: Update the `build_usb.sh` header comment**

Find the usage comment block at the top of `build_usb.sh` (lines starting with `#   bash build_usb.sh`). Add legal:

```bash
#   bash build_usb.sh legal               # → dist/minifw-usb-legal-v2.2.0/
```

Place it after the `education` line.

- [ ] **Step 6.3: Update `scripts/build_deb.sh` header comment**

Open `scripts/build_deb.sh`. Find the line near the top that says `# Supports 6 deployment sectors:`. Add legal to the example usage comment if it's not there. The wildcard case `*) _PMODE="minifw_${SECTOR}" ;;` already handles legal → minifw_legal automatically, so no case change is needed — only the comment.

- [ ] **Step 6.4: Verify `legal` is in VALID_SECTORS**

```bash
grep VALID_SECTORS scripts/build_deb.sh
```

Expected output contains `legal`. If already present (it is), no change needed.

- [ ] **Step 6.5: Smoke-test build_usb.sh parses the legal case**

```bash
bash -n build_usb.sh
```

Expected: no output (syntax OK).

```bash
bash -n scripts/build_deb.sh
```

Expected: no output.

- [ ] **Step 6.6: Commit**

```bash
git add build_usb.sh scripts/build_deb.sh
git commit -m "feat(legal): add legal sector to build_usb.sh + update build_deb.sh header"
```

---

## Task 7: Documentation

**Files:**
- Create: `docs/legal/demo-guide.md`
- Create: `docs/legal/INSTALL.md`
- Create: `docs/legal/README.md`

- [ ] **Step 7.1: Create `docs/legal/demo-guide.md`**

```bash
mkdir -p docs/legal
```

Create `docs/legal/demo-guide.md`:

```markdown
# MiniFW-AI Legal Sector — Demo Guide

**Audience:** Sales engineers presenting to managing partners, IT directors, and compliance officers at law firms.

**Port:** 8448 · **Password:** `Legal1!` · **Mode:** `minifw_legal`

---

## Quick Start

From the repo root (source build):

    docker compose -f docker/docker-compose.legal.yml up

From USB:

    bash demo.sh

Open `https://localhost:8448` → accept the self-signed certificate → log in with `admin` / `Legal1!`.

---

## What the Demo Shows

The demo runs a continuous loop of law firm network scenarios. Each cycle takes approximately 2 minutes.

### Phase 1 — BASELINE (normal legal research)

Partners and associates browsing Westlaw, LexisNexis, and courts.gov. The dashboard shows green allow events.

**Talking point:** "This is what a normal day at the firm looks like — case research flows freely with no friction."

### Phase 2 — ANOMALY (unauthorised cloud upload)

`wetransfer-legal.io` appears from the paralegal subnet (10.20.2.x). Score reaches 40 → MONITOR.

**Talking point:** "The AI notices a paralegal attempting to upload files to an unauthorised transfer service. It flags it for the administrator — no disruption yet, but a full audit trail is created."

### Phase 3 — ESCALATION (Tor exit relay)

`tor-exit-relay.onion-gw.net` from a client meeting room (192.168.200.x). Feed match + YARA push score to 75 → BLOCK (client block threshold: 62).

**Talking point:** "A device in a client meeting room tried to reach the Tor network. The system blocks it immediately — client meeting rooms have the tightest thresholds because we don't know those devices."

### Phase 4 — BLOCK (Ransomware C2)

`clio-encrypt.c2-server.ru` from the associate subnet — feed + YARA, score 75 → BLOCK (associate threshold: 72).

**Talking point:** "This is a ransomware command-and-control beacon. The pattern matches our YARA rule for case management system targeting. It's blocked before a single file is encrypted."

### Phase 5 — BLOCK (Privilege breach)

`opposing-counsel.harvest.io` from the paralegal subnet — feed + YARA, score 75 → BLOCK (paralegal threshold: 70).

**Talking point:** "This domain is associated with opposing counsel data harvesting. The YARA rule catches it even if the exact domain hasn't been seen before."

### Phase 6 — BURST CASCADE

200 rapid queries to `clio-encrypt.c2-server.ru` from `10.20.1.99`. The dashboard shows the block cascade with Trace ID and Decision Owner.

**Talking point:** "When ransomware starts its beacon loop, the burst pattern is unmistakeable. Blocked in real time, full audit trail for your incident response team."

---

## Key Talking Points by Audience

| Audience | Focus |
|----------|-------|
| Managing Partner | Trace ID + Decision Owner — audit trail for privilege complaints and regulatory enquiries |
| IT Director | Per-segment thresholds — partner net is relaxed; client rooms are tightest |
| Compliance Officer | YARA catches unknown C2 and privilege-breach variants not yet on blocklists |
| Associate | AI Reason field — clear explanation of why each event was blocked or monitored |

---

## Dashboard Sections to Highlight

1. **AI Threat Synthesis panel** — show the BLOCKED event with risk %, action badge, AI Reason, Decision Owner, Trace ID
2. **Events page** — filter by `blocked` to show the audit log
3. **Policy page** — show different thresholds for `partner` vs `paralegal` vs `client` segments

---

## Reset Between Demos

    docker compose -f docker/docker-compose.legal.yml down -v
    docker compose -f docker/docker-compose.legal.yml up

The `-v` flag clears the log volume so the dashboard starts fresh.
```

- [ ] **Step 7.2: Create `docs/legal/INSTALL.md`**

Create `docs/legal/INSTALL.md`:

```markdown
# Installation Guide — MiniFW-AI Legal Sector v2.2.0

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Debian 12 / Ubuntu 22.04+ | amd64 only |
| Python 3.10+ | `python3 --version` |
| python3-venv | `sudo apt install python3-venv` |
| nftables | `sudo apt install nftables` |
| conntrack | `sudo apt install conntrack` |
| openssl | For TLS certificate generation |
| Root / sudo | Required for install and daemon startup |

Optional (for enhanced detection):
- `dnsmasq` — DNS event collection (recommended for all deployments)
- `zeek` — TLS SNI enrichment via ssl.log

---

## Step 1 — Verify the Package

```bash
sha256sum -c minifw-ai_2.2.0-legal_amd64.deb.sha256
# Expected: minifw-ai_2.2.0-legal_amd64.deb: OK
```

---

## Step 2 — Set Environment Variables

```bash
export MINIFW_SECRET_KEY="$(openssl rand -hex 32)"
export MINIFW_ADMIN_PASSWORD="YourSecurePassword1!"
```

The `postinst` script reads these to provision the admin user and bake the secret key.
If not set, installation will abort with an error.

---

## Step 3 — Install

```bash
sudo -E dpkg -i minifw-ai_2.2.0-legal_amd64.deb
```

**What `postinst` does automatically:**
1. Creates `/opt/minifw_ai/` directory tree
2. Creates a Python virtual environment at `/opt/minifw_ai/venv/`
3. Installs Python dependencies into the venv
4. Generates a self-signed TLS certificate (valid 3650 days)
5. Provisions the `admin` user with the password you set
6. Writes `/etc/minifw-ai/minifw-ai.conf` with `MINIFW_SECTOR=legal` and `PRODUCT_MODE=minifw_legal`
7. Enables and starts `minifw-engine.service` and `minifw-web.service`

If any dependency is missing, resolve it with:
```bash
sudo apt-get install -f
sudo -E dpkg -i minifw-ai_2.2.0-legal_amd64.deb
```

---

## Step 4 — Verify Services

```bash
systemctl status minifw-engine
systemctl status minifw-web
```

Both should show `active (running)`.

```bash
journalctl -u minifw-engine -n 50
```

Expected output includes:
```
[minifw] Sector: legal | Mode: BASELINE_PROTECTION
[minifw] Web dashboard: https://0.0.0.0:8443
```

---

## Step 5 — Open the Dashboard

Navigate to `https://<gateway-ip>:8443`.

- Accept the self-signed TLS certificate warning
- Login: `admin` / `<password you set in Step 2>`
- Dashboard header should show **Legal Sector** with the amber-brown accent

---

## Step 6 — Configure DNS Source (Recommended)

Edit `/etc/minifw-ai/minifw-ai.conf`:

```bash
MINIFW_DNS_SOURCE=file
MINIFW_DNS_LOG=/var/log/dnsmasq.log
```

Ensure dnsmasq is logging queries:

```bash
# /etc/dnsmasq.conf
log-queries
log-facility=/var/log/dnsmasq.log
```

```bash
sudo systemctl restart minifw-engine
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/minifw-ai/minifw-ai.conf` | Environment variables for both services |
| `/opt/minifw_ai/config/modes/minifw_legal/policy.json` | Legal policy (per-segment thresholds, score weights) |
| `/opt/minifw_ai/config/feeds/` | Domain/IP/ASN deny and allow feeds |
| `/opt/minifw_ai/yara_rules/legal_rules.yar` | Ransomware C2, data exfiltration, privilege violation, Tor exit rules |

---

## Per-Segment Thresholds

Default thresholds baked into `minifw_legal/policy.json`. Adjust via Dashboard → Policy → Segments.

| Segment | Block | Monitor | Rationale |
|---------|-------|---------|-----------|
| `partner` | 85 | 55 | Senior counsel — most trusted |
| `associate` | 72 | 45 | Standard lawyer threshold |
| `paralegal` | 70 | 38 | Stricter — limited data access |
| `client` | 62 | 30 | Client meeting rooms — tight |
| `guest` | 60 | 28 | Visitor WiFi — tightest |

---

## Troubleshooting

**Services not starting:**
```bash
journalctl -u minifw-engine --no-pager -n 100
```
Common cause: `MINIFW_SECRET_KEY` not set. Add it to `/etc/minifw-ai/minifw-ai.conf` and restart.

**nftables enforcement not working:**
```bash
sudo nft list ruleset
sudo systemctl status nftables
```

**Port 8443 in use:**
```bash
ss -tlnp | grep 8443
sudo systemctl restart minifw-web
```

**No events appearing on dashboard:**
```bash
sudo systemctl status dnsmasq
tail -f /var/log/dnsmasq.log
```

---

## Uninstall

```bash
sudo systemctl stop minifw-engine minifw-web
sudo dpkg -r minifw-ai
```

To purge completely:
```bash
sudo dpkg --purge minifw-ai
sudo rm -rf /opt/minifw_ai /etc/minifw-ai
```
```

- [ ] **Step 7.3: Create `docs/legal/README.md`**

Create `docs/legal/README.md`:

```markdown
# MiniFW-AI Legal Sector — Tutorial

This tutorial walks through both **demo mode** (Docker, for presentations) and **production mode** (installed on a real Linux gateway).

---

## Part 1: Demo Mode (Docker)

### 1.1 Prerequisites

- Docker Engine 24+ and Docker Compose v2
- 4 GB free disk space (image is ~910 MB)
- Port 8448 available on your machine

### 1.2 Start the Demo

    cd /path/to/minifw-ai
    docker compose -f docker/docker-compose.legal.yml up

Wait ~20 seconds for the engine healthcheck to pass, then open `https://localhost:8448`. Accept the self-signed TLS certificate and log in:

- **Username:** `admin`
- **Password:** `Legal1!`

### 1.3 Understanding the Dashboard

**Top bar:** Shows the current sector (`Legal — Attorney-Client Privilege · Data Exfiltration · Ransomware`) and protection state.

**AI Threat Synthesis panel:**
- **THREAT BLOCKED** — headline for the most recent block event
- **Risk %** — colour-coded score badge (red ≥85%, amber ≥65%)
- **BLOCKED** pill — confirms enforcement action
- **AI REASON** — what detection method triggered (YARA, DNS feed, MLP)
- **DECISION OWNER** — which layer made the call (Hard Gate, AI Engine, Policy Engine)
- **TRACE ID** — 8-character ID for the audit trail

**Events page:** Full log of all allow/monitor/block decisions.

**Policy page:** Edit segment thresholds live (changes take effect within 5 seconds).

### 1.4 Watch the Demo Cycle

The injector sends threats in this order every ~2 minutes:

| Time | Event | Expected outcome |
|------|-------|-----------------|
| 0-8s | westlaw.com, lexisnexis.com, courts.gov | ALLOW |
| 10s | wetransfer-legal.io from 10.20.2.10 | MONITOR (score 40) |
| 12s | tor-exit-relay.onion-gw.net from 192.168.200.5 | BLOCK (feed+YARA, score 75) |
| 14s | clio-encrypt.c2-server.ru from 10.20.1.20 | BLOCK (YARA ransomware, score 75) |
| 16s | opposing-counsel.harvest.io from 10.20.2.50 | BLOCK (YARA privilege, score 75) |
| 20s+ | 200× clio-encrypt.c2-server.ru burst | BLOCK CASCADE |

### 1.5 Modify Policy Live

1. Go to **Policy → Segments**
2. Lower the `paralegal` block threshold from 70 to 40
3. Reload the Events page — the next `wetransfer-legal.io` event will change from MONITOR to BLOCK

### 1.6 Stop and Reset

    docker compose -f docker/docker-compose.legal.yml down -v

---

## Part 2: Production Mode (.deb on Linux Gateway)

### 2.1 Prerequisites

- Ubuntu 22.04 LTS or Debian 12 (amd64)
- Root access
- nftables: `sudo apt install nftables`
- dnsmasq configured for log output (see INSTALL.md)

### 2.2 Install the Package

    sudo apt install ./minifw-ai_2.2.0-legal_amd64.deb

### 2.3 Configure Secrets

    sudo mkdir -p /etc/minifw-ai
    sudo tee /etc/minifw-ai/minifw-ai.conf <<EOF
    MINIFW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    MINIFW_ADMIN_PASSWORD=YourSecurePassword1!
    MINIFW_DNS_LOG=/var/log/dnsmasq.log
    MINIFW_DNS_SOURCE=file
    EOF
    sudo chmod 600 /etc/minifw-ai/minifw-ai.conf

### 2.4 Start Services

    sudo systemctl enable --now minifw-engine.service
    sudo systemctl enable --now minifw-web.service

### 2.5 Verify Operation

    sudo journalctl -u minifw-engine -f
    sudo journalctl -u minifw-web -f
    sudo tail -f /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool

### 2.6 Add Custom Deny Domains

Edit `/opt/minifw_ai/config/feeds/deny_domains.txt`:

    # Firm-specific additions
    *.dropbox.com
    *.googledrive.com
    pastebin.com

To force an immediate reload:

    sudo systemctl restart minifw-engine

### 2.7 Tune Per-Segment Thresholds

Log in to `https://<gateway-ip>:8443` → **Policy → Segments**.

Recommended starting values:

| Segment | Block | Monitor | Rationale |
|---------|-------|---------|-----------|
| partner | 85 | 55 | Senior counsel — relaxed |
| associate | 72 | 45 | Standard lawyer threshold |
| paralegal | 70 | 38 | Stricter — limited access |
| client | 62 | 30 | Client rooms — tight |
| guest | 60 | 28 | Visitor WiFi — tightest |

### 2.8 Export Audit Reports

**Dashboard → Reports → Export Events** — download CSV or PDF of all block events for compliance records, regulatory submissions, and incident response documentation.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No events appearing | dnsmasq not logging | Check `log-queries` in `/etc/dnsmasq.conf` |
| Dashboard unreachable | Service not started | `sudo systemctl start minifw-web.service` |
| All traffic blocked | Block threshold too low | Raise threshold in Policy → Segments |
| YARA not matching | Rules path wrong | Check `MINIFW_YARA_RULES` env var |
| Secret key error | Env var missing | Ensure `MINIFW_SECRET_KEY` is set in `/etc/minifw-ai/minifw-ai.conf` |
| Wrong sector shown | PRODUCT_MODE mismatch | Verify `PRODUCT_MODE=minifw_legal` in conf file |
```

- [ ] **Step 7.4: Verify all three docs exist**

```bash
ls docs/legal/
```

Expected: `demo-guide.md  INSTALL.md  README.md`

- [ ] **Step 7.5: Commit**

```bash
git add docs/legal/
git commit -m "docs(legal): add demo guide, INSTALL.md, and tutorial README"
```

---

## Final Verification

- [ ] **Run the full test suite one last time**

```bash
cd /home/sydeco/minifw-ai
source .venv/bin/activate
pytest testing/ -m "not integration" -q
```

Expected: 246+ passed (new legal tests added), 0 failed.

- [ ] **Verify legal sector resolves correctly**

```bash
PRODUCT_MODE=minifw_legal python3 -c "
from app.minifw_ai.mode_context import get_mode_ui
ui = get_mode_ui()
print(f'label={ui.label} sector={ui.sector} color={ui.color}')
"
```

Expected: `label=Legal sector=legal color=#b45309`

- [ ] **Verify YARA file compiles standalone**

```bash
python3 -c "
import yara
with open('yara_rules/legal_rules.yar') as f:
    src = f.read()
rules = yara.compile(sources={'legal': src})
m = rules.match(data=b'clio-encrypt.c2-server.ru')
print([x.rule for x in m])
"
```

Expected: `['LegalRansomwareC2']`

- [ ] **Verify build_usb.sh syntax**

```bash
bash -n build_usb.sh && echo "OK"
```

Expected: `OK`
