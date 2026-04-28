# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

MiniFW-AI is an AI-powered behavioral firewall engine for Linux gateway hardware. It detects threats via DNS event analysis, MLP inference, YARA scanning, and hard rule gates, then enforces via nftables/ipset. It is deployed in six vertically-locked sectors: `hospital | education | government | finance | legal | establishment`.

Two independently running processes:
1. **Firewall Engine Daemon** — `app/minifw_ai/` — the detection/enforcement loop
2. **Web Admin Panel** — `app/web/` — FastAPI dashboard for policy management

## Environment Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set MINIFW_SECRET_KEY and MINIFW_ADMIN_PASSWORD
```

`MINIFW_SECRET_KEY` is required at import time — the app crashes without it.

## Running

```bash
# Firewall daemon (requires root for nftables enforcement)
MINIFW_SECTOR=establishment python -m app.minifw_ai

# Web admin panel
uvicorn app.web.app:app --host 127.0.0.1 --port 8443 --reload

# Standalone Demo (Hospital v3 Framework - Preferred)
cd dist/minifw-ai-usb-v2.2.0v3 && bash run_demo.sh

# Docker demo (Legacy)
docker compose -f docker/docker-compose.yml up
```

## Tests

```bash
# All unit tests (no root needed)
pytest testing/

# Single file
pytest testing/test_baseline_hard_gates.py

# Skip integration tests (those needing root/real network)
pytest testing/ -m "not integration"
```

Tests live in `testing/` (not `tests/`). `conftest.py` adds `sys.path.insert` for `app/` and provides the `synthetic_mlp_model_path` session fixture that trains a minimal in-memory MLP — no external model file needed.

Current test suite: 246 passed, 1 skipped, 0 failed.

## Build & Package

```bash
# Build .deb for a sector
bash build_deb.sh establishment
bash build_deb.sh hospital

# Build USB demo kit
bash build_usb.sh
```

## Architecture

### Scoring Pipeline (engine daemon)

`main.py::run()` processes DNS events as the primary trigger. 

**DEMO_MODE Simulator:** When `DEMO_MODE=1` is set, the engine bypasses real network interception and instead cycles through synthetic traffic patterns defined in `demo_data/normal_traffic.json` and `demo_data/attack_traffic.json`. Used for executive demonstrations.

```
DNS event → pump_zeek() + pump_flows()
          → StateManager.check_and_transition()      # auto-switch AI on/off
          → FeedMatcher [deny_domains/ips/asn]
          → BurstTracker [qpm tracking]
          → evaluate_hard_threat() [PPS/burst/bot gates]  # overrides score to 100
          → MLPThreatDetector.is_suspicious()         # optional, needs model file
          → YARAScanner.scan_payload()                # optional, needs rules dir
          → score_and_decide() → allow / monitor / block
          → ipset_add()                               # nftables enforcement on block
          → EventWriter.write() [JSONL log]
```

Score weights (configurable in `policy.json`): DNS feed match +40, TLS SNI +35, ASN deny +15, DNS burst +10, MLP 0–30, YARA 0–35. Decision thresholds are per-segment, per-policy.

**Protection states** (`state_manager.py`): `BASELINE_PROTECTION` (hard gates only) auto-transitions to `AI_ENHANCED_PROTECTION` (adds MLP + YARA) based on DNS telemetry health. State persists to `/opt/minifw_ai/logs/deployment_state.json`.

**DNS backends** (set via `MINIFW_DNS_SOURCE`): `file` (dnsmasq log), `journald`, `udp`, `none` (degraded/flow-only). Any backend failure falls back gracefully to an empty iterator.

### Sector System (Core + Sector Overlay)

The project follows a **Core + Sector Overlay** model. The Common Core (traffic collection, AI scoring, dashboard skeleton) is frozen and sector-neutral. New verticals are implemented as overlays using the **4-Layer Adaptation** framework:

1.  **Detection Priorities:** Specific threat landscapes (e.g., IoMT for Hospital, SafeSearch for Schools).
2.  **Enforcement Logic:** Sector-specific thresholds for Block/Monitor/Alert via `policy.json`.
3.  **Dashboard Narrative:** Domain-specific terminology and widgets (e.g., HIPAA vs. PCI-DSS vs. Sovereignty).
4.  **Evidence Packs:** Sector-specific YARA rules, threat feeds, and logs.

**`PRODUCT_MODE`** is the canonical selector (e.g. `minifw_hospital`). `MINIFW_SECTOR` is a backward-compatible fallback; `sector_lock.json` is used on production hardware. Resolution priority: `PRODUCT_MODE` → `MINIFW_SECTOR` → `sector_lock.json`.

Valid `PRODUCT_MODE` values: `minifw_hospital`, `minifw_school`, `minifw_financial`, `minifw_establishment`, `minifw_gambling`.

Per-sector configs live in `config/modes/minifw_<sector>/policy.json`.

### Web Admin (`app/web/`)

FastAPI app at `app/web/app.py`. AdminLTE 3 UI (static assets in `app/web/static/adminLTE/`), Jinja2 templates. SQLite at `minifw.db`. Auth: JWT (`python-jose`) + TOTP (`pyotp`) + bcrypt. RBAC via `services/rbac_service.py`.

**AI Threat Synthesis Panel:** A high-impact dashboard component that consolidates detection data, kernel enforcement status, and AI reasoning into a single real-time view.

**Automated Provisioning:** `init_db()` in `app/database.py` automatically creates a default `admin` user if the database is fresh, using credentials from environment variables.

## Critical Constraints

- **`MINIFW_SECRET_KEY`** — must be set before import; app fails without it
- **Sector lock is immutable** — set at startup, cannot change at runtime; use `MINIFW_SECTOR` env var in dev
- **`numpy` pinned to `1.26.4`** — legacy CPU compatibility (no AVX/SSE4); do not upgrade
- **YARA compilation** — use `yara.compile(sources=dict)`, NOT `filepaths=dict`; `filepaths` silently drops files
- **Enforcement requires root** — `enforce.py` calls `nft` via subprocess; daemon exits gracefully if nftables setup fails
- **`/proc/net/nf_conntrack` absent on kernel 6.8+** — `collector_flow.py` auto-detects and falls back to `conntrack -L` CLI

## Project Stage

Currently at **Stage 8 (Distribution/Release)** of an 11-stage lifecycle. `v2.0.0` is tagged and GPG-signed (key `BDB471E1FB46F58A`). See `DEVELOPER.md` for the full stage definitions and current gate status.
