# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## What This Codebase Is

**MiniFW-AI (ARCHANGEL 2.0)** is a gateway-based AI security platform that enforces network policy via DNS/flow metadata inspection, ML threat scoring, and kernel-level nftables blocking — without TLS MITM or browser proxies.

This directory (`(BASE)minifw-ai/minifw-ai/`) is the **single canonical source of truth** for all sector deployments. All six sector packages (hospital, education, government, finance, legal, establishment) are built from this directory using `build_deb.sh`. Do not develop in the legacy variants.

---

## Commands

### Web dashboard (dev, no root)
```bash
export MINIFW_SECRET_KEY="dev-key"
export PYTHONPATH=$(pwd)
uvicorn app.web.app:app --reload --host 0.0.0.0 --port 8000
```

### Firewall engine (root + gateway required)
```bash
export MINIFW_SECRET_KEY="dev-key"
export PYTHONPATH=$(pwd)
export MINIFW_SECTOR=hospital   # hospital|education|government|finance|legal|establishment
sudo -E python3 -m app.minifw_ai.main
```

### Tests (no root)
```bash
PYTHONPATH=app pytest testing/                                    # full suite
PYTHONPATH=app pytest testing/test_sector_lock.py -v             # sector lock tests
PYTHONPATH=app pytest testing/test_sector_rules.py -v            # sector rules pipeline tests
python3 testing/test_standalone_integration.py 500               # simulated flows
python3 testing/test_flow_collector_simulated.py 100             # flow collection
```

### Tests (root required)
```bash
sudo python3 testing/test_flow_collector.py 60      # real traffic, 60s
sudo python3 testing/test_real_traffic.py 5         # full integration, 5 min
```

### Build a sector .deb
```bash
# Run from this directory
bash build_deb.sh hospital        # → dist/minifw-ai-hospital_1.0.0.deb
bash build_deb.sh education       # → dist/minifw-ai-education_1.0.0.deb
bash build_deb.sh government      # → dist/minifw-ai-government_1.0.0.deb
bash build_deb.sh finance         # → dist/minifw-ai-finance_1.0.0.deb
bash build_deb.sh legal           # → dist/minifw-ai-legal_1.0.0.deb
bash build_deb.sh establishment   # → dist/minifw-ai-establishment_1.0.0.deb

# Install on target device
sudo dpkg -i dist/minifw-ai-<sector>_1.0.0.deb
sudo apt-get install -f    # resolve any missing deps
```

### Train MLP model
```bash
python3 testing/test_standalone_integration.py 1000   # generate labeled data
python3 scripts/train_mlp.py \
  --data ./data/testing_output/flow_records_labeled.csv \
  --output models/mlp_engine.pkl
```

### Database / admin setup
```bash
python3 scripts/create_admin.py          # create initial admin user
python3 scripts/migrate_database.py     # run DB migrations
python3 scripts/check_database.py       # inspect DB state
```

### Production service management
```bash
sudo systemctl status minifw-ai-<sector>
sudo systemctl restart minifw-ai-<sector>
tail -f /opt/minifw_ai_<sector>/logs/events.jsonl
```

---

## Architecture

Two independently runnable subsystems share config and models from the same install.

### 1. Firewall Engine (`app/minifw_ai/`)

Event loop in `main.py`. The full decision pipeline per DNS event:

```
dnsmasq log / Zeek SNI
        ↓
  segment lookup          (maps client IP → segment via policy.json CIDR ranges)
        ↓
  hard threat gates       (PPS saturation, burst flood, bot patterns → immediate block=100)
        ↓
  FeedMatcher             (blocklist/allowlist feeds from config/feeds/*.txt)
        ↓
  BurstTracker            (sliding-window DNS query rate per client IP)
        ↓
  FlowTracker → MLP       (24-feature vector → scikit-learn MLP threat score 0–100)
        ↓
  YARA scanner            (293 rules across 11 categories in yara_rules/)
        ↓
  sector_rules pipeline   (base.evaluate → base.supply_chain_guard → sector_mod.evaluate)
        ↓
  score_and_decide()      (weighted sum → block/monitor/allow vs thresholds)
        ↓
  ipset / nftables        (enforcement)
        ↓
  post_decision hook      (sector side-effects, e.g. hospital IoMT CRITICAL alerts)
```

Key modules:
- `policy.py` — loads `config/policy.json`; segment thresholds, weights, enforcement config
- `feeds.py` — FeedMatcher; allowlist/blocklist from `config/feeds/*.txt`
- `enforce.py` — thin wrappers around `ipset` and `nftables` system calls
- `burst.py` — sliding-window DNS query rate tracker per client IP
- `collector_flow.py` — FlowTracker; builds 24-feature vectors from 5-tuple flows
- `utils/mlp_engine.py` — loads serialized scikit-learn MLPClassifier (`models/mlp_engine.pkl`)
- `utils/yara_scanner.py` — scans domain/SNI payloads against `yara_rules/` subdirectory tree
- `sector_lock.py` — immutable singleton; reads `config/sector_lock.json` or `MINIFW_SECTOR` env. **Fails closed** if neither is set.
- `sector_config.py` — per-sector threshold adjustments, extra feeds, policy flags
- `sector_rules/` — per-sector security rule modules (see below)

### 2. Web Dashboard (`app/web/`)

FastAPI app (`app/web/app.py`). Routers → Controllers → Services → Models:
- `app/web/routers/` — auth, admin, health, status
- `app/controllers/` — request handling logic
- `app/services/` — auth, policy CRUD, user management, RBAC, events
- `app/models/` — SQLAlchemy ORM; DB is SQLite at `minifw.db`
- `app/middleware/auth_middleware.py` — JWT cookie auth; all `/admin` routes require it

Auth: cookie `access_token` → `verify_token()` (JWT HS256) → user lookup → `is_active` check.
`MINIFW_SECRET_KEY` is **required at import time** — app crashes without it.

---

## Sector Rules Pipeline

`app/minifw_ai/sector_rules/` contains security rule modules that run after YARA and before `score_and_decide()`. The pipeline takes the **most severe result** across all three stages:

```python
_sev = {"block": 2, "monitor": 1, "allow": 0}
# Run: base.evaluate → base.supply_chain_guard → sector_mod.evaluate
# Keep whichever returns highest severity
```

A sector "block" sets `hard_threat = True`, forcing `score_and_decide()` to return 100/block regardless of ML scores.

### Module summary

| Module | Sector | Key rules |
|---|---|---|
| `base.py` | ALL | DDoS per-dest (>100 q/60s), DGA entropy (label ≥12 chars, >3.5 → monitor), cloud sync → monitor, chat apps → monitor, sensitive payment API no-TLS → block, VPN direct-to-IP no-SNI → monitor |
| `hospital.py` | hospital | `evaluate()` always allows; `post_decision()` fires `CRITICAL` IoMT alert when medical device anomaly detected |
| `education.py` | education | VPN/proxy → block, AI tools during class hours → block, piracy patterns → block, entertainment BW cap (>500 MB) → block, cloud sync → monitor, stricter DDoS during class hours (>50 q/60s) |
| `establishment.py` | establishment | Cowrie honeypot contact → monitor+CRITICAL log, VPN from trusted_segments → allow, VPN from untrusted → monitor |
| `government.py` | government | ccTLD geo-IP (.ru/.cn/.ir/.kp) → block (geo_ip_strict) or monitor, APT deep-subdomain C2 (>4 labels) → monitor, audit-all-queries logging |
| `finance.py` | finance | Tor .onion → block, anonymizer keywords → block, crypto phishing patterns → block, finance API no-TLS (Visa/Binance/Plaid etc.) → block |
| `legal.py` | legal | DNS exfil long label (>50 chars) → monitor, DNS exfil deep chain (>6 labels) → monitor, paste/leak sites → block, file sharing → monitor |

**VPN policy is sector-specific — not in base.py:**
- education: always block
- establishment: allow from `trusted_segments`, monitor otherwise
- hospital, government, finance, legal: no VPN restriction at DNS level

### Adding a new sector rule
1. Create `app/minifw_ai/sector_rules/<sector>.py` with `evaluate(metadata) -> Tuple[str, str]`
2. Register it in `app/minifw_ai/sector_rules/__init__.py` `get_sector_module()`
3. Add sector config flags to `app/minifw_ai/sector_config.py` `SECTOR_POLICIES`
4. Add test cases to `testing/test_sector_rules.py`

`metadata` dict keys guaranteed present: `domain`, `sni`, `client_ip`, `segment`, `sector`, `sector_config`. Optional: `is_tls`, `bandwidth_usage_mb`.

---

## Sector Lock & Deployment

`config/sector_lock.json` bakes the sector identity into each device at deploy time:

```json
{ "sector": "hospital", "locked": true, "lock_reason": "Factory-set deployment configuration" }
```

The `SectorLock` singleton reads this once at startup and refuses to change at runtime. Valid sectors: `hospital | education | government | finance | legal | establishment`.

For development: `export MINIFW_SECTOR=education` (env var takes priority over the lock file).

`build_deb.sh <sector>` stamps the correct sector into the package at build time. The `postinst` script regenerates `sector_lock.json` with a unique device serial on first install.

**Install paths per sector:**

| Sector | Install root | Systemd service | Env file |
|---|---|---|---|
| hospital | `/opt/minifw_ai_hospital` | `minifw-ai-hospital` | `/etc/minifw_ai_hospital/minifw.env` |
| education | `/opt/minifw_ai_education` | `minifw-ai-education` | `/etc/minifw_ai_education/minifw.env` |
| government | `/opt/minifw_ai_government` | `minifw-ai-government` | `/etc/minifw_ai_government/minifw.env` |
| finance | `/opt/minifw_ai_finance` | `minifw-ai-finance` | `/etc/minifw_ai_finance/minifw.env` |
| legal | `/opt/minifw_ai_legal` | `minifw-ai-legal` | `/etc/minifw_ai_legal/minifw.env` |
| establishment | `/opt/minifw_ai_establishment` | `minifw-ai-establishment` | `/etc/minifw_ai_establishment/minifw.env` |

---

## YARA Rules

`yara_rules/` contains 293 `.yara` files across 11 threat categories:

```
backdoor/ certificate/ costumRules/ downloader/ exploit/
general/  infostealer/ pua/         ransomware/ trojan/ virus/
```

`utils/yara_scanner.py` loads the full tree using `yara.compile(sources=dict)` where all files in each subdirectory are concatenated under a namespace matching the directory name. **Do not use `yara.compile(filepaths=dict)`** — it silently drops all but the last file per namespace.

---

## Key Environment Variables

| Variable | Purpose |
|---|---|
| `MINIFW_SECRET_KEY` | JWT signing key — **required at import time** |
| `MINIFW_SECTOR` | Override sector lock (dev/containers) |
| `MINIFW_POLICY` | Path to `policy.json` (default: `<install_root>/config/policy.json`) |
| `MINIFW_FEEDS` | Path to feeds dir (default: `<install_root>/config/feeds`) |
| `MINIFW_LOG` | Path to `events.jsonl` (default: `<install_root>/logs/events.jsonl`) |
| `MINIFW_FLOW_RECORDS` | Path to `flow_records.jsonl` |
| `MINIFW_MLP_MODEL` | Path to trained `.pkl` model file |
| `MINIFW_MLP_THRESHOLD` | MLP threat probability threshold (default: `0.5`) |
| `MINIFW_YARA_RULES` | Path to YARA rules directory |

---

## Architecture Decisions & Constraints

### Why this directory is the source of truth
The repo contains four variants. Education and Establishment are legacy Django platforms from a previous developer. Their enforcement was silently broken (`CapabilityBoundingSet=~all` stripped `CAP_NET_ADMIN`, making all iptables calls fail silently). BASE is the only variant with working enforcement (nftables + ipset). All future development happens here.

### What was extracted from legacy
- **293 YARA rules** from `minifw-ai_education/.../yaraagent/yara/` — copied into `yara_rules/` subdirs
- **`engine.py evaluate_general()` + `supply_chain_guard()`** → ported to `sector_rules/base.py`
- **`engine.py evaluate_education()`** → ported to `sector_rules/education.py`
- Establishment `engine.py` was a 1-line placeholder — `establishment.py` was built fresh

### What to ignore in legacy variants
- Django/Flask enforcement — broken by design
- Agent4 (TensorFlow, raw socket TCP RST injection) — requires `CAP_NET_RAW`, broken
- Agent2 iptables calls — silently fail
- Hardcoded MAC address in education `engine.py` lines 15–18 — development artifact

### Do not touch
- `sector_lock.py` singleton pattern — immutable by design, correct as-is
- `score_and_decide()` in `main.py` — weighted scoring is calibrated; adjust weights in `policy.json` not in code
- Hard threat gates in `main.py` — PPS/burst/bot bypass logic is intentional

### SectorType enum convention
`SectorType.SCHOOL = "education"` — the enum **key** is `SCHOOL` (kept for internal references), but the runtime **value** is `"education"`. Always use the value string for sector identification at runtime.

### PYTHONPATH
Imports in `app/minifw_ai/` use `from minifw_ai.X import ...` (bare, not `from app.minifw_ai.X`). Set `PYTHONPATH=app` when running tests or the engine directly.

---

## HTTP-Layer Stubs

Several rules are documented as stubs pending an HTTP inspection collector. They are marked with `[ ]` in each module. They activate automatically when the collector provides these metadata keys: `content_length`, `user_agent`, `url_path`, `http_method`.

Affected modules: `base.py`, `legal.py`, `establishment.py` (supply_chain_guard).

---

## Conventions

- Event logs: JSONL at `logs/events.jsonl` (one JSON object per line)
- Flow records: `logs/flow_records.jsonl`, exported every 100 DNS events
- Config overrides: env vars always take precedence over file paths
- MLP and YARA are optional — engine degrades gracefully if absent
- `sqlalchemy` must be installed to run `test_sector_lock.py` (it imports `app.models.user`)
- Development reports: `docs/report-YYYY-MM-DD.md`
