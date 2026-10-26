# DEVELOPER.md

Developer guidance for working with the MiniFW-AI codebase.

## Product Overview

MiniFW-AI is an AI Behavioral Firewall Engine deployed on Linux gateway hardware. It is a **standalone copy** of the engine originally at `ritapi-v-sentinel/projects/minifw_ai_service/`. It is deployed in vertically-locked sectors (hospital, school, government, finance, legal, establishment) and enforces network policy via nftables.

The product has **two independently running processes**:
1. **Firewall Engine Daemon** — `python -m minifw_ai` (run from `app/` with PYTHONPATH, or via `python -m app.minifw_ai` from project root)
2. **Web Admin Panel** — FastAPI app served via uvicorn

## Commands

### Environment Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit as needed
export $(cat .env | xargs)
```

### Run Daemon
```bash
# From project root
MINIFW_SECTOR=establishment python -m app.minifw_ai
```

### Run Web Admin
```bash
uvicorn app.web.app:app --host 127.0.0.1 --port 8443 --reload
```

### Run Tests
```bash
# All tests
pytest testing/

# Single test file
pytest testing/test_baseline_hard_gates.py

# Skip integration tests (those requiring root/network)
pytest testing/ -m "not integration"
```

### Generate Training Data and Train MLP
```bash
# Generate labeled flow data (no root required)
python3 testing/test_standalone_integration.py 1000

# Train MLP model
python3 scripts/train_mlp.py --data ./data/testing_output/flow_records_labeled.csv
```

### Database / Admin Scripts
```bash
python3 scripts/create_admin.py
python3 scripts/create_default_users.py
python3 scripts/check_database.py
python3 scripts/migrate_database.py
```

## Critical Constraints

### Enforcement Requires Root
`app/minifw_ai/enforce.py` calls `nft` (nftables) via subprocess. The daemon must run as root or with `CAP_NET_ADMIN`. The daemon will `return` (graceful exit) if nftables setup fails.

### Sector Lock is a Singleton
`app/minifw_ai/sector_lock.py` — `SectorLock` is a module-level singleton. The sector is loaded once at startup from `MINIFW_SECTOR` env var (dev) or `/opt/minifw_ai/config/sector_lock.json` (production). It **cannot be changed** at runtime — this is intentional security design. If sector is invalid or missing, the daemon refuses to start.

### numpy Pinned to < 2.0
`requirements.txt` pins `numpy==1.26.4` for legacy CPU compatibility (No-AVX/SSE4). Do not upgrade numpy.

## Architecture

### Engine Daemon (`app/minifw_ai/`)

The main event loop in `main.py::run()` processes DNS events as the primary trigger:

```
DNS event → pump_zeek() + pump_flows()
          → StateManager.check_and_transition() [auto-switch AI on/off]
          → segment_for_ip() → Policy.thresholds()
          → FeedMatcher [deny_domains, deny_ips, deny_asn]
          → BurstTracker [qpm tracking]
          → evaluate_hard_threat() [PPS/burst/bot gates]
          → MLPThreatDetector.is_suspicious() [optional, requires model file]
          → YARAScanner.scan_payload() [optional, requires rules dir]
          → score_and_decide() → action: allow/monitor/block
          → ipset_add() [nftables enforcement on block]
          → EventWriter.write() [JSONL log]
          → flow_records export every 100 events [ML retraining data]
```

**Protection States** (`state_manager.py`):
- `BASELINE_PROTECTION` — hard gates only, MLP/YARA disabled
- `AI_ENHANCED_PROTECTION` — hard gates + MLP + YARA

Auto-transitions based on DNS telemetry health (consecutive healthy/unhealthy checks). State persisted to `/opt/minifw_ai/logs/deployment_state.json`.

**DNS Backends** (pluggable via `MINIFW_DNS_SOURCE` env var):
- `file` — tail dnsmasq log file (default)
- `journald` — stream from systemd-resolved via `journalctl -f`
- `udp` — listen on UDP socket (port via `MINIFW_DNS_UDP_PORT`)
- `none` — degraded mode (flow-only, no DNS scoring)

Any backend failure gracefully falls back to an empty iterator, keeping the service alive in baseline protection mode.

**Scoring** (`score_and_decide()` in `main.py`):
- DNS feed match: +40 (configurable via `dns_weight`)
- TLS SNI match: +35 (`sni_weight`)
- ASN deny: +15 (`asn_weight`) — resolved against `asn_prefixes.txt` (141 CIDR entries)
- DNS burst: +10 (`burst_weight`)
- MLP score: 0–30 weighted contribution (`mlp_weight`)
- YARA score: 0–35 weighted contribution (`yara_weight`)
- Hard threat gate: score overridden to 100

Decision thresholds (from `policy.json`, per segment): `< monitor_threshold` → allow, `>= monitor_threshold` → monitor, `>= block_threshold` → block.

### Web Admin (`app/web/`)

FastAPI app at `app/web/app.py`. AdminLTE 3 UI served from `app/web/static/adminLTE/`. Jinja2 templates. SQLite database (`minifw.db` at project root) via SQLAlchemy.

Auth stack: JWT tokens (`python-jose`) + TOTP (`pyotp`) + bcrypt passwords. `auth_middleware.py` protects all `/admin/` routes. RBAC via `services/rbac_service.py`.

Router → Controller → Service pattern:
- `app/web/routers/` — FastAPI route definitions
- `app/controllers/admin/` — request handling
- `app/services/` — business logic (one file per operation: add/get/update/delete)
- `app/models/` — SQLAlchemy models

The web admin manages policy lists (deny_domain, deny_ip, deny_asn, allow_domain) and user accounts. It does **not** directly control the daemon — the daemon reads policy files from disk.

### Key Configuration Files (runtime, not in repo)
- `policy.json` — segments, thresholds, weights, enforcement config, burst config, collectors config
- `feeds/deny_domains.txt`, `feeds/allow_domains.txt`, `feeds/deny_ips.txt`, `feeds/deny_asn.txt`
- `models/mlp_model.pkl` — trained MLP model (required for AI mode)
- `yara_rules/` — directory of `.yar` files (required for YARA scanning)

All paths are configurable via env vars; see `.env.example` for the full list.

### Known Limitations
- `collector_flow.py::stream_conntrack_flows()` — reads `/proc/net/nf_conntrack` which is absent on kernel 6.8+ (Ubuntu 24.04, `CONFIG_NF_CONNTRACK_PROCFS=not set`). Falls back to the `conntrack -L` CLI (see Version History, 2.0.0) — hard threat gates remain functional but at slightly higher latency on this kernel.
- `audit_daemon_stop()` is only called on `KeyboardInterrupt`, not `SIGTERM`. Stop event is not written to audit log on `systemctl stop`.

## Testing Conventions

Tests live in `testing/` (not `tests/`). The `conftest.py` registers the `integration` marker and provides shared fixtures (synthetic MLP model, etc.).

Integration tests requiring root or real network access are marked `@pytest.mark.integration`. Unit tests in `testing/test_*.py` can be run without root or special infrastructure.

Simulation scripts for generating training data without root:
- `testing/test_standalone_integration.py` — full pipeline with synthetic flows
- `testing/test_flow_collector_simulated.py` — flow generation only
- `scripts/simulate_attack.py` / `scripts/real_traffic_simulator.py` — pattern generators

---

## Development Stage Guidelines

This project follows an 11-stage development lifecycle. The end goal is **installable software deployed on a client's host machine** (Linux gateway hardware). Every feature, module, and release must progress through these stages sequentially — no stage may be skipped.

### Stage 0 — Concept / Requirements

**Goal**: Define what the product does and why it exists.

**Gate criteria**:
- [ ] Product Requirements Document (PRD) written and approved
- [ ] Target deployment environment defined (OS, hardware, network topology)
- [ ] Sector list finalised (hospital, education, government, finance, legal, establishment)
- [ ] Threat model documented (what attacks are in scope, what is out of scope)
- [ ] Regulatory constraints identified per sector (HIPAA, PCI-DSS, etc.)
- [ ] Success metrics defined (detection rate, false positive rate, latency budget)

**Artifacts**: PRD, threat model, sector requirements matrix.

### Stage 1 — Design

**Goal**: Translate requirements into architecture and interfaces.

**Gate criteria**:
- [ ] System architecture documented (daemon + web admin two-process model)
- [ ] Data flow diagram: DNS event → scoring pipeline → enforcement → logging
- [ ] Module boundaries defined (collector, flow tracker, scorer, enforcer, writer)
- [ ] Configuration schema designed (`policy.json`, env vars, sector lock)
- [ ] Security design reviewed (SectorLock singleton, fail-closed behaviour, nftables isolation)
- [ ] API contracts for web admin defined (routes, auth, RBAC)
- [ ] Decision on ML model architecture (MLP) and feature vector (24 features)

**Artifacts**: Architecture document, API specification, data flow diagrams, `policy.json` schema.

### Stage 2 — Development (Local)

**Goal**: Implement all modules with code that runs locally on a developer machine.

**Gate criteria**:
- [ ] All PRD features have implementation code (not stubs or pseudocode)
- [ ] DNS backends implemented (file, journald, udp, none)
- [ ] Flow collector with 24-feature vector extraction
- [ ] Hard threat gates (PPS saturation, burst flood, bot detection)
- [ ] Baseline scoring engine (`score_and_decide()`) with all signal sources wired
- [ ] MLP inference engine with model loading and graceful fallback
- [ ] YARA scanner with rule compilation and payload matching
- [ ] Enforcement module (`enforce.py`) with nftables/ipset integration
- [ ] State manager with auto-transition between BASELINE and AI_ENHANCED
- [ ] Sector lock and per-sector policy adjustments
- [ ] Event writer (JSONL) and flow records export
- [ ] Web admin panel (FastAPI + AdminLTE + auth stack)
- [ ] No TODO stubs remain in shipped modules (prometheus, retraining scheduler)
- [ ] Code runs locally: `MINIFW_SECTOR=establishment python -m app.minifw_ai` starts without crash

**Artifacts**: Working codebase, `requirements.txt` with all dependencies.

**Current blockers for this stage**: None — Stage 2 is complete.

### Stage 3 — Integration

**Goal**: All modules work together as a coherent system. Cross-module interfaces are validated.

**Gate criteria**:
- [ ] Daemon starts and processes DNS events end-to-end (DNS → score → action → log)
- [ ] MLP and YARA integrate with scoring pipeline (scores flow into `score_and_decide()`)
- [ ] Hard threat gates override scoring when triggered
- [ ] State manager transitions between BASELINE and AI_ENHANCED based on telemetry health
- [ ] Enforcement module creates nftables rules on block decisions (requires root)
- [ ] Web admin reads/writes policy files that the daemon consumes
- [ ] Sector lock restricts behaviour per sector (threshold adjustments apply)
- [ ] Prometheus metrics are emitted and scrapeable
- [ ] Flow records export feeds into retraining pipeline
- [ ] All env vars from `.env.example` are consumed correctly
- [ ] Integration test (`testing/test_full_integration.py`) passes end-to-end

**Artifacts**: Integration test results, end-to-end flow documentation.

### Stage 4 — Testing / QA

**Goal**: Full test coverage. Every feature has automated tests. No skips, no stubs, no permanently disabled features.

**Gate criteria**:
- [ ] `pytest testing/` passes with **0 failures, 0 unexpected skips**
- [ ] Unit tests exist for every module:
  - Collectors: journald, conntrack parser, Zeek parser
  - Flow context: `build_feature_vector_24()` value assertions
  - Hard gates: all 4 paths (PPS, burst, bot-small, bot-timing)
  - Scoring: `score_and_decide()` boundary conditions (allow/monitor/block thresholds)
  - Enforcement: `enforce.py` with mocked subprocess
  - MLP: inference, batch, threshold, fallback, stats
  - YARA: compilation, detection, metadata, stats
  - Sector: all 6 sectors, flag enforcement (`redact_payloads`, `block_tor`)
  - State manager: transitions, persistence
  - Prometheus: counter increments
  - Retraining: auto-labeling, model swap
- [ ] Integration tests marked `@pytest.mark.integration` and skippable via `-m "not integration"`
- [ ] No `sys.path.insert()` hacks — `pyproject.toml` sets `pythonpath = app` for pytest
- [ ] No debug prints in production code
- [ ] CI pipeline (`.github/workflows/test.yml`) runs on every push, passes with 0 failures
- [ ] Test coverage report generated (target: >80% line coverage on `app/minifw_ai/`)

**Artifacts**: CI green badge, coverage report, test inventory document.

**Stage 4 complete** — all 22 Stage 4 readiness tasks resolved. Test suite: 246 passed, 1 skipped, 0 failed. CI pipeline active (`.github/workflows/test.yml`).

### Stage 5 — Staging

**Goal**: Deploy to a staging environment that mirrors production. Validate under realistic conditions.

**Gate criteria**:
- [ ] Staging server provisioned (Linux gateway, nftables capable, dnsmasq installed)
- [ ] `scripts/install.sh` runs successfully on staging server
- [ ] `scripts/install_systemd.sh` creates and starts the `minifw-ai` systemd service
- [ ] `scripts/vsentinel_scope_gate.sh` passes (sector validation against canonical list)
- [ ] `scripts/vsentinel_selftest.sh` passes (service active, ipset exists, audit log present)
- [ ] Daemon processes real DNS traffic for ≥24 hours without crash or memory leak
- [ ] MLP model loaded and producing inference results on live flows
- [ ] YARA rules loaded and scanning payloads
- [ ] Enforcement verified: blocked IPs appear in `minifw_block_v4` ipset
- [ ] Web admin accessible, auth stack functional (JWT + TOTP + RBAC)
- [ ] Prometheus metrics scrapeable on configured port
- [ ] JSONL event log and flow records written correctly
- [ ] Sector lock enforced (correct sector loaded, cannot be changed at runtime)
- [ ] Graceful degradation verified: daemon survives DNS backend failure, missing model file, missing YARA rules

**Artifacts**: Staging deployment log, 24-hour stability report, resource usage metrics.

### Stage 6 — Build & Packaging

**Goal**: Produce a distributable package that can be installed on any target machine without a development environment.

**Gate criteria**:
- [ ] Build script or Makefile produces a self-contained release artifact
- [ ] Package includes:
  - `app/minifw_ai/` — engine daemon code
  - `app/web/` — web admin code (including static assets)
  - `config/policy.json` — default policy
  - `config/feeds/` — default deny/allow lists
  - `yara_rules/` — bundled YARA rules
  - `scripts/install.sh` — installation script
  - `scripts/install_systemd.sh` — systemd setup
  - `scripts/enable_dnsmasq_logging.sh` — dnsmasq config
  - `scripts/vsentinel_scope_gate.sh` — scope gate
  - `scripts/vsentinel_selftest.sh` — post-install self-test
  - `requirements.txt` — Python dependencies
  - `systemd/minifw-ai.service` — systemd unit file
- [ ] Version number stamped in package and retrievable at runtime (`--version`)
- [ ] `requirements.txt` is frozen (exact versions, no ranges)
- [ ] Package excludes: `.git/`, `testing/`, `scripts/simulate_*.py`, `.env`, `*.pyc`, development tools
- [ ] Package integrity verifiable (SHA-256 checksum file)
- [ ] Pre-trained MLP model included or documented as a required post-install step
- [ ] Package tested: clean install from artifact on a fresh VM succeeds

**Artifacts**: Release tarball/archive, SHA-256 checksum, version manifest.

### Stage 7 — Code Signing & Security Audit

**Goal**: Ensure the release is trustworthy and free of security vulnerabilities.

**Gate criteria**:
- [ ] Release artifact is cryptographically signed (GPG or equivalent)
- [ ] Signature verification instructions documented
- [ ] Security audit completed:
  - No hardcoded secrets in codebase (API keys, passwords, tokens)
  - `vsentinel_scope_gate.sh` prohibited keyword scan passes
  - No command injection vectors in `enforce.py` (nftables calls use validated inputs)
  - `is_valid_nft_object_name()` rejects all injection patterns
  - Web admin: no XSS, CSRF, SQL injection (SQLAlchemy parameterised queries)
  - JWT tokens use strong secrets (`MINIFW_SECRET_KEY` generated via `openssl rand`)
  - TOTP implementation follows RFC 6238
  - File permissions: `/etc/minifw/minifw.env` is `0600` (secrets file)
  - No world-readable sensitive files post-install
- [ ] Dependency audit: no known CVEs in pinned versions (`pip audit` or equivalent)
- [ ] YARA rules reviewed for false positive/negative rates
- [ ] Sector lock tamper resistance verified (cannot be overridden without physical access)

**Artifacts**: Signed release, security audit report, dependency audit report.

### Stage 8 — Distribution / Release

**Goal**: Make the signed package available for deployment to client sites.

**Gate criteria**:
- [ ] Release tagged in git (`vX.Y.Z`) with changelog
- [ ] Signed package uploaded to distribution channel (private repo, secure file server, USB media)
- [ ] Release notes document:
  - New features and changes since last release
  - Known limitations
  - Supported hardware and OS versions
  - Required post-install configuration (sector, feeds, MLP model)
- [ ] Rollback procedure documented (how to revert to previous version)
- [ ] Distribution channel access restricted to authorised personnel only

**Artifacts**: Git tag, release notes, distribution package, rollback procedure.

### Stage 9 — Client Installation & Validation

**Goal**: Software is installed on the client's gateway hardware and passes acceptance testing.

**Gate criteria**:
- [ ] Hardware meets minimum requirements (Linux, nftables-capable kernel, network interfaces)
- [ ] Installation performed:
  1. `sudo ./scripts/install.sh` — installs to `/opt/minifw_ai/`
  2. `sudo ./scripts/enable_dnsmasq_logging.sh` — configures DNS logging
  3. `sudo ./scripts/install_systemd.sh` — creates systemd service + generates secrets
  4. Sector lock configured (`/opt/minifw_ai/config/sector_lock.json` or `MINIFW_SECTOR` env var)
  5. Policy tuned for client's network (`policy.json` thresholds, feeds populated)
  6. MLP model deployed (pre-trained or trained on client's baseline traffic)
  7. Web admin credentials delivered securely to client
- [ ] `scripts/vsentinel_selftest.sh` passes on client hardware
- [ ] Client acceptance tests:
  - Daemon starts on boot (`systemctl enable minifw-ai`)
  - DNS events are captured and scored
  - Known-bad domain triggers block action
  - Blocked IP appears in nftables/ipset
  - Web admin is accessible and functional
  - Correct sector is locked and reflected in scoring thresholds
  - Logs are written to expected paths
- [ ] Firewall does not disrupt legitimate traffic (false positive check)
- [ ] Client signs off on installation

**Artifacts**: Installation checklist (signed), acceptance test results, client sign-off document.

### Stage 10 — Production & Maintenance

**Goal**: Software operates in production with ongoing monitoring, updates, and support.

**Ongoing responsibilities**:
- [ ] Monitor daemon health via systemd and Prometheus metrics
- [ ] Review JSONL event logs for anomalies and false positives
- [ ] Update deny/allow feeds as threat intelligence evolves
- [ ] Retrain MLP model periodically on accumulated flow records
- [ ] Update YARA rules for new threat patterns
- [ ] Apply security patches (dependency updates within pinned constraints)
- [ ] Rotate secrets (`MINIFW_SECRET_KEY`, admin passwords) on schedule
- [ ] Perform periodic `vsentinel_selftest.sh` health checks
- [ ] Handle sector policy changes (requires re-deployment — sector lock is immutable)
- [ ] Plan and execute version upgrades (Stage 8 → Stage 9 cycle)
- [ ] Maintain incident response runbook
- [ ] Collect client feedback for next PRD cycle (feeds back into Stage 0)

**Artifacts**: Monitoring dashboard, maintenance log, incident reports, upgrade history.

### Stage Progression Summary

```
Stage 0   Concept / Requirements
  ↓       PRD approved, threat model documented
Stage 1   Design
  ↓       Architecture finalised, interfaces defined
Stage 2   Development (Local)
  ↓       All features implemented, no stubs
Stage 3   Integration
  ↓       Modules work together end-to-end
Stage 4   Testing / QA
  ↓       Full test suite passes, CI green
Stage 5   Staging
  ↓       24-hour stability on staging hardware
Stage 6   Build & Packaging
  ↓       Self-contained release artifact produced
Stage 7   Code Signing & Security Audit
  ↓       Signed, audited, no known vulnerabilities
Stage 8   Distribution / Release
  ↓       Tagged, documented, available for deployment
Stage 9   Client Installation & Validation
  ↓       Installed, tested, client sign-off
Stage 10  Production & Maintenance
          Monitored, updated, supported
```

### Current Project Status

**Overall: Stage 7 (Code Signing & Security Audit) — complete.**

- Stage 4 (Testing/QA): complete — 246 tests pass, CI green
- Stage 5 (Staging): complete — enforcement tested live, 24-hour stability confirmed, all ports localhost-bound, security hardening applied
- Stage 6 (Packaging): complete — `minifw-ai_2.0.0_amd64.deb` built, SHA-256 verified, postinst embeds all hardening steps for out-of-box install
- Stage 7 (Code Signing & Security Audit): complete — GPG signed (RSA 4096, key `BDB471E1FB46F58A`), zero CVEs (`pip-audit` clean after PyJWT 2.9.0→2.12.1 bump for CVE-2026-32597)
- Stage 8 (Distribution / Release): complete — `v2.0.0` tagged and pushed, CHANGELOG updated, rollback procedure documented (`docs/rollback.md`), GitHub release created with package artifacts

---

## Version History

All notable changes to MiniFW-AI. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

### [2.2.10] — 2026-10-26

**Fixed**
- **DNS logging helper on fresh installs** — normalize the shared helper to LF line endings so Bash accepts `set -euo pipefail` on all sector packages.

### [2.2.0] — 2026-03-17

**Changed**
- **Sector-versioned package naming** — `.deb` packages now include the sector as a
  version suffix: `minifw-ai_2.2.0-establishment_amd64.deb`,
  `minifw-ai_2.2.0-hospital_amd64.deb`. Makes parallel sector builds of the same
  codebase version unambiguous. `BASE_VERSION` in `build_deb.sh` is set once; the
  full `VERSION` is derived as `${BASE_VERSION}-${SECTOR}`.

**Added**
- **Zeek TLS/SNI collector fully activated** — `use_zeek_sni: true` by default in
  `policy.json`. `collector_zeek.py` now yields `ZeekSSLEvent` (NamedTuple) carrying
  `handshake_ms`, `alpn_h2`, `cert_self_signed`. All four previously-hardcoded `0.0`
  MLP features now populated from live Zeek and domain-frequency data.
- **`domain_repeat_5min` frequency tracking** — `FlowTracker` maintains a 5-minute
  sliding window per domain. `build_feature_vector_24()` accepts optional `tracker=`
  argument to populate feature index 23.
- **Dashboard: Collector Status** — Firewall Status panel shows live Active/Inactive
  state for Zeek TLS/SNI, DNS Collector, and Flow Tracking (conntrack), read from
  actual file presence at request time.
- **Dashboard: SNI Blocks tile** — 7th System Intelligence counter tracking TLS/SNI
  deny events.
- **Dashboard: Monitor badge** — events table now shows amber "Monitor" badge for
  `action=monitor` events (previously fell through to "Allowed").

**Fixed**
- **SIGTERM audit gap** — `main.py` now registers a `SIGTERM` handler that calls
  `audit_daemon_stop("sigterm")` before `sys.exit(0)`. `systemctl stop` is now
  recorded in the audit log.
- **`user_management.html` sector dropdown** — `school` corrected to `education` in
  filter dropdown, Create User modal, Edit User modal, and sector-badge CSS class.
- **`get_system_uptime()` was hardcoded** — now reads `/proc/uptime` and returns
  uptime as a percentage of a 30-day reference window.

**Build artifacts**
- `minifw-ai_2.2.0-establishment_amd64.deb` — SHA256: `9434eb27a89333f2d5b0aaa6f8f1ac98a55694b7a52af97dbf24041531964c2d`
- `minifw-ai_2.2.0-hospital_amd64.deb` — SHA256: `2f9bd834a0ffe5d4cb213043c7c9371fa506a24778f8585b789692a489b89823`

### [2.1.0] — 2026-03-17

**Added (Hospital Sector)**
- **`Event.severity` field** — `Event` dataclass now carries a `severity` field
  (default `"info"`). Elevated to `"critical"` for IoMT device alerts when
  `MINIFW_SECTOR=hospital` and the source IP is within `iomt_subnets`.
- **`alert_severity_boost` wired** — `main.py` IoMT alert block now reads
  `sector_config.get("alert_severity_boost", "info")` and passes the result to
  `Event(severity=...)`, serialised to `events.jsonl`.
- **`config/feeds/healthcare_threats.txt`** — Hospital sector extra feed: 35+ threat
  entries across four categories: ransomware C2 (Ryuk/Conti/LockBit campaigns),
  phishing/credential-harvest, unauthorised medical data brokers, IoMT exploit delivery.
  Wildcard patterns supported (e.g. `*.patient-records-secure.com`).
- **`yara_rules/hospital_rules.yar`** — Three hospital YARA rules:
  - `MedicalRansomware` (severity=critical) — ransom note strings, Conti/Ryuk/LockBit
    extensions, `vssadmin delete shadows`, `bcdedit /set recoveryenabled no`, `wbadmin`.
  - `IoMTExploit` (severity=critical) — medical device API paths (`/infusion/rate/set`,
    `/pump/bolus`, `/monitor/alarm/disable`), GE/Philips/Baxter API patterns, firmware
    upload, shell injection.
  - `MedicalDataExfil` (severity=high) — HL7 MSH/PID headers, FHIR bulk export
    (`/$export`, `_outputFormat=application/fhir`), DICOM C-STORE/C-MOVE, `phi_archive`.
- **`policy.json` IoMT subnets populated** — `iomt_subnets` set to example ranges
  `["10.20.0.0/24", "10.20.1.0/24"]` with deployment note. Must be set to actual
  medical device network ranges before production deployment.
- **Hospital test suite** — 66 tests across 4 new files:
  `test_sector_hospital_severity.py`, `test_sector_hospital_feeds.py`,
  `test_sector_hospital_integration.py`, `test_hospital_yara.py`. All pass.
- **Hospital deployment readiness report** — `docs/report-2026-03-17-hospital.md`.

**Fixed**
- **YARA `compile_rules()` silent-drop bug** — `yara_scanner.py` used
  `yara.compile(filepaths=dict)` keyed by parent directory name. With multiple `.yar`
  files in the same directory, only the first file per key was compiled —
  `hospital_rules.yar` was silently dropped. Fixed: switched to
  `yara.compile(sources=dict)` keyed by file stem. All `.yar` files in `yara_rules/`
  are now compiled.

**Changed**
- **`build_deb.sh` sector-aware** — accepts `$1` sector argument (default: `establishment`).
  Sector validated against 6-sector allowlist. `MINIFW_SECTOR` baked into the copied
  service unit via `sed`. Package `Description` now includes sector name.
- **`DEBIAN/conffiles`** — `healthcare_threats.txt` added for hospital sector builds only.
- **VERSION bump: 2.0.0 → 2.1.0** for hospital sector.

**Build Artefacts (hospital)**
- `build/minifw-ai_2.1.0_amd64.deb` — SHA256: `b766ee905b5f47059bd7ec0076131a80c920a5532f4a39273cf29acb3e9e0988`
- GPG: signed with key `BDB471E1FB46F58A` (release@minifw.local)

### [2.0.0] — 2026-03-16

**Security (breaking)**
- **Removed VSentinel GAMBLING_ONLY hard guard** — module-level `SystemExit` gate that
  blocked all non-gambling deployments has been removed from `main.py`, both systemd
  service units, and the `.deb` postinst. All sector deployments now work without this env var.
- **PyJWT bumped 2.9.0 → 2.12.1** — fixes CVE-2026-32597 (`crit` header bypass, RFC 7515
  §4.1.11 non-compliance). Zero CVEs confirmed via `pip-audit`.
- **All service ports restricted to 127.0.0.1** — Prometheus (9090), Grafana (3000),
  ipapi_guard (5514), nginx proxy (7004) were previously bound to 0.0.0.0.
- **ipapi_guard source patched** — `server.bind(("0.0.0.0", port))` → `("127.0.0.1", port)`

**Added**
- **ASN feed populated** — `config/feeds/asn_prefixes.txt` now ships with 141 CIDR-to-ASN
  entries (Google, Cloudflare, AWS, Azure, Akamai, Fastly, Indonesian ISPs, threat hosting
  ASNs). ASN scoring signal (+15) is fully operational.
- **Prometheus metrics module** — full implementation replacing 0% stub:
  counters (flows, decisions, hard-gate blocks), histograms (threat score, MLP/YARA latency),
  gauges (active blocks, flows, model timestamp). Bound to 127.0.0.1 by default.
- **ML retraining scheduler** — full implementation replacing 0% stub:
  auto-labeling from event log, MLP training with 80/20 split, atomic model swap.
- **Journald collector retry** — replaced infinite `yield None` degraded loop with
  exponential backoff (5s → 5min). Collector retries instead of giving up permanently.
- **Sector flags enforced** — `redact_payloads` (hospital HIPAA) and `block_tor`/
  `block_anonymizers` (finance) are now active, not no-ops.
- **DNS tunneling detection** — entropy-based tunnel score wired into `score_and_decide()`.
- **Rate limiting and input validation** — login endpoint, admin API, nftables object names.
- **CI pipeline** — `.github/workflows/test.yml` runs on push/PR, Python 3.12, no GAMBLING_ONLY.
- **`vsentinel_scope_gate.sh` rewritten** — validates `MINIFW_SECTOR` against canonical list
  (`hospital education government finance legal establishment`), rejects `gambling` and unknowns.
- **GPG-signed release** — RSA 4096, key `BDB471E1FB46F58A`, expires 2028-03-15.
  Verification instructions in `docs/release-verification.md`.
- **`docs/monitoring-mode.md`** — analyst reference: thresholds, weights, scoring table,
  how to enter observation-only mode, fail-safe behaviour.
- **`docs/report-2026-03-16.md`** — client deployment readiness report, enforcement test
  results, port exposure verification, outstanding items.

**Fixed**
- **Dashboard `/admin/` HTTP 500** — `jinja2.UndefinedError: 'detection_counters' is undefined`
  caused by Starlette 0.49 deprecating the old `TemplateResponse(name, context_dict)` API.
  All 16 `TemplateResponse` calls across 12 files migrated to new API:
  `TemplateResponse(request, name, context_dict)` with `request` removed from the context dict.
- **`collector_flow.py` kernel 6.8 compatibility** — `stream_conntrack_flows()` now
  auto-detects procfs availability and falls back to the `conntrack -L` CLI when
  `/proc/net/nf_conntrack` is absent (`CONFIG_NF_CONNTRACK_PROCFS=not set`). Hard threat
  gates (burst flood, bot detection, flow frequency) are fully operational on Ubuntu 24.04
  kernel 6.8. `conntrack` added to `.deb` Depends.
- `interarrival_std_ms` property called non-existent `get_interarrival_std()` — fixed to
  `get_interarrival_std_ms()` in `collector_flow.py:138`.
- Debug print `for route in app.routes: print(...)` removed from `app/web/app.py`.
- `prometheus_client` and `schedule` added to `requirements.txt` (were missing).
- `pyproject.toml` added with `pythonpath = ["app", "."]` — eliminates `sys.path.insert` hacks.
- `collector_dnsmasq.py` UDP bind default changed `0.0.0.0` → `127.0.0.1` — UDP DNS collector
  no longer listens on all interfaces by default.
- Removed stale `GAMBLING_ONLY` env var from CI workflow, `conftest.py`, `test_state_manager.py`,
  and `test_security_features.py`. Set `MINIFW_SECTOR=establishment` (was `gambling`, an invalid
  sector since 2.0.0) in `test_security_features.py`.

**Changed**
- Sector name `school` → `education` throughout codebase, docs, and package metadata.
- postinst expanded from 6 → 9 steps: adds nf_conntrack module load + persistence,
  Grafana localhost hardening, CUPS disable.
- `start_metrics_server()` default bind address changed from implicit 0.0.0.0 → 127.0.0.1.

**Known limitations**: `audit_daemon_stop()` not called on SIGTERM — stop event absent from
audit log on `systemctl stop`. Only fires on KeyboardInterrupt.

**Test suite**: 328 passed, 0 failed (up from 246 after conntrack CLI path tests added).

### [2.0.0] — 2026-03-11 (pre-release snapshot)

**Added**
- Formal versioned PRD with threat model, compliance matrix, quality targets & QA test plan
- Development stage guidelines (11-stage model), this file's predecessor `TODO.md`
- Synthetic MLP model fixture in `testing/conftest.py` for test independence
- Bundled YARA rules at `yara_rules/test_rules.yar`
- Rewrote `testing/test_mlp_integration.py`, `test_mlp_inference.py`, `test_yara_scanner.py` as proper pytest (45 tests)

**Changed**
- Test suite: 114 passed, 1 skipped, 0 failed (up from broken/skipping state)

**Known issues**: Prometheus export not yet implemented; journald DNS backend falls to
degraded mode permanently; automated ML retraining not yet wired; ASN signal hardcoded
`False`; IP block sync with V-Sentinel not implemented.

### [1.0.0] — Unknown Date

**Added**
- Initial implementation of MiniFW-AI engine (standalone copy from `ritapi-v-sentinel`)
- DNS telemetry collection (file, journald, UDP backends), TLS SNI via Zeek `ssl.log`,
  network flow collection via `/proc/net/nf_conntrack`, 24-feature flow context builder
- Hard threat gates (PPS saturation, burst flood, bot detection)
- Baseline threat scoring (DNS +40, SNI +35, ASN +15, burst +10)
- MLP inference engine (scikit-learn MLPClassifier, 0-30 points)
- YARA pattern detection (0-35 points), 3-tier decision engine (allow / monitor / block)
- nftables/ipset enforcement with configurable TTL
- State manager with auto-transition (BASELINE <-> AI_ENHANCED)
- Sector lock singleton (hospital, school, government, finance, legal, establishment)
- JSONL event logging and flow records export
- FastAPI web admin panel with AdminLTE 3 UI, JWT + TOTP + bcrypt auth stack with RBAC
- Per-sector policy adjustments and threshold tuning
- Scaffold for Prometheus metrics and ML retraining scheduler
