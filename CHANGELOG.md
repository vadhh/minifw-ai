# Changelog

All notable changes to MiniFW-AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.0.0] — 2026-03-16

### Security (breaking)
- **Removed VSentinel GAMBLING_ONLY hard guard** — module-level `SystemExit` gate that
  blocked all non-gambling deployments has been removed from `main.py`, both systemd
  service units, and the `.deb` postinst. All sector deployments now work without this env var.
- **PyJWT bumped 2.9.0 → 2.12.1** — fixes CVE-2026-32597 (`crit` header bypass, RFC 7515
  §4.1.11 non-compliance). Zero CVEs confirmed via `pip-audit`.
- **All service ports restricted to 127.0.0.1** — Prometheus (9090), Grafana (3000),
  ipapi_guard (5514), nginx proxy (7004) were previously bound to 0.0.0.0.
- **ipapi_guard source patched** — `server.bind(("0.0.0.0", port))` → `("127.0.0.1", port)`

### Added
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

### Fixed
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

### Changed
- Sector name `school` → `education` throughout codebase, docs, and package metadata.
- postinst expanded from 6 → 9 steps: adds nf_conntrack module load + persistence,
  Grafana localhost hardening, CUPS disable.
- `start_metrics_server()` default bind address changed from implicit 0.0.0.0 → 127.0.0.1.

### Known Limitations
- `audit_daemon_stop()` not called on SIGTERM — stop event absent from audit log on
  `systemctl stop`. Only fires on KeyboardInterrupt.

### Test Suite
328 passed, 0 failed (up from 246 after conntrack CLI path tests added).

---

## [2.0.0] — 2026-03-11 (pre-release snapshot)

### Added
- Formal versioned PRD (`PRD_3_MiniFW-AI_v3.docx`) with threat model (S14), compliance matrix (S15), quality targets & QA test plan (S16)
- `CHANGELOG.md` (this file)
- Development stage guidelines (11-stage model) in `DEVELOPER.md`
- `TODO.md` with Stage 4 readiness task list (19 tasks identified, 3 completed)
- `tests/reports/` directory for QA test reports
- Synthetic MLP model fixture in `testing/conftest.py` for test independence
- Bundled YARA rules at `yara_rules/test_rules.yar` (GamblingKeywords, MalwarePatterns, ApiAbuse)
- Rewrote `testing/test_mlp_integration.py` and `testing/test_mlp_inference.py` as proper pytest (20 tests)
- Rewrote `testing/test_yara_scanner.py` as proper pytest (25 tests)

### Changed
- Feature documentation moved from `README.md` to formal PRD
- `README.md` now references PRD and supporting documents
- Test suite: 114 passed, 1 skipped, 0 failed (up from broken/skipping state)

### Removed
- Standalone `THREAT_MODEL.md`, `COMPLIANCE.md`, `QUALITY_TARGETS.md`, `QA_TEST_PLAN.md` — consolidated into PRD v3 sections 14-16

### Known Issues
- Prometheus export not yet implemented (`prometheus/metrics.py` is a stub)
- Journald DNS backend falls to degraded mode permanently
- Automated ML retraining not yet wired (`scheduler/retrain_scheduler.py` is a stub)
- ASN signal hardcoded `False` in `main.py:561`
- IP block sync with V-Sentinel not implemented

---

## [1.0.0] — Unknown Date

### Added
- Initial implementation of MiniFW-AI engine (standalone copy from `ritapi-v-sentinel`)
- DNS telemetry collection (file, journald, UDP backends)
- TLS SNI collection via Zeek ssl.log
- Network flow collection via /proc/net/nf_conntrack
- 24-feature flow context builder
- Hard threat gates (PPS saturation, burst flood, bot detection)
- Baseline threat scoring (DNS +40, SNI +35, ASN +15, burst +10)
- MLP inference engine (scikit-learn MLPClassifier, 0-30 points)
- YARA pattern detection (malware, gambling, API abuse, 0-35 points)
- 3-tier decision engine (allow / monitor / block)
- nftables/ipset enforcement with configurable TTL
- State manager with auto-transition (BASELINE <-> AI_ENHANCED)
- Sector lock singleton (hospital, school, government, finance, legal, establishment)
- JSONL event logging and flow records export
- FastAPI web admin panel with AdminLTE 3 UI
- JWT + TOTP + bcrypt authentication stack with RBAC
- Per-sector policy adjustments and threshold tuning
- Scaffold for Prometheus metrics and ML retraining scheduler
