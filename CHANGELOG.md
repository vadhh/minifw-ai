# Changelog

All notable changes to MiniFW-AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.0.0] — 2026-03-11

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
