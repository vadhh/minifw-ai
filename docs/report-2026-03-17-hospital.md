# MiniFW-AI / ARCHANGEL 2.0 — Hospital Sector Deployment Readiness Report

**Date:** 2026-03-17
**Version:** 2.1.0
**Sector:** Hospital (`MINIFW_SECTOR=hospital`)
**Build:** `16b387c` — feat(hospital): complete hospital sector 2.1.0 — H-1 through H-6 + build
**Prepared by:** Engineering (Claude Code assisted)
**Status:** ✅ DEPLOYMENT READY (IoMT subnets require site-specific configuration)

---

## Executive Summary

MiniFW-AI v2.1.0 (hospital sector) has been validated against the hospital deployment
checklist. All 6 hospital feature tasks (H-1 through H-6) are implemented, tested, and
passing. The package has been GPG-signed and SHA256-verified. One site-specific action
is required before going live: set `iomt_subnets` in `policy.json` to the actual medical
device network ranges at the target facility.

---

## 1. Hospital Sector Checklist

| # | Item | Status | Detail |
|---|------|--------|--------|
| H-1 | `alert_severity_boost` wired | ✅ PASS | `Event.severity="critical"` for IoMT alerts; serialised to `events.jsonl` |
| H-2 | `healthcare_threats.txt` feed | ✅ PASS | 35+ entries, 4 categories, wildcard support |
| H-3 | Hospital YARA rules | ✅ PASS | MedicalRansomware, IoMTExploit, MedicalDataExfil compiled and matching |
| H-4 | `iomt_subnets` populated | ⚠ ACTION | Example ranges set; **must update to facility's actual IoMT subnets** |
| H-5 | Sector-aware build | ✅ PASS | `MINIFW_SECTOR=hospital` baked into service unit |
| H-6 | Hospital integration tests | ✅ PASS | 66/66 tests pass |
| — | Package signed | ✅ PASS | RSA 4096, key `BDB471E1FB46F58A` |
| — | SHA256 verified | ✅ PASS | `b766ee905b5f47059bd7ec0076131a80c920a5532f4a39273cf29acb3e9e0988` |

---

## 2. Hospital-Specific Feature Validation

### H-1 — IoMT Alert Severity (HIPAA-grade alerting)

**Config key:** `alert_severity_boost: "critical"` in hospital sector config.

**Behaviour:**
- Source IP within `iomt_subnets` + score ≥ monitor threshold (40) → `severity=critical`
- `iomt_device_alert` appended to `reasons[]`
- Critical-level log entry written: `[IOMT_ALERT] Medical device anomaly: <ip> -> <domain>`
- Severity serialised to `events.jsonl` for SIEM/audit pipeline

**Test results:**
```
test_event_has_severity_field                    PASS
test_event_severity_default_is_info              PASS
test_event_severity_can_be_set_to_critical       PASS
test_alert_severity_boost_config_key_is_critical PASS
test_alert_severity_boost_absent_for_estab       PASS
test_event_severity_written_to_json              PASS
```

---

### H-2 — Healthcare Threats Feed

**File:** `config/feeds/healthcare_threats.txt`
**Loaded via:** `FeedMatcher.load_sector_feeds(["healthcare_threats.txt"])` at engine startup.

**Feed categories:**
| Category | Entries | Example |
|----------|---------|---------|
| Ransomware C2 | 8 | `lockbit-blog.com`, `*.conti-decryptor.onion.pet` |
| Phishing / credential harvest | 10 | `myhealth-portal-login.net`, `*.secure-patient-login.com` |
| Unauthorised data brokers | 8 | `medrecords-transfer.io`, `*.healthcare-data-marketplace.net` |
| IoMT exploit delivery | 9 | `iomt-firmware-update.ru`, `*.medical-device-patch.cc` |

**Test results:**
```
test_healthcare_threats_file_exists              PASS
test_healthcare_threats_file_is_not_empty        PASS  (35 active entries)
test_load_sector_feeds_loads_healthcare_threats  PASS  (3 entries in test fixture)
test_domain_in_healthcare_feed_is_denied         PASS
test_wildcard_domain_in_healthcare_feed_matches  PASS
test_benign_domain_not_denied_after_load         PASS
test_missing_feed_does_not_raise                 PASS  (non-hospital deployments safe)
```

---

### H-3 — Hospital YARA Rules

**File:** `yara_rules/hospital_rules.yar`

**Rules:**

| Rule | Severity | Category | Trigger |
|------|----------|----------|---------|
| `MedicalRansomware` | critical | medical_ransomware | Ransom notes, shadow delete, recovery disable, `.lockbit` extension |
| `IoMTExploit` | critical | iomt_exploit | Medical device API paths, GE/Philips/Baxter patterns, shell injection |
| `MedicalDataExfil` | high | medical_data_exfil | HL7/FHIR/DICOM patterns, PHI archive filenames |

**YARA engine fix applied:** `yara_scanner.py` `compile_rules()` was silently dropping all
`.yar` files after the first per directory (used `filepaths=` keyed by parent dir name).
Fixed to `sources=` keyed by file stem — all files in `yara_rules/` are now compiled.

**Test results (41 tests):**
```
MedicalRansomware — 8 payload matches    PASS
MedicalRansomware — severity=critical    PASS
MedicalRansomware — category check       PASS
IoMTExploit — 8 payload matches          PASS
IoMTExploit — severity=critical          PASS
IoMTExploit — category check             PASS
MedicalDataExfil — 10 payload matches    PASS
MedicalDataExfil — severity=high         PASS
MedicalDataExfil — category check        PASS
Benign payload — no false positives (7)  PASS
```

---

### H-4 — IoMT Subnets

**Current state in `policy.json`:**
```json
"iomt_subnets": ["10.20.0.0/24", "10.20.1.0/24"]
```

> **⚠ ACTION REQUIRED before deployment:**
> Replace example subnets with the facility's actual medical device network ranges.
> IoMT alerting is entirely disabled when `iomt_subnets` is empty.
>
> ```bash
> sudo nano /opt/minifw_ai/config/policy.json
> # Update "iomt_subnets": ["<actual_range_1>", "<actual_range_2>"]
> sudo systemctl restart minifw-ai
> ```
> Confirm with: `journalctl -u minifw-ai | grep "iomt_subnets"`

---

### H-5 — Sector Lock and Package

**Package:** `minifw-ai_2.1.0_amd64.deb`
**Sector baked in:**
```
Environment=MINIFW_SECTOR=hospital   # in /etc/systemd/system/minifw-ai.service
```

**Conffiles preserved on upgrade:**
```
/opt/minifw_ai/config/policy.json
/opt/minifw_ai/config/feeds/allow_domains.txt
/opt/minifw_ai/config/feeds/deny_domains.txt
/opt/minifw_ai/config/feeds/deny_ips.txt
/opt/minifw_ai/config/feeds/deny_asn.txt
/opt/minifw_ai/config/feeds/tor_exit_nodes.txt
/opt/minifw_ai/config/feeds/asn_prefixes.txt
/opt/minifw_ai/config/feeds/healthcare_threats.txt   ← hospital-only
```

---

### H-6 — Integration Test Summary

Full end-to-end pipeline tested:

| Scenario | Score | Action | Severity | IoMT alert |
|----------|-------|--------|----------|------------|
| IoMT IP + healthcare threat domain | 90 | block | critical | yes |
| IoMT IP at monitor threshold (42) | 42 | monitor | critical | yes |
| Non-IoMT IP + healthcare threat domain | 90 | block | info | no |
| IoMT IP + benign domain | 0 | allow | info | no |

HIPAA redaction: domain replaced with `[REDACTED]` in all hospital events regardless of
action or source IP.

Hospital threshold verification:
```
Hospital monitor threshold: 40  (default 60, adjusted -20)  ✓
Hospital block threshold:   85  (default 90, adjusted -5)   ✓
Score 39 → allow             ✓
Score 40 → monitor           ✓
Score 85 → block             ✓
```

---

## 3. Inherited Establishment Baseline (from 2.0.0)

All 2.0.0 establishment features carry forward unchanged:

| Feature | Status |
|---------|--------|
| DNS behavioral scoring | ✅ Active |
| Hard threat gates (PPS/burst/bot) | ✅ Active |
| MLP inference engine | ✅ Active (model: mlp_model.pkl, accuracy 1.0) |
| YARA scanning | ✅ Active (test_rules.yar + hospital_rules.yar) |
| nftables enforcement | ✅ Active (inet minifw table) |
| HIPAA payload redaction | ✅ Active (redact_payloads=True) |
| Tor/anonymizer blocking | N/A — finance sector only |
| Prometheus metrics | ✅ Active (127.0.0.1:9090) |
| ML retraining scheduler | ✅ Active (24h cycle) |
| JWT + bcrypt + TOTP auth | ✅ Active |
| TLS web dashboard (port 8443) | ✅ Active |
| Audit logging | ✅ Active |

---

## 4. Hospital-Specific Scoring Reference

With hospital sector active, effective thresholds are:

| Threshold | Default | Hospital adjustment | Effective |
|-----------|---------|---------------------|-----------|
| Monitor | 60 | −20 | **40** |
| Block | 90 | −5 | **85** |

Scoring weights (unchanged from 2.0.0):

| Signal | Weight | Notes |
|--------|--------|-------|
| DNS deny match (incl. healthcare feed) | +40 | `healthcare_threats.txt` loaded as extra deny feed |
| TLS SNI deny match | +35 | |
| YARA match | 0–35 | Hospital rules: MedicalRansomware/IoMTExploit → +35 |
| MLP inference | 0–30 | |
| ASN deny | +15 | |
| IP deny | +15 | |
| DNS burst | +10 | |
| Hard gate | =100 | Override: PPS, burst, bot |

Typical hospital block scenarios:

| Event | Signals | Score | Action |
|-------|---------|-------|--------|
| Medical device → ransomware C2 | dns_denied(+40) + iomt_alert | 40+ | block (≥85 w/ ip deny) |
| FHIR exfil payload | yara_MedicalDataExfil(+35) + dns_denied(+40) | 75 → monitor | escalates with MLP |
| IoMT device burst query | burst(+10) + dns_denied(+40) + mlp(+25) | 75+ → block at 85 | |

---

## 5. Pre-Deployment Checklist (On-Site)

Before powering on the hospital appliance:

- [ ] **Set IoMT subnets** — Update `policy.json` `iomt_subnets` with actual medical device VLANs
- [ ] **Set DNS source** — Configure `MINIFW_DNS_SOURCE` in service unit (`file` for dnsmasq)
- [ ] **Enable dnsmasq logging** — `log-queries` + `log-facility=/var/log/dnsmasq.log`
- [ ] **Configure dnsmasq as gateway DNS** — Point all client devices to the appliance IP
- [ ] **Connect gateway NIC** — Plug ethernet into `enp1s0/enp3s0/enp4s0` and run `netplan apply`
- [ ] **Change admin password** — First login at `https://localhost:8443` forces password change
- [ ] **Verify nftables table** — `sudo nft list table inet minifw`
- [ ] **Verify sector lock** — `journalctl -u minifw-ai | grep SECTOR_LOCK`
  Expected: `[SECTOR_LOCK] Device sector: hospital (LOCKED)`
- [ ] **Verify IoMT alert path** — Send test query from an IoMT subnet IP; confirm
  `[IOMT_ALERT]` log entry and `severity=critical` in `events.jsonl`
- [ ] **Verify HIPAA redaction** — Check `events.jsonl`; `domain` field must be `[REDACTED]`

---

## 6. Package Verification

```bash
# Import release key (if not already imported)
gpg --import minifw-ai-release.asc

# Verify GPG signature
gpg --verify minifw-ai_2.1.0_amd64.deb.asc minifw-ai_2.1.0_amd64.deb
# Expected: Good signature from "MiniFW-AI Release" [key BDB471E1FB46F58A]

# Verify SHA-256
sha256sum -c minifw-ai_2.1.0_amd64.deb.sha256
# Expected: minifw-ai_2.1.0_amd64.deb: OK
# SHA256: b766ee905b5f47059bd7ec0076131a80c920a5532f4a39273cf29acb3e9e0988
```

---

## 7. Outstanding Items

| Item | Severity | Notes |
|------|----------|-------|
| `iomt_subnets` must be set to actual facility ranges | **Required** | See H-4 above |
| `audit_daemon_stop()` not called on SIGTERM | Low | Inherited from 2.0.0; stop event absent from audit log on `systemctl stop`. Only fires on KeyboardInterrupt. |
| Wired NIC connection | Deployment step | `enp1s0/enp3s0/enp4s0` — physical cable required |

---

*Report generated: 2026-03-17 | Build: 16b387c | Key: BDB471E1FB46F58A*
