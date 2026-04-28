# MiniFW-AI — Production Roadmap (Remaining 3 Sectors)

## Architecture doctrine

```
1 core engine  +  sector-based modules  =  sector product
```

**Core engine** (frozen — never touched per sector):
- `flow_collector.py` — traffic collection layer
- `ai_engine.py` — AI scoring engine
- `policy_engine.py` — policy enforcement
- `alert_engine.py` — alert dispatch
- `logger.py` — logging and proof output

**Sector overlays** (the only things that change per sector):
1. Detection priorities
2. Policy enforcement logic
3. Dashboard narrative and labels
4. Rules and evidence pack

---

## Non-negotiable rules

- ONE core only — no duplication between sectors
- NO sector logic inside `/core`
- ALL differences live in config + rules only
- Dashboard structure stays identical across sectors — change wording only
- Logs must always justify decisions with human-readable operational reasons
- Code labels and dashboard labels must be separated explicitly

---

## Phase 1 — Consolidation (mandatory first)

Before touching any new sector, extract a clean reusable core from the 3 existing sectors.

### Required folder structure

```
/opt/minifw_ai/
│
├── core/
│   ├── flow_collector.py
│   ├── ai_engine.py
│   ├── policy_engine.py
│   ├── alert_engine.py
│   └── logger.py
│
├── sector/
│   ├── rules.py
│   └── config.json
│
├── dashboard/
│   ├── app.py
│   ├── templates/
│   └── static/
│
├── demo/
│   └── demo_flows.json
│
├── packaging/
│   ├── install.sh
│   └── service.service
│
└── main.py
```

**Deliverable**: one unified sector-neutral template. Do not proceed to Phase 2 until this exists.

---

## Phase 2 — Sector matrices (critical thinking step)

Write these 3 matrices before writing a single line of sector code.

### Financial

| Layer | Content |
|---|---|
| Detection priorities | Abnormal outbound flows, suspicious encrypted traffic, ASN risk, API anomalies, exfiltration patterns |
| Enforcement | Block high-risk ASN, alert abnormal behavior, escalate unknown encrypted flows |
| Dashboard language | "Transaction environment protection", "Suspicious encrypted communication", "Audit-ready evidence" |
| Evidence pack | Financial YARA rules, API abuse signatures, fraud behavioral indicators, compliance-grade logs |

### Government

| Layer | Content |
|---|---|
| Detection priorities | External communication anomalies, C2-like patterns, segmentation violations, critical service misuse |
| Enforcement | Strict blocking, alert escalation, traceability logging |
| Dashboard language | "Sovereign infrastructure protection", "Critical system integrity", "Full traceability" |
| Evidence pack | Sovereign infra signatures, C2 behavioral indicators, critical service logs, audit-compliant trace exports |

### Legal

| Layer | Content |
|---|---|
| Detection priorities | Sensitive data movement, unusual destinations, abnormal encrypted sessions, discreet exfiltration |
| Enforcement | Silent detection + alert, selective blocking, high-evidence logging |
| Dashboard language | "Client confidentiality protection", "Sensitive data control", "Professional secrecy preservation" |
| Evidence pack | Professional secrecy rules, document movement signatures, confidentiality anomaly indicators, legal-grade audit logs |

---

## Phase 3 — Build Financial (first implementation)

### Step 1 — Sector config

`/sector/config.json`

```json
{
  "sector": "financial",
  "risk_threshold": 0.7,
  "block_asn": true,
  "detect_exfiltration": true
}
```

### Step 2 — Detection rules

`/sector/rules.py`

```python
from __future__ import annotations

from typing import Any, Dict, List, Optional


# -----------------------------------------------------------------------------
# FINANCIAL SECTOR CONFIG
# -----------------------------------------------------------------------------

FINANCIAL_DEFAULTS = {
    "high_risk_countries": {"KP", "IR", "SY", "RU"},
    "suspicious_ports": {21, 22, 23, 25, 53, 4444, 5555, 6666, 7777, 8443},
    "approved_business_hours_start": 6,   # 06:00
    "approved_business_hours_end": 22,    # 22:00
    "large_upload_bytes": 50 * 1024 * 1024,        # 50 MB
    "very_large_upload_bytes": 200 * 1024 * 1024,  # 200 MB
    "burst_connection_threshold": 80,
    "suspicious_ja3_risk_threshold": 0.80,
    "blocked_asns": set(),
    "trusted_asns": set(),
    "sensitive_tags": {"core-banking", "payment", "finance-db", "customer-data-api"},
}


# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_hour(flow: Dict[str, Any]) -> Optional[int]:
    hour = flow.get("hour")
    if hour is None:
        return None
    try:
        hour = int(hour)
        if 0 <= hour <= 23:
            return hour
    except (TypeError, ValueError):
        pass
    return None


def _add_detection(
    detections: List[Dict[str, Any]],
    *,
    detection_type: str,
    score: float,
    severity: str,
    reason: str,
    recommended_action: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    detections.append({
        "type": detection_type,
        "score": max(0.0, min(1.0, score)),
        "severity": severity,
        "reason": reason,
        "recommended_action": recommended_action,
        "source": "financial_sector_rules",
        "metadata": metadata or {},
    })


# -----------------------------------------------------------------------------
# INDIVIDUAL RULES
# -----------------------------------------------------------------------------

def detect_high_risk_country(flow, cfg, detections):
    dst_country = str(flow.get("dst_country", "")).upper().strip()
    if not dst_country:
        return
    if dst_country in cfg["high_risk_countries"]:
        _add_detection(
            detections,
            detection_type="high_risk_country",
            score=0.86,
            severity="high",
            reason=f"Outbound connection to high-risk country: {dst_country}",
            recommended_action="block",
            metadata={"dst_country": dst_country, "dst_ip": flow.get("dst_ip"), "dst_host": flow.get("dst_host")},
        )


def detect_blocked_asn(flow, cfg, detections):
    asn = str(flow.get("dst_asn", "")).strip()
    if not asn:
        return
    if asn in cfg["blocked_asns"]:
        _add_detection(
            detections,
            detection_type="blocked_asn",
            score=0.95,
            severity="critical",
            reason=f"Connection to blocked ASN: {asn}",
            recommended_action="block",
            metadata={"dst_asn": asn, "dst_ip": flow.get("dst_ip"), "dst_host": flow.get("dst_host")},
        )


def detect_unknown_external_asn(flow, cfg, detections):
    asn = str(flow.get("dst_asn", "")).strip()
    internal = bool(flow.get("is_internal", False))
    known_vendor = bool(flow.get("known_vendor", False))
    if internal or not asn:
        return
    if cfg["trusted_asns"] and asn not in cfg["trusted_asns"] and not known_vendor:
        _add_detection(
            detections,
            detection_type="unknown_external_asn",
            score=0.72,
            severity="medium",
            reason=f"Connection to non-trusted external ASN: {asn}",
            recommended_action="alert",
            metadata={"dst_asn": asn, "dst_ip": flow.get("dst_ip"), "known_vendor": known_vendor},
        )


def detect_suspicious_port(flow, cfg, detections):
    dst_port = _safe_int(flow.get("dst_port"))
    if dst_port in cfg["suspicious_ports"]:
        _add_detection(
            detections,
            detection_type="suspicious_port",
            score=0.68,
            severity="medium",
            reason=f"Connection to suspicious destination port: {dst_port}",
            recommended_action="alert",
            metadata={"dst_port": dst_port, "dst_ip": flow.get("dst_ip")},
        )


def detect_large_outbound_transfer(flow, cfg, detections):
    bytes_out = _safe_int(flow.get("bytes_out"))
    internal = bool(flow.get("is_internal", False))
    app_tag = str(flow.get("app_tag", "")).strip().lower()
    if internal:
        return
    if bytes_out >= cfg["very_large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="very_large_outbound_transfer",
            score=0.96,
            severity="critical",
            reason=f"Very large outbound transfer detected: {bytes_out} bytes",
            recommended_action="block",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "app_tag": app_tag},
        )
    elif bytes_out >= cfg["large_upload_bytes"]:
        _add_detection(
            detections,
            detection_type="large_outbound_transfer",
            score=0.81,
            severity="high",
            reason=f"Large outbound transfer detected: {bytes_out} bytes",
            recommended_action="alert",
            metadata={"bytes_out": bytes_out, "dst_ip": flow.get("dst_ip"), "app_tag": app_tag},
        )


def detect_sensitive_asset_exfil(flow, cfg, detections):
    asset_tag = str(flow.get("asset_tag", "")).strip().lower()
    bytes_out = _safe_int(flow.get("bytes_out"))
    internal = bool(flow.get("is_internal", False))
    if internal:
        return
    if asset_tag in cfg["sensitive_tags"] and bytes_out >= 10 * 1024 * 1024:
        _add_detection(
            detections,
            detection_type="sensitive_asset_exfiltration_risk",
            score=0.93,
            severity="critical",
            reason=f"Sensitive financial asset communicated externally with significant outbound volume ({bytes_out} bytes)",
            recommended_action="block",
            metadata={"asset_tag": asset_tag, "bytes_out": bytes_out, "dst_ip": flow.get("dst_ip")},
        )


def detect_after_hours_external_activity(flow, cfg, detections):
    internal = bool(flow.get("is_internal", False))
    hour = _get_hour(flow)
    if internal or hour is None:
        return
    if hour < cfg["approved_business_hours_start"] or hour > cfg["approved_business_hours_end"]:
        bytes_out = _safe_int(flow.get("bytes_out"))
        score = 0.60 if bytes_out < 5 * 1024 * 1024 else 0.77
        severity = "medium" if score < 0.70 else "high"
        _add_detection(
            detections,
            detection_type="after_hours_external_activity",
            score=score,
            severity=severity,
            reason=f"External activity outside approved financial operating hours at {hour:02d}:00",
            recommended_action="alert",
            metadata={"hour": hour, "bytes_out": bytes_out, "dst_ip": flow.get("dst_ip")},
        )


def detect_tls_anomaly(flow, cfg, detections):
    tls_used = bool(flow.get("tls_used", False))
    ja3_risk = _safe_float(flow.get("ja3_risk_score"))
    sni_present = bool(flow.get("sni_present", True))
    known_vendor = bool(flow.get("known_vendor", False))
    if not tls_used:
        return
    if ja3_risk >= cfg["suspicious_ja3_risk_threshold"] and not known_vendor:
        _add_detection(
            detections,
            detection_type="tls_fingerprint_anomaly",
            score=0.84,
            severity="high",
            reason=f"Suspicious TLS client fingerprint detected (risk={ja3_risk:.2f})",
            recommended_action="alert",
            metadata={"ja3": flow.get("ja3"), "ja3_risk_score": ja3_risk, "dst_ip": flow.get("dst_ip")},
        )
    if tls_used and not sni_present and not known_vendor:
        _add_detection(
            detections,
            detection_type="missing_sni_on_external_tls",
            score=0.71,
            severity="medium",
            reason="External TLS session without SNI in a financial environment",
            recommended_action="alert",
            metadata={"dst_ip": flow.get("dst_ip"), "dst_port": flow.get("dst_port"), "ja3": flow.get("ja3")},
        )


def detect_api_anomaly(flow, cfg, detections):
    api_call = bool(flow.get("api_call", False))
    method = str(flow.get("http_method", "")).upper().strip()
    status_code = _safe_int(flow.get("status_code"))
    unknown_endpoint = bool(flow.get("unknown_endpoint", False))
    schema_violation = bool(flow.get("schema_violation", False))
    auth_failure_burst = bool(flow.get("auth_failure_burst", False))
    if not api_call:
        return
    if unknown_endpoint:
        _add_detection(
            detections,
            detection_type="unknown_api_endpoint",
            score=0.74,
            severity="medium",
            reason="API request to unknown or non-approved endpoint",
            recommended_action="alert",
            metadata={"endpoint": flow.get("endpoint"), "method": method, "status_code": status_code},
        )
    if schema_violation:
        _add_detection(
            detections,
            detection_type="api_schema_violation",
            score=0.88,
            severity="high",
            reason="API payload/schema anomaly in financial service traffic",
            recommended_action="block",
            metadata={"endpoint": flow.get("endpoint"), "method": method},
        )
    if auth_failure_burst:
        _add_detection(
            detections,
            detection_type="api_auth_failure_burst",
            score=0.85,
            severity="high",
            reason="Repeated API authentication failures detected",
            recommended_action="block",
            metadata={"endpoint": flow.get("endpoint"), "method": method, "src_ip": flow.get("src_ip")},
        )


def detect_connection_burst(flow, cfg, detections):
    burst_count = _safe_int(flow.get("burst_conn_count"))
    if burst_count >= cfg["burst_connection_threshold"]:
        _add_detection(
            detections,
            detection_type="burst_connection_pattern",
            score=0.79,
            severity="high",
            reason=f"Abnormally high connection burst detected: {burst_count} connections",
            recommended_action="alert",
            metadata={"burst_conn_count": burst_count, "src_ip": flow.get("src_ip"), "dst_ip": flow.get("dst_ip")},
        )


# -----------------------------------------------------------------------------
# MAIN ENTRY POINT
# -----------------------------------------------------------------------------

def evaluate_financial_sector(flow: Dict[str, Any], custom_cfg: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    cfg = dict(FINANCIAL_DEFAULTS)
    if custom_cfg:
        for key, value in custom_cfg.items():
            cfg[key] = value

    detections: List[Dict[str, Any]] = []

    detect_high_risk_country(flow, cfg, detections)
    detect_blocked_asn(flow, cfg, detections)
    detect_unknown_external_asn(flow, cfg, detections)
    detect_suspicious_port(flow, cfg, detections)
    detect_large_outbound_transfer(flow, cfg, detections)
    detect_sensitive_asset_exfil(flow, cfg, detections)
    detect_after_hours_external_activity(flow, cfg, detections)
    detect_tls_anomaly(flow, cfg, detections)
    detect_api_anomaly(flow, cfg, detections)
    detect_connection_burst(flow, cfg, detections)

    return detections
```

### Step 3 — Policy decision logic

`/sector/financial_policy.py`

```python
from __future__ import annotations
from typing import Any, Dict, List


def decide_financial_action(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not detections:
        return {
            "final_action": "allow",
            "confidence": 0.0,
            "reason": "No financial sector detection triggered",
        }

    max_score = max(d["score"] for d in detections)

    critical_block_types = {
        "blocked_asn",
        "very_large_outbound_transfer",
        "sensitive_asset_exfiltration_risk",
        "api_schema_violation",
        "api_auth_failure_burst",
        "high_risk_country",
    }

    for d in detections:
        if d["type"] in critical_block_types:
            return {
                "final_action": "block",
                "confidence": d["score"],
                "reason": d["reason"],
                "trigger_type": d["type"],
            }

    high_count = sum(1 for d in detections if d["severity"] in {"high", "critical"})
    if high_count >= 2:
        return {
            "final_action": "block",
            "confidence": min(0.95, max_score + 0.05),
            "reason": "Multiple high-severity financial detections combined",
            "trigger_type": "combined_high_risk",
        }

    if max_score >= 0.75:
        return {
            "final_action": "alert",
            "confidence": max_score,
            "reason": "High-confidence financial anomaly detected",
            "trigger_type": "high_confidence_alert",
        }

    return {
        "final_action": "monitor",
        "confidence": max_score,
        "reason": "Low-to-medium financial anomaly detected",
        "trigger_type": "monitoring_required",
    }
```

### Step 4 — Main dispatcher connection

`main.py`

```python
from sector.rules import evaluate_financial_sector
from sector.financial_policy import decide_financial_action


def process_flow(flow: dict, sector_config: dict) -> dict:
    detections = evaluate_financial_sector(flow, sector_config)
    decision = decide_financial_action(detections)

    return {
        "sector": "financial",
        "flow": flow,
        "detections": detections,
        "decision": decision,
    }
```

### Step 5 — Normalized flow object format

Every flow fed to the rule engine must be normalized to this structure before evaluation:

```python
example_flow = {
    "src_ip": "10.10.10.25",
    "dst_ip": "185.200.1.5",
    "dst_host": "unknown-payments-service.example",
    "dst_country": "RU",
    "dst_asn": "AS9009",
    "dst_port": 443,
    "bytes_out": 73400320,
    "bytes_in": 120390,
    "hour": 2,
    "is_internal": False,
    "known_vendor": False,
    "tls_used": True,
    "sni_present": False,
    "ja3": "a1b2c3d4e5",
    "ja3_risk_score": 0.91,
    "api_call": True,
    "http_method": "POST",
    "status_code": 401,
    "unknown_endpoint": True,
    "schema_violation": False,
    "auth_failure_burst": True,
    "burst_conn_count": 102,
    "asset_tag": "payment",
    "app_tag": "payments-api",
}
```

### Step 6 — Demo scenario

`/demo/demo_flows.json` must include:
- Normal banking traffic
- Suspicious outbound to high-risk country
- Abnormal encrypted flow without SNI
- Large exfiltration attempt from tagged sensitive asset

### Step 7 — Required proof output (critical for sales)

The system must produce logs in this exact form:

```
[BLOCKED] Reason: High-risk country communication — Outbound connection to RU
[BLOCKED] Reason: Sensitive financial asset exposure risk — payment asset sent 70MB externally
[ALERT]   Reason: Suspicious encrypted client profile — JA3 risk score 0.91
[ALERT]   Reason: Abnormal connection burst — 102 connections from 10.10.10.25
[MONITOR] Reason: After-hours external activity at 02:00
```

---

## Phase 4 — Government (reuse + adapt)

Change only:
- Rules priorities (external comms, C2 patterns, segmentation violations, critical service misuse)
- Enforcement strictness (stricter blocking, zero-tolerance segmentation breach)
- Dashboard vocabulary (sovereignty, traceability, critical service integrity)

Add:
- Stronger blocking thresholds than Financial
- Segmentation violation logic if available in the collector

Do not rebuild the core. Clone the financial template, swap the sector config and rules module.

---

## Phase 5 — Legal (most subtle)

Key principle: less aggressive blocking, more controlled monitoring and evidence-grade output.

Change only:
- Detection focus shifts to document/file movement and professional secrecy flows
- Enforcement: silent alerts, selective blocking, high-evidence log priority
- Dashboard vocabulary (confidentiality, professional secrecy, behavioral prevention)

Add:
- Silent alert mode (detection logged but not surfaced visibly to avoid operational disruption)
- Sensitive flow tagging for document-adjacent traffic
- Evidence-chain compatible log format

---

## Phase 6 — Packaging

Each sector produces one installable unit:

```
minifw-ai-financial.deb
minifw-ai-government.deb
minifw-ai-legal.deb
```

Each package includes:
- `/core` (shared engine)
- Sector `config.json`
- Sector `rules.py`
- Dashboard with sector wording
- systemd service file

---

## Financial sector — Dashboard wording (CIO level)

### Product title

```
MiniFW-AI Financial
Preventive AI Control Layer for Sensitive Financial Infrastructure
```

### Header subtitle (choose one)

**Strongest institutional:**
Continuously analyzes financial network behavior, detects suspicious encrypted communications, and enforces preventive controls before operational compromise.

**Board-level:**
Designed to protect sensitive financial environments through behavioral detection, outbound risk control, and audit-ready prevention evidence.

**Sales/demo:**
From abnormal encrypted traffic to suspicious outbound data movement, MiniFW-AI Financial turns network visibility into immediate preventive action.

### Value statement

```
Not just traffic monitoring. Preventive control for sensitive financial operations.
```

### Executive KPI block labels

```
Protected Financial Flows
Suspicious Encrypted Sessions
Critical Outbound Alerts
Blocked High-Risk Communications
Sensitive Asset Exposure Attempts
Audit-Ready Security Events
```

### Risk panel

**Title:** Financial Risk Control Overview

**Subtitle:** Real-time visibility on suspicious communications, outbound anomalies, and sensitive asset exposure risk.

### Alert table

**Title:** Priority Detection Events

**Columns:**

| Time | Source Asset | Destination | Detection Type | Severity | Action Taken | Operational Reason |
|---|---|---|---|---|---|---|

### Detection label mapping

| Internal code | Dashboard label |
|---|---|
| `high_risk_country` | High-Risk Country Communication |
| `blocked_asn` | Blocked High-Risk ASN |
| `unknown_external_asn` | Non-Trusted External ASN |
| `suspicious_port` | Suspicious Service Destination |
| `large_outbound_transfer` | Large Outbound Data Movement |
| `very_large_outbound_transfer` | Critical Outbound Data Movement |
| `sensitive_asset_exfiltration_risk` | Sensitive Financial Asset Exposure Risk |
| `after_hours_external_activity` | After-Hours External Activity |
| `tls_fingerprint_anomaly` | Suspicious Encrypted Client Profile |
| `missing_sni_on_external_tls` | Low-Transparency External TLS Session |
| `unknown_api_endpoint` | Non-Approved API Access Attempt |
| `api_schema_violation` | API Structure Violation |
| `api_auth_failure_burst` | Repeated API Authentication Failure |
| `burst_connection_pattern` | Abnormal Connection Burst |

Implementation note — keep these in a constant map, never hardcode in templates:

```python
DETECTION_LABELS = {
    "high_risk_country": "High-Risk Country Communication",
    "blocked_asn": "Blocked High-Risk ASN",
    "unknown_external_asn": "Non-Trusted External ASN",
    "sensitive_asset_exfiltration_risk": "Sensitive Financial Asset Exposure Risk",
    "tls_fingerprint_anomaly": "Suspicious Encrypted Client Profile",
    "missing_sni_on_external_tls": "Low-Transparency External TLS Session",
    "unknown_api_endpoint": "Non-Approved API Access Attempt",
    "api_schema_violation": "API Structure Violation",
    "api_auth_failure_burst": "Repeated API Authentication Failure",
    "burst_connection_pattern": "Abnormal Connection Burst",
    "large_outbound_transfer": "Large Outbound Data Movement",
    "very_large_outbound_transfer": "Critical Outbound Data Movement",
    "after_hours_external_activity": "After-Hours External Activity",
    "suspicious_port": "Suspicious Service Destination",
}
```

### Action label mapping

| Internal | Dashboard |
|---|---|
| `block` | Blocked Immediately |
| `alert` | Escalated for Review |
| `monitor` | Monitored Under Financial Policy |
| — | Restricted Pending Verification |

### Operational reason strings (UI-facing)

```
Connection targeted a high-risk geopolitical zone.
Sensitive financial asset initiated abnormal outbound communication.
Encrypted session profile deviated from approved financial behavior.
API access pattern violated expected financial service structure.
Outbound data volume exceeded normal operating thresholds.
External communication occurred outside approved financial operating hours.
Destination ASN is not trusted for this financial environment.
```

### Executive summary box

**Title:** Executive Security Summary

**Text:**
MiniFW-AI Financial provides a preventive AI control layer for financial infrastructure. It identifies abnormal encrypted behavior, suspicious outbound communications, and sensitive asset exposure risks before they become operational incidents. The system produces evidence-ready logs to support audit, compliance, and executive review.

### CIO benefit boxes (4)

**Financial Integrity**
Detects abnormal communications that may indicate fraud preparation, data exposure, or unauthorized external interaction.

**Encrypted Risk Visibility**
Surfaces suspicious encrypted sessions that traditional perimeter tools often fail to interpret at the behavioral level.

**Outbound Exposure Control**
Identifies and restricts risky outbound traffic before sensitive financial assets are exposed outside approved environments.

**Audit-Ready Evidence**
Produces clear operational reasons and traceable security events for compliance, internal review, and executive reporting.

### Demo screen phrases

```
Abnormal financial outbound behavior detected
Sensitive asset communication blocked before exposure
Suspicious encrypted session escalated
Non-trusted destination restricted under financial policy
Critical outbound movement prevented
Financial API anomaly blocked before transaction risk propagation
```

### Dashboard section order

1. **Header** — product name, subtitle, value statement
2. **Executive KPIs** — 6 metric cards
3. **Financial Risk Control Overview** — risk trend, severity distribution, blocked vs escalated
4. **Priority Detection Events** — main event table
5. **Executive Security Summary** — operational explanation
6. **Policy Status** — financial sector profile active, outbound controls active, sensitive asset protection active, anomaly escalation active

---

## Final objective

At the end of all 6 phases, you do not have 6 products.

You have:

```
1 MiniFW-AI engine
6 sector modules
6 demo packs
6 dashboards (same structure, different wording)
6 .deb installers
```

This is what makes scaling possible, maintenance simple, and the sales story clear.
