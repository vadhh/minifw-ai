# System Stats — Government Demo
**Captured:** 2026-05-26  
**Package:** minifw-usb-government-v2.2.0

---

## Runtime Metrics

| Metric | Value |
|--------|-------|
| Container count | 3 (engine, web, injector) |
| CPU (idle) | < 1% per container |
| RAM (all containers) | ~280 MB |
| Port | 8449 (HTTPS) |
| Log retention (production) | 365 days (policy.json) |
| Burst threshold (government) | 40 QPM — strictest in suite |
| Enforcement IP timeout | 604800 seconds (7 days) — blocks persist across restarts |

## Event Counters (per demo loop)

| Counter | Value |
|---------|-------|
| Allow | ~4 |
| Monitor | ~1 (leak site) |
| Block | 3 (APT C2, Tor relay, burst) |
| Near miss (allow below monitor threshold) | 1 (phishing portal) |

## Government-Specific Policy Differences vs Other Sectors

| Feature | Government | Financial | Hospital |
|---------|-----------|-----------|---------|
| Classified segment threshold | 70 | — | — |
| Burst QPM threshold | 40 | 50 | 50 |
| IP block timeout | 7 days | 1 day | 1 day |
| Log retention | 365 days | 90 days | 90 days |
| Geo-IP ASN weight | 20 | 15 | 15 |
