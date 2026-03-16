# MiniFW-AI — Monitoring Mode Reference

## Overview

MiniFW-AI does not have a dedicated "passive monitor" mode toggle. Monitoring behaviour
is built into the scoring pipeline and operates continuously alongside enforcement.
Every event is scored; events that cross the **monitor threshold** (score ≥ 60) are
logged as `action=monitor` before any block is issued.

---

## Protection States

| State | MLP | YARA | Hard gates | Enforcement |
|-------|-----|------|------------|-------------|
| `BASELINE_PROTECTION` | off | off | on (if conntrack available) | IP deny + ASN deny only |
| `AI_ENHANCED_PROTECTION` | on | on | on (if conntrack available) | Full scoring pipeline |

Set via environment variable:

```
MINIFW_PROTECTION_STATE=baseline    # → BASELINE_PROTECTION
MINIFW_PROTECTION_STATE=ai_enhanced # → AI_ENHANCED_PROTECTION (default)
```

---

## Scoring Thresholds (establishment sector — policy.json)

| Decision | Score range | What it means |
|----------|-------------|----------------|
| `allow`  | 0 – 59      | Traffic passes, event logged |
| `monitor`| 60 – 89     | Traffic passes, event flagged for analyst review |
| `block`  | ≥ 90        | Traffic dropped, IP added to `minifw_block_v4` nftables set |

> **Establishment sector:** no `block_threshold_adjustment` — defaults apply (monitor=60, block=90).
>
> Hospital sector applies `block_threshold_adjustment` that raises the block threshold
> to reduce false positives for clinical traffic.

---

## Signal Weights

| Signal | Weight | Trigger condition |
|--------|--------|-------------------|
| DNS deny-list match | +40 | Domain in `deny_domains.txt` |
| TLS SNI deny match | +35 | SNI hostname in deny list |
| YARA match | up to +35 | Weighted: `yara_score × 35 / 100` |
| MLP threat score | up to +30 | Weighted: `mlp_score × 30 / 100` |
| IP deny-list match | +15 | Client IP in `deny_ips.txt` or Tor exit list |
| ASN deny match | +15 | Client ASN in `deny_asns.txt` |
| Burst / DDoS gate | +10 | QPM ≥ `dns_queries_per_minute_monitor` (120) |
| DNS tunnel score | direct add | Entropy-based tunnel detection |

---

## How to Use Monitor Mode for Investigation

Analyst workflow — no config changes required:

1. **Watch the live event stream:**
   ```bash
   tail -f /opt/minifw_ai/logs/events.jsonl | python3 -m json.tool
   ```
   Filter monitor-only events:
   ```bash
   tail -f /opt/minifw_ai/logs/events.jsonl | grep '"action": "monitor"'
   ```

2. **Dashboard:** `https://localhost:8443/admin/events` — filter by action=monitor.

3. **To observe without blocking** (lower the block threshold temporarily):
   Edit `/opt/minifw_ai/config/policy.json` → `thresholds.block_threshold` → set to `100`.
   Restart: `sudo systemctl restart minifw-ai`
   All scored events will now land as `monitor` instead of `block`.
   Revert when investigation is complete.

---

## Fail-Safe Behaviour

- On `SIGTERM` / `systemctl stop`: daemon exits immediately (no graceful flush).
  Audit log records `daemon_start` but **not** `daemon_stop` on SIGTERM — only on
  `KeyboardInterrupt`. This is a known limitation (see `TODO.md`).
- On restart: policy reloads, nftables set reinitialises, MLP + YARA reload from disk.
  The engine returns to `AI_ENHANCED_PROTECTION` within ~4 seconds.
- On DNS collector failure: engine falls back to `BASELINE_PROTECTION` (IP/ASN filtering
  only) rather than stopping — fail-closed security model.

---

## Enforcement Test Results (2026-03-16)

Test vector:
- Domain: `enforcement-test-casino.minifw-test.local` → dns_denied (+40) + YARA GamblingKeywords (+26)
- Client IP: `192.168.100.40` → ip_denied (+15)
- Total score: **81** → `action=block`

nftables confirmed:
```
table inet minifw {
    set minifw_block_v4 {
        type ipv4_addr
        timeout 1h
        elements = { 192.168.100.40 timeout 1d expires 23h56m30s846ms }
    }
    chain forward {
        ip saddr @minifw_block_v4 drop comment "MiniFW-AI-Blocklist"
    }
}
```
