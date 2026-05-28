# MiniFW-AI — Financial Sector Executive Demo v2.2.0

**PCI-DSS compliant AI-powered behavioral firewall — standalone demo package**

---

## What This Demonstrates

MiniFW-AI monitors DNS traffic from your financial network in real time. It combines a feed-matching engine, machine learning inference, and YARA pattern scanning to detect and block threats before they exfiltrate data.

This demo shows:

1. **Normal trading floor traffic** — Bloomberg, Reuters, SWIFT, internal DNS (first ~60 seconds)
2. **Attack detection** — Banking trojan C2 beacon, card data exfiltration probe, PCI boundary violation detected from `10.50.0.1` on the trading floor subnet
3. **Automatic BLOCK** — Score exceeds the trading segment threshold (80/100) → IP blocked, audit trail written, dashboard alert fired

No Docker. No root at runtime. One command.

---

## Quick Start

```bash
bash setup_tls.sh    # once per machine
bash run_demo.sh     # starts demo + opens browser
```

Login: `admin / Finance1!` at `https://localhost:8443`

---

## Package Layout

```
run_demo.sh          ← one-button entry point
setup_tls.sh         ← one-time TLS setup
teardown_demo.sh     ← post-meeting cleanup
HEALTHCHECK.sh       ← pre-meeting verification
recover_demo.sh      ← fix stale processes
INSTALL.md           ← full setup guide

config/policy.json   ← PCI-DSS enforcement thresholds
demo_data/           ← synthetic traffic patterns
scheduler/           ← deterministic BLOCK scheduler (T+75s)
app/                 ← MiniFW engine + web dashboard
```

---

## Sector Configuration

| Setting | Value |
|---|---|
| Sector | Finance (`PRODUCT_MODE=minifw_financial`) |
| Trading block threshold | 80/100 |
| Compliance | PCI-DSS |
| Tor/anonymizer blocking | Enabled |
| TLS minimum | 1.2 |

---

## After the Demo

```bash
bash teardown_demo.sh
```
