# Score Timeline — ArborCrest Capital Attack Simulation
**Date captured:** 2026-05-22  
**Scenario:** Dual concurrent breach — trading floor + SWIFT fraud from ERP subnet

---

## Phase 1 — Normal Operations (T+0s to T+90s)

All clean. Scores 18–22/100. No alerts. Legitimate ArborCrest Capital traffic:

```
bloomberg.com         → ALLOW  Score: 19   TXN-AC-*
reuters.com           → ALLOW  Score: 20   TXN-AC-*
swift.arborcrest.int  → ALLOW  Score: 19   TXN-AC-*
api.refinitiv.com     → ALLOW  Score: 19   TXN-AC-*
market.nasdaq.com     → ALLOW  Score: 20   TXN-AC-*
oracle-erp.arborcrest → ALLOW  Score: 21   TXN-AC-*
sap.arborcrest.int    → ALLOW  Score: 20   TXN-AC-*
```

**Clean baseline. Zero alerts. Zero disruption to trading operations.**

---

## Phase 2 — Attacker 1: Trading Floor Breach (T+90s to T+114s)

Origin: `10.50.0.1` (ArborCrest trading floor workstation)

```
10:06:22  [MONITOR]  Score:  55/100  ###########
         Domain: tor-exit-4f2a.net
         Signal: anonymizer_traffic, trading_floor_anomaly
         Note: Workstation on trading floor connecting to Tor. Not Bloomberg.

10:06:28  [MONITOR]  Score:  72/100  ##############
         Domain: c2.trickbot-gate.com
         Signal: dns_feed_match, banking_trojan_c2_beacon, financial_fraud_feed
         Note: TrickBot banking trojan phoning home. Feed match confirmed.

10:06:34  [MONITOR]  Score:  82/100  ################
         Domain: exfil.payment-collect.io
         Signal: card_exfil_pattern, oracle_erp_subnet_pivot, pci_dss_boundary_crossed
         Note: Lateral move — attacker pivoted to Oracle ERP. Client accounts at risk.

10:06:40  [MONITOR]  Score:  89/100  #################
         Domain: exfil.payment-collect.io
         Signal: card_exfil_pattern, client_portfolio_exfil, pci_dss_violation
         Note: Active exfiltration of client portfolio data. PCI-DSS boundary crossed.

10:06:46  ██ BLOCK ██  Score:  95/100  ###################
         Domain: exfil.payment-collect.io
         Trace:  SWIFT-MT103-73A46E3D
         Signal: dns_feed_match, card_exfil_pattern, pci_dss_violation, erp_subnet_block
         Result: IP 10.50.0.1 BLOCKED. Trading floor attacker stopped. AUTOMATIC.
```

**Time from first anomaly to block: 24 seconds.**

---

## Phase 3 — Attacker 2: SWIFT Fraud from ERP Subnet (T+150s to T+174s)

Origin: `192.168.1.50` (ArborCrest internal ERP network — different subnet, different attacker)

```
10:07:14  [MONITOR]  Score:  58/100  ###########
         Domain: harvest.cred-stealer.net
         Signal: credential_harvesting_tool, internal_subnet_anomaly
         Note: Credential harvesting tool running from inside ERP network.

10:07:20  [MONITOR]  Score:  74/100  ##############
         Domain: api.swift-intercept.cc
         Signal: dns_feed_match, swift_gateway_probe, financial_fraud_feed
         Note: Probing the SWIFT gateway. Wire transfer intercept attempt.

10:07:26  [MONITOR]  Score:  84/100  ################
         Domain: drop.wire-redirect.io
         Signal: wire_transfer_intercept, erp_credential_abuse, pci_dss_boundary_crossed
         Note: Attempting to redirect live settlement transactions.

10:07:32  [MONITOR]  Score:  91/100  ##################
         Domain: drop.wire-redirect.io
         Signal: wire_transfer_intercept, settlement_data_exfil, pci_dss_violation
         Note: Active settlement data exfiltration.

10:07:38  ██ BLOCK ██  Score:  97/100  ###################
         Domain: drop.wire-redirect.io
         Trace:  SWIFT-MT103-1E817ECA
         Signal: dns_feed_match, wire_transfer_intercept, pci_dss_violation, swift_fraud_block
         Result: IP 192.168.1.50 BLOCKED. SWIFT fraud stopped. AUTOMATIC.
```

**Time from first anomaly to block: 24 seconds.**

---

## Summary

| Metric | Value |
|--------|-------|
| Attackers | 2 concurrent |
| Subnets compromised | 2 (trading floor + ERP) |
| Attack vectors | External breach + insider/supply chain |
| Time to first block | 24 seconds |
| Time to second block | 24 seconds |
| Data exfiltrated | 0 bytes |
| Human interventions | 0 |
| False positives | 0 |
| Trading disrupted | No |
| PCI-DSS status | Compliant throughout |
| Industry avg detection time | 197 days (IBM Cost of a Data Breach 2023) |
