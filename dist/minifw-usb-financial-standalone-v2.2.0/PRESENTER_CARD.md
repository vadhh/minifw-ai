# ArborCrest Capital — Presenter Card
# MiniFW-AI Financial Sector Executive Demo

**URL:** https://localhost:8443 · **Login:** admin / Finance1!  
**Recovery:** `bash fast_reset.sh` (target: 45 seconds)  
**Full script:** `DEMO_SCRIPT.md`

---

| Phase | T+ | Score | Screen Cue | Say |
|-------|----|-------|------------|-----|
| Normal Operations | 0s | 18–22 | bloomberg.com, reuters, swift.arborcrest.int → ALLOW (green) | "Normal Friday morning at ArborCrest. 300 traders. All systems nominal. Scores 18–22 — well below threshold." |
| Trading Activity | ~30s | 18–22 | oracle-erp, sap, internal-auth → ALLOW | "ERP subnet is normal too. Clean baseline." |
| Suspicious Connection | 90s | 55 | `tor-exit-4f2a.net` — MONITOR (amber) · `10.50.0.1` | "One workstation just hit a Tor exit node. Not Bloomberg. Score 55. Watching." |
| C2 Beacon | 96s | 72 | `c2.trickbot-gate.com` — MONITOR (red) | "Banking trojan phoning home. TrickBot. Score 72 — AI building its case." |
| ERP Pivot | 102s | 82 | `exfil.payment-collect.io` — MONITOR | "Pivoted to Oracle ERP — client accounts. Score 82. One more signal." |
| Escalation | 108s | 89 | `exfil.payment-collect.io` — MONITOR | "89. Active exfil. The AI has seen enough." *(pause)* |
| **★ BLOCK 1** | 114s | **95** | `exfil.payment-collect.io` — **BLOCK** CRITICAL | "**BLOCK. 95. Trading floor attacker stopped. Automatic.**" |
| Recovery | 120–150s | 18–22 | All ALLOW · `10.50.0.1` blocked | "Trading continues. But watch — the system doesn't relax." |
| Credential Harvest | 150s | 58 | `harvest.cred-stealer.net` — MONITOR · `192.168.1.50` | "Different machine. Different subnet. Already inside — ERP network. Credential harvesting tool. Score 58." |
| SWIFT Probe | 156s | 74 | `api.swift-intercept.cc` — MONITOR | "Probing the SWIFT gateway. Wire transfer intercept attempt. Score 74." |
| Wire Intercept | 162–168s | 84→91 | `drop.wire-redirect.io` — MONITOR | "84. 91. Trying to redirect live settlement transactions." *(pause)* |
| **★ BLOCK 2** | 174s | **97** | `drop.wire-redirect.io` — **BLOCK** CRITICAL | "**BLOCK. 97. SWIFT fraud stopped. Two attackers. Two subnets. Both blocked. Zero humans.**" |
| Sustained Safe | 180s+ | 18–22 | All ALLOW · 2 blocked IPs | "ArborCrest clean. Two breach attempts. Zero data lost. PCI-DSS: compliant." |

---

## Key Numbers for Q&A

| Stat | Value |
|------|-------|
| Block threshold (trading floor) | 80 / 100 |
| Time from first anomaly to BLOCK (each attacker) | ~24 seconds |
| Simultaneous attackers detected | 2 |
| Attack vectors covered | External breach + insider/supply chain |
| Average financial breach detection time (industry) | 197 days |
| Data exfiltrated | 0 bytes |
| Human interventions required | 0 |
| PCI-DSS status after both incidents | Compliant |
