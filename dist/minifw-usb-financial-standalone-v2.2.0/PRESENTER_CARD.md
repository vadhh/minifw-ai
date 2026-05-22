# ArborCrest Capital — Presenter Card
# MiniFW-AI Financial Sector Executive Demo

**URL:** https://localhost:8443 · **Login:** admin / Finance1!  
**Recovery:** `bash fast_reset.sh` (target: 45 seconds)  
**Full script:** `DEMO_SCRIPT.md`

---

| Phase | T+ | Score | Screen Cue | Say |
|-------|----|-------|------------|-----|
| Normal Operations | 0s | 18–22 | bloomberg.com, reuters, swift.arborcrest.int → ALLOW (green) | "Normal Friday morning at ArborCrest. 300 traders. All systems nominal. Scores 18–22 — well below threshold." |
| Trading Activity | ~30s | 18–22 | oracle-erp, sap, internal-auth → ALLOW | "The ERP subnet is normal too. Every query scored live. Clean baseline." |
| Suspicious Connection | 90s | 55 | `tor-exit-4f2a.net` — MONITOR (amber) | "One workstation just hit a Tor exit node. Not Bloomberg. Score jumps to 55. We're watching." |
| C2 Beacon | 96s | 72 | `c2.trickbot-gate.com` — MONITOR (red) | "Banking trojan phoning home. TrickBot. Score 72 — AI is building its case." |
| ERP Pivot | 102s | 82 | `exfil.payment-collect.io` — MONITOR (red) | "Pivoted to Oracle ERP subnet — client accounts. Score 82, above block threshold. One more signal." |
| Escalation | 108s | 89 | `exfil.payment-collect.io` — MONITOR | "89. Active exfiltration attempt. The AI has seen enough." *(pause)* |
| **★ BLOCK** | 114s | **95** | `exfil.payment-collect.io` — **BLOCK** 🛑 CRITICAL | "**BLOCK. 95. Behavioral chain: Tor → C2 → ERP pivot → exfil. Milliseconds. Automatic.**" |
| Safe Operations | 120s+ | 18–22 | Bloomberg/ERP back to ALLOW · 1 blocked IP | "Trading continues. Data never left. PCI-DSS: compliant. No human intervention." |

---

## Key Numbers for Q&A

| Stat | Value |
|------|-------|
| Block threshold (trading floor) | 80 / 100 |
| Time from first anomaly to BLOCK | ~24 seconds |
| Average financial breach detection time (industry) | 197 days |
| Data exfiltrated | 0 bytes |
| Human interventions required | 0 |
| PCI-DSS status after incident | Compliant |
