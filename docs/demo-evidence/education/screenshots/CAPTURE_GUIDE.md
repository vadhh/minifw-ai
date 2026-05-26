# Screenshot Index — Education Demo Evidence
**Scenario:** Westgate Academy — VPN bypass + content filter evasion  
**Total:** 10 screenshots

---

## Complete Sequence

| File | What it shows | Best use |
|------|--------------|---------|
| `01-dashboard-clean-baseline.png` | Main dashboard — Education mode, 0 blocked, 0 alerts, all green | Sales deck opener |
| `02-events-clean-baseline.png` | Security Events — Khan Academy, BBC, Wikipedia all score 18–22 | Prove zero false positives |
| `03-events-social-vpn-monitors.png` | instagram.com + nordvpn.com as MONITOR events, score 40, among clean traffic | Shows AI watching without overblocking |
| `04-events-BLOCK1-vpn-bypass-score75.png` | **BLOCK #1** — nordvpn-bypass.proxy.io score 75, student segment, AI SCORED | **Primary proof screenshot** |
| `05-detail-BLOCK1-vpn-proxy-yara.png` | Event Details modal — score 75, Status: Blocked, YARA trigger visible, student segment | Shows YARA contribution in score breakdown |
| `06-events-BLOCK2-guest-filter-bypass.png` | **BLOCK #2** — filter-bypass.student.io score 75, guest segment, AI SCORED | Second block — different segment, same decision quality |
| `07-detail-BLOCK2-guest-content-filter.png` | Event Details modal — score 75, guest segment, content filter YARA rule | Guest segment label + lower threshold story |
| `08-events-burst-cascade-score100.png` | Burst attack block — score 100, 200 queries cascade, AI SCORED red row | Burst detector fires — score maxed |
| `09-events-gambling-monitor.png` | bet365.com MONITOR score 40 among clean traffic | Shows calibrated monitoring — not blocking social sites outright |
| `10-events-sustained-3blocks-clean.png` | Sustained state — 3+ blocked, Khan Academy/BBC continuing, feed showing mix | Closing shot — clean traffic unaffected |

---

## Recommended Selections by Use Case

**LinkedIn post:**  
→ `04-events-BLOCK1-vpn-bypass-score75.png` + `10-events-sustained-3blocks-clean.png`

**Sales deck (3–4 images):**  
→ `01`, `03`, `04`, `06`

**Safeguarding conversation:**  
→ `05-detail-BLOCK1-vpn-proxy-yara.png` — score breakdown + trace ID visible; auditable decision

**MAT director (one image):**  
→ `04-events-BLOCK1-vpn-bypass-score75.png` — VPN bypass blocked, AI SCORED, one frame

**IT manager:**  
→ `07-detail-BLOCK2-guest-content-filter.png` — guest segment with lower threshold, same AI engine
