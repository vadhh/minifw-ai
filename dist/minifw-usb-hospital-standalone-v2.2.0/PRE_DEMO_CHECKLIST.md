# Pre-Demo Checklist — Hospital Standalone
**Run this 10 minutes before any client demo.**  
**Every box must be ticked before you start.**

---

## 1. Machine State

- [ ] Laptop charged (or plugged in — demo takes ~10 minutes active)
- [ ] Screen brightness set, sleep/lock disabled for the demo duration
- [ ] Browser open and zoomed to comfortable size for the audience
- [ ] Terminal window open in the demo folder

---

## 2. Port Clear

```bash
ss -tlnp | grep 8000
```

- [ ] Output is empty (port 8000 is free)

If occupied: `lsof -ti:8000 | xargs kill -9`

---

## 3. Clean State

```bash
bash fast_reset.sh
```

- [ ] Reset completed without error
- [ ] `logs/events.jsonl` does not exist (or is empty)
- [ ] `minifw.db` is fresh (no stale events from previous run)

---

## 4. Pre-Flight Check

```bash
bash validate_install.sh
```

- [ ] All lines show `[ OK ]` (no `[FAIL]`)
- [ ] YARA rules compile OK
- [ ] Port 8000 confirmed free
- [ ] App imports OK

---

## 5. Demo Running

```bash
bash five_min_demo.sh     # 5-minute version (recommended for executives)
# OR
bash run_demo.sh          # Full 3-minute demo with longer normal-traffic phase
```

- [ ] Terminal shows `Dashboard ready → http://localhost:8000`
- [ ] Browser opens automatically (or open manually)
- [ ] Login succeeds: `admin / Hospital1!`

---

## 6. Dashboard Sanity Check

- [ ] Sector label shows "Hospital"
- [ ] Protection status shows "Active" or "AI Enhanced"
- [ ] First ALLOW event appears within 30 seconds
- [ ] Event score for clinical traffic is < 25 (no false positives)
- [ ] Event feed is auto-refreshing (not static)

---

## 7. Attack Readiness

- [ ] You know when the first BLOCK fires (~38 seconds for 5-min mode)
- [ ] You have `PRESENTER_CARD.md` or `FIVE_MIN_SCRIPT.md` open as reference
- [ ] You know the two key numbers: **mednet threshold 45**, **internal threshold 80**
- [ ] You know the trace ID prefix: **HIPAA-PHI-***

---

## 8. Recovery Ready

- [ ] `fast_reset.sh` is ready to run if demo breaks
- [ ] You know the RECOVERY.md fallback steps (printed or on second screen)
- [ ] If reset fails: `kill $(lsof -ti:8000); rm -f minifw.db logs/events.jsonl; bash five_min_demo.sh`

---

## Go / No-Go

| Check | Status |
|-------|--------|
| Port free | |
| Clean state | |
| Validate passes | |
| Dashboard loads | |
| First event appears | |

**All five green = GO.**  
Any red = fix before client enters the room.
