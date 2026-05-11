# Demo Reliability Standard v1 — Test Report

**Date:** 2026-05-11  
**Standard:** v1  
**Machine:** <!-- describe target machine: OS, CPU, RAM, e.g. "Ubuntu 24.04, Intel i5, 16 GB RAM" -->  
**Network:** Offline (interface disabled during all tests)  
**Tester:** <!-- name -->

---

## Summary

| Demo | Result | Startup Time |
|------|--------|-------------|
| Hospital v3 (Standalone) | PASS / FAIL | ___ seconds |
| Education (Docker, first run) | PASS / FAIL | ___ minutes |
| Education (Docker, repeat run) | PASS / FAIL | ___ seconds |

---

## Hospital Demo (v3 Standalone)

**Launch command:** `cd dist/minifw-ai-usb-v2.2.0v3 && bash run_demo.sh`  
**Dashboard:** http://localhost:8000  
**Credentials:** admin / Hospital1!

| Check | Result | Notes |
|-------|--------|-------|
| Dashboard loads | PASS / FAIL | |
| Events appear (ALLOW + BLOCK) | PASS / FAIL | |
| BLOCK events trigger (deny_domain) | PASS / FAIL | |
| logs/events.jsonl written | PASS / FAIL | |
| logs/audit.jsonl written | PASS / FAIL | |
| No outbound connections (offline) | PASS / FAIL | |
| Restart is clean | PASS / FAIL | |
| Stop is clean (port 8000 released) | PASS / FAIL | |

### Timing

| Milestone | Time |
|-----------|------|
| `bash run_demo.sh` executed | HH:MM:SS |
| Uvicorn ready (`INFO: running on...`) | HH:MM:SS |
| **Elapsed (startup)** | ___ seconds |
| First event appeared on dashboard | HH:MM:SS |
| First BLOCK event | HH:MM:SS |
| Restart (2nd run) elapsed | ___ seconds |

### Screenshots

- `docs/demo-evidence/hospital/01-login.png` — login page
- `docs/demo-evidence/hospital/02-dashboard.png` — main dashboard with Hospital header
- `docs/demo-evidence/hospital/03-block-event.png` — BLOCK event visible in events panel

### Issues Found

<!-- List any failures or unexpected behaviour -->
_None_ / <!-- describe issues -->

---

## Education Demo (Docker)

**Launch command:** `cd dist/minifw-usb-education-v2.2.0 && bash demo.sh`  
**Dashboard:** https://localhost:8447 (accept self-signed TLS warning)  
**Credentials:** admin / Education1!

| Check | Result | Notes |
|-------|--------|-------|
| Dashboard loads | PASS / FAIL | |
| Events appear (ALLOW + BLOCK) | PASS / FAIL | |
| BLOCK events trigger | PASS / FAIL | |
| Injector container running | PASS / FAIL | |
| No containers in Restarting state | PASS / FAIL | |
| No outbound connections (offline) | PASS / FAIL | |
| Restart is clean | PASS / FAIL | |
| Stop is clean (port 8447 released) | PASS / FAIL | |

### Timing

| Milestone | Time |
|-----------|------|
| `bash demo.sh` executed | HH:MM:SS |
| `[minifw-demo] Images loaded.` | HH:MM:SS |
| Dashboard URL shown / services ready | HH:MM:SS |
| **Elapsed (first run, image load)** | ___ minutes ___ seconds |
| First event appeared on dashboard | HH:MM:SS |
| First BLOCK event | HH:MM:SS |
| Restart (2nd run) elapsed | ___ seconds |

### Screenshots

- `docs/demo-evidence/education/01-login.png` — login page (with TLS warning step if needed)
- `docs/demo-evidence/education/02-dashboard.png` — main dashboard with Education header
- `docs/demo-evidence/education/03-block-event.png` — BLOCK event visible in events panel

### Issues Found

<!-- List any failures or unexpected behaviour -->
_None_ / <!-- describe issues -->

---

## Offline Verification

Both demos were tested with the network interface disabled:

```
Interface disabled: sudo ip link set <interface> down
Verified offline:   ping -c 1 8.8.8.8  →  "Network is unreachable"
Verified no external connections during demo:
  ss -tnp | grep -v '127.0.0\|::1'  →  (no output)
```

Result: **PASS / FAIL**

---

## Startup Video

- Recording: `docs/demo-evidence/startup-recording.mp4`
- Covers: Hospital demo cold start → login → first BLOCK event (and/or Education demo)

---

## Overall Verdict

- [ ] Both demos: **READY FOR LIVE PRESENTATION**
- [ ] Issues requiring fix before presentation: _(list here)_

---

*MiniFW-AI Demo Reliability Standard v1 — 2026-05-11*
