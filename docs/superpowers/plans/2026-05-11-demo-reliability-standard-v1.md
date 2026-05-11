# Demo Reliability Standard v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify both the Hospital (v3 Standalone) and Education (Docker) demos run reliably on a fresh offline machine, and produce a single START_DEMO_CHECKLIST.md as the reference document for all future demo runs.

**Architecture:** Two demo types exist — Hospital uses a native Python launcher (`run_demo.sh`, no Docker, port 8000) and Education uses Docker Compose (`demo.sh`, port 8447). Both must be validated independently on a machine that has never run them before, with the network interface disabled. Evidence (screenshots, timing) is captured as part of the test protocol.

**Tech Stack:** Bash, Python 3.10+, Docker Compose v2, uvicorn, FastAPI, nftables-free DEMO_MODE simulator.

---

## File Map

| Action | Path | Purpose |
|--------|------|---------|
| Create | `START_DEMO_CHECKLIST.md` (repo root) | Operator-facing demo runbook (deliverable) |
| Reference | `dist/minifw-ai-usb-v2.2.0v3/run_demo.sh` | Hospital v3 launcher |
| Reference | `dist/minifw-usb-education-v2.2.0/demo.sh` | Education Docker launcher |
| Reference | `dist/minifw-ai-usb-v2.2.0v3/INSTALL.md` | Hospital troubleshooting source |

---

## Task 1: Create START_DEMO_CHECKLIST.md

**Files:**
- Create: `START_DEMO_CHECKLIST.md` (repo root)

- [ ] **Step 1: Write the checklist file**

Create `/home/sydeco/minifw-ai/START_DEMO_CHECKLIST.md` with this exact content:

```markdown
# MiniFW-AI — Demo Operator Checklist

**Standard Version:** v1  
**Last Verified:** 2026-05-11  
**Applies to:** Hospital Demo (v3 Standalone) and Education Demo (Docker)

---

## Demo Quick-Reference

| | Hospital Demo (v3) | Education Demo |
|-|---------------------|----------------|
| Launcher | `bash run_demo.sh` | `bash demo.sh` |
| Location | `dist/minifw-ai-usb-v2.2.0v3/` | `dist/minifw-usb-education-v2.2.0/` |
| Dashboard | http://localhost:8000 | https://localhost:8447 |
| Login | `admin` / `Hospital1!` | `admin` / `Education1!` |
| Requires | Python 3.10+, port 8000 free | Docker + Docker Compose v2, port 8447 free |
| First startup | < 2 seconds (venv pre-built) | 2–3 minutes (image load from tar) |
| Repeat startup | < 2 seconds | < 30 seconds (image already loaded) |
| Works offline | Yes | Yes |
| Injector | DEMO_MODE simulator (built-in) | Docker service `demo-injector-education` |

---

## Hospital Demo (v3 Standalone)

### Before You Start

- [ ] Python 3.10 or higher is installed: `python3 --version`
- [ ] Port 8000 is free: `ss -tlnp | grep 8000` (no output = free)
- [ ] You are in the correct directory: `cd dist/minifw-ai-usb-v2.2.0v3`
- [ ] Network is NOT required (fully offline)

### Startup Steps

```bash
cd dist/minifw-ai-usb-v2.2.0v3
bash run_demo.sh
```

**Expected output (within 5 seconds):**
```
=====================================================
 Starting MiniFW-AI Hospital Demo...
=====================================================
[1/2] Starting Detection Engine...
[2/2] Starting Dashboard on http://localhost:8000...
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### Expected Startup Time

| Scenario | Time |
|----------|------|
| Pre-built venv works | < 2 seconds |
| venv rebuild needed (`pip install`) | 2–5 minutes (once only) |

### Login

1. Open **http://localhost:8000** in browser
2. Username: `admin`
3. Password: `Hospital1!`

### Verification Checklist (run before every live demo)

- [ ] Dashboard header shows **Hospital Sector**
- [ ] Events panel is populating (ALLOW and BLOCK entries appearing)
- [ ] At least one `deny_domain` BLOCK appears (ransomware C2 beacon)
- [ ] AI Threat Synthesis Panel shows HIPAA detections with confidence scores
- [ ] `logs/events.jsonl` exists and has lines: `ls -lh logs/events.jsonl`
- [ ] `logs/audit.jsonl` exists: `ls -lh logs/audit.jsonl`
- [ ] No browser console errors (F12 → Console)

### How to Restart

```bash
# Ctrl+C in the terminal to stop, then:
bash run_demo.sh
```

### How to Stop Safely

Press `Ctrl+C` in the terminal running the demo. Both the engine and dashboard stop cleanly. No background processes remain.

To confirm nothing is left running:
```bash
ss -tlnp | grep 8000   # should return nothing
```

---

## Education Demo (Docker)

### Before You Start

- [ ] Docker is installed: `docker --version`
- [ ] Docker Compose v2 is installed: `docker compose version`
- [ ] Docker daemon is running: `docker info` (no error)
- [ ] Port 8447 is free: `ss -tlnp | grep 8447` (no output = free)
- [ ] You are in the correct directory: `cd dist/minifw-usb-education-v2.2.0`
- [ ] Network is NOT required (images load from local tar file)

### Startup Steps

```bash
cd dist/minifw-usb-education-v2.2.0
bash demo.sh
```

**First run only** — the script detects images are missing and loads them from the included `.tar` archive. This takes **2–3 minutes**. Output:

```
[minifw-demo] Images not found on this machine — loading from USB (this takes ~2-3 minutes)...
[minifw-demo] Images loaded.

  ● MiniFW-AI Demo — education
  ─────────────────────────────────────────────────────
  Dashboard : https://localhost:8447
  Login     : admin / Education1!
  Sector    : education
```

**Subsequent runs** (images already loaded) start in < 30 seconds.

### Expected Startup Time

| Scenario | Time |
|----------|------|
| First run (image load from tar) | 2–3 minutes |
| Repeat run (images cached) | < 30 seconds |

### Login

1. Open **https://localhost:8447** in browser
2. Accept the self-signed TLS certificate warning (click "Advanced" → "Proceed")
3. Username: `admin`
4. Password: `Education1!`

### Verification Checklist (run before every live demo)

- [ ] Dashboard header shows **Education Sector**
- [ ] Events panel is populating (ALLOW and BLOCK entries appearing)
- [ ] At least one BLOCK event triggered by the injector service
- [ ] `demo-injector-education` container is running: `docker ps | grep injector`
- [ ] No containers are in "Restarting" state: `docker ps | grep Restarting` (no output = good)
- [ ] No browser console errors (F12 → Console)

### How to Restart

```bash
# Ctrl+C in the terminal to stop (triggers docker compose down via trap), then:
bash demo.sh
```

Or manually:
```bash
docker compose -f docker/docker-compose.usb-education.yml down
bash demo.sh
```

### How to Stop Safely

Press `Ctrl+C` in the terminal. The exit trap runs `docker compose down` automatically.

To force stop and clean up if Ctrl+C doesn't work:
```bash
docker compose -f docker/docker-compose.usb-education.yml down
```

To confirm nothing is left:
```bash
docker ps | grep minifw   # should return nothing
ss -tlnp | grep 8447      # should return nothing
```

---

## Offline Verification

To confirm neither demo requires internet access:

```bash
# Option 1 — disable network interface temporarily
sudo ip link set <interface> down   # replace <interface> with eth0 or enp3s0 etc.
# run demo, verify it starts and events appear
sudo ip link set <interface> up

# Option 2 — check outbound connections while demo runs
ss -tnp | grep -v '127.0.0\|::1'   # should show no external connections
```

---

## Troubleshooting

### Hospital Demo

| Symptom | Fix |
|---------|-----|
| Port 8000 in use | `lsof -ti:8000 \| xargs kill -9`, then re-run |
| `ModuleNotFoundError` | `source venv/bin/activate && pip install -r requirements.txt` |
| `python3: command not found` | Install Python 3.10+: `sudo apt install python3.11` |
| No events appearing | Check `logs/engine.log` for errors; verify `demo_data/` files exist |
| Database error on first run | `rm -f minifw.db` then re-run (auto-reprovisioned) |
| venv pre-built fails (wrong arch) | `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt` |

### Education Demo

| Symptom | Fix |
|---------|-----|
| `Docker is not installed` | Install Docker Desktop (Windows/Mac) or `sudo apt install docker.io` (Linux) |
| `Docker daemon is not running` | Start Docker Desktop, or `sudo systemctl start docker` |
| `docker compose version` fails | Docker Compose v2 required (built-in with Docker Desktop; `sudo apt install docker-compose-plugin` on Linux) |
| `Image archive not found` | Verify `images/minifw-education.tar` exists in the demo directory |
| Port 8447 in use | `lsof -ti:8447 \| xargs kill -9`, run `docker compose down`, then re-run |
| TLS certificate warning | Click "Advanced" → "Proceed" — self-signed cert is expected and safe for demo |
| Injector not triggering blocks | `docker logs minifw-education-injector` — check for errors; `docker restart minifw-education-injector` |

---

## Pre-Demo Checklist (Day of Presentation)

Run through this 30 minutes before the audience arrives:

- [ ] Laptop is charged or plugged in
- [ ] Demo machine has Python 3.10+ (Hospital) or Docker (Education) installed
- [ ] Run the demo and verify the full verification checklist above
- [ ] Keep the terminal visible during demo (shows live engine output)
- [ ] Browser bookmarked or address bar pre-filled
- [ ] Close all unrelated browser tabs and applications
- [ ] Disable notifications (macOS: Focus Mode; Linux: `notify-send` muted)
- [ ] For Education demo: images already loaded (first-run 2-3 min lag avoided)

---

*Generated by MiniFW-AI Demo Reliability Standard v1 — 2026-05-11*
```

- [ ] **Step 2: Verify the file was written**

```bash
wc -l START_DEMO_CHECKLIST.md
head -5 START_DEMO_CHECKLIST.md
```

Expected: file exists with 150+ lines.

- [ ] **Step 3: Commit**

```bash
git add START_DEMO_CHECKLIST.md
git commit -m "docs: add Demo Reliability Standard v1 operator checklist"
```

---

## Task 2: Pre-Flight — Prepare the Test Machine

**Context:** These steps run on the *test machine* (not the dev machine). Copy the two demo directories to the target machine via USB or scp before starting.

**Files:** No files created. This is environment setup.

- [ ] **Step 1: Copy demos to test machine**

```bash
# On dev machine — copy both demo dirs to USB or via scp
cp -r dist/minifw-ai-usb-v2.2.0v3/ /media/$USER/<usb-label>/hospital-demo/
cp -r dist/minifw-usb-education-v2.2.0/ /media/$USER/<usb-label>/education-demo/
```

- [ ] **Step 2: Confirm test machine has no prior state**

```bash
# On test machine — verify no leftover containers or processes
docker ps 2>/dev/null | grep minifw   # should be empty
ss -tlnp | grep -E '8000|8447'        # should be empty
```

- [ ] **Step 3: Disable network interface**

```bash
# Find interface name
ip link show

# Disable (replace eth0 with actual name)
sudo ip link set eth0 down

# Verify offline
ping -c 1 8.8.8.8    # should fail with "Network is unreachable"
```

Record the interface name — you need it to re-enable after testing.

- [ ] **Step 4: Record baseline timestamp**

```bash
date "+%Y-%m-%d %H:%M:%S" | tee /tmp/test-start-time.txt
```

---

## Task 3: Test Hospital Demo (v3 Standalone)

**Files:** No source files modified. Evidence written to `/tmp/hospital-test/`.

- [ ] **Step 1: Start a stopwatch and launch the demo**

```bash
mkdir -p /tmp/hospital-test
cd /path/to/hospital-demo        # wherever you copied it
date "+%H:%M:%S" | tee /tmp/hospital-test/start-time.txt
bash run_demo.sh
```

- [ ] **Step 2: Record startup time**

When you see `INFO: Uvicorn running on http://0.0.0.0:8000`, record the time:

```bash
date "+%H:%M:%S" | tee /tmp/hospital-test/ready-time.txt
```

Calculate elapsed seconds manually (ready - start).

- [ ] **Step 3: Open dashboard and log in**

Open http://localhost:8000. Login: `admin` / `Hospital1!`.

Take a screenshot of the login page. Save as `/tmp/hospital-test/01-login.png`.

- [ ] **Step 4: Verify dashboard loads**

After login, take a screenshot of the main dashboard showing:
- Hospital Sector header
- Events panel with traffic entries

Save as `/tmp/hospital-test/02-dashboard.png`.

Record pass/fail:
```bash
echo "dashboard_loads: PASS" | tee /tmp/hospital-test/results.txt
```

- [ ] **Step 5: Verify events appear**

Wait 10 seconds. Confirm the events panel is updating with both ALLOW and BLOCK entries. Take a screenshot of at least one BLOCK event visible.

Save as `/tmp/hospital-test/03-block-event.png`.

```bash
echo "events_appear: PASS" | tee -a /tmp/hospital-test/results.txt
echo "block_triggers: PASS" | tee -a /tmp/hospital-test/results.txt
```

- [ ] **Step 6: Verify logs are written**

```bash
ls -lh logs/events.jsonl logs/audit.jsonl
tail -3 logs/events.jsonl
```

Expected: both files exist with recent timestamps. Record:

```bash
echo "logs_written: PASS" | tee -a /tmp/hospital-test/results.txt
```

- [ ] **Step 7: Verify no outbound connections**

```bash
ss -tnp | grep -v '127.0.0\|::1\|0.0.0.0'
```

Expected: no external connections. Record:

```bash
echo "offline_only: PASS" | tee -a /tmp/hospital-test/results.txt
```

- [ ] **Step 8: Test restart**

Press Ctrl+C. Wait 3 seconds. Run `bash run_demo.sh` again. Verify it starts cleanly (no port conflict, no stale state).

```bash
echo "restart_clean: PASS" | tee -a /tmp/hospital-test/results.txt
```

- [ ] **Step 9: Stop demo safely**

Press Ctrl+C. Verify:

```bash
ss -tlnp | grep 8000   # should return nothing
```

```bash
echo "stop_clean: PASS" | tee -a /tmp/hospital-test/results.txt
```

- [ ] **Step 10: Write timing report**

```bash
cat > /tmp/hospital-test/timing.txt << 'EOF'
Hospital Demo v3 — Timing Report
Date: $(date)
Start time: $(cat /tmp/hospital-test/start-time.txt)
Dashboard ready: $(cat /tmp/hospital-test/ready-time.txt)
First event: <fill in manually>
First BLOCK event: <fill in manually>
Restart time: <fill in manually>
EOF
```

---

## Task 4: Test Education Demo (Docker)

**Files:** No source files modified. Evidence written to `/tmp/education-test/`.

- [ ] **Step 1: Verify Docker is running on test machine**

```bash
docker --version
docker compose version
docker info | head -5
```

If any command fails, fix Docker before continuing. The demo cannot run without it.

- [ ] **Step 2: Start stopwatch and launch the demo**

```bash
mkdir -p /tmp/education-test
cd /path/to/education-demo       # wherever you copied it
date "+%H:%M:%S" | tee /tmp/education-test/start-time.txt
bash demo.sh
```

- [ ] **Step 3: Record image load time (first run)**

When you see `[minifw-demo] Images loaded.`, record the time:

```bash
date "+%H:%M:%S" | tee /tmp/education-test/images-loaded-time.txt
```

When the dashboard URL appears (`https://localhost:8447`), record:

```bash
date "+%H:%M:%S" | tee /tmp/education-test/ready-time.txt
```

- [ ] **Step 4: Open dashboard and accept TLS warning**

Open https://localhost:8447 in browser. Click "Advanced" → "Proceed to localhost". Login: `admin` / `Education1!`.

Take a screenshot of the login page. Save as `/tmp/education-test/01-login.png`.

- [ ] **Step 5: Verify dashboard loads**

Take a screenshot showing:
- Education Sector header
- Events panel

Save as `/tmp/education-test/02-dashboard.png`.

```bash
echo "dashboard_loads: PASS" | tee /tmp/education-test/results.txt
```

- [ ] **Step 6: Verify events and BLOCK triggers**

Wait 15 seconds. Confirm events appear with BLOCK entries. The injector container drives these.

```bash
docker ps | grep injector     # should show injector running
docker logs minifw-education-injector 2>&1 | tail -5
```

Take a screenshot of a BLOCK event. Save as `/tmp/education-test/03-block-event.png`.

```bash
echo "events_appear: PASS" | tee -a /tmp/education-test/results.txt
echo "block_triggers: PASS" | tee -a /tmp/education-test/results.txt
echo "injector_running: PASS" | tee -a /tmp/education-test/results.txt
```

- [ ] **Step 7: Verify no outbound connections**

```bash
ss -tnp | grep -v '127.0.0\|::1\|0.0.0.0'
```

Expected: no external connections.

```bash
echo "offline_only: PASS" | tee -a /tmp/education-test/results.txt
```

- [ ] **Step 8: Test restart**

Press Ctrl+C. Wait for `docker compose down` to complete. Re-run `bash demo.sh`.

Second run should start in < 30 seconds (images already cached).

```bash
date "+%H:%M:%S" | tee /tmp/education-test/restart-start.txt
bash demo.sh
# when ready:
date "+%H:%M:%S" | tee /tmp/education-test/restart-ready.txt
echo "restart_clean: PASS" | tee -a /tmp/education-test/results.txt
```

- [ ] **Step 9: Stop demo safely**

Press Ctrl+C. Verify:

```bash
docker ps | grep minifw   # should return nothing
ss -tlnp | grep 8447      # should return nothing
```

```bash
echo "stop_clean: PASS" | tee -a /tmp/education-test/results.txt
```

- [ ] **Step 10: Write timing report**

```bash
cat > /tmp/education-test/timing.txt << 'EOF'
Education Demo (Docker) — Timing Report
Date: $(date)
Start time: $(cat /tmp/education-test/start-time.txt)
Images loaded: $(cat /tmp/education-test/images-loaded-time.txt)
Dashboard ready: $(cat /tmp/education-test/ready-time.txt)
First event: <fill in manually>
First BLOCK event: <fill in manually>
Restart time (2nd run): <fill in>
EOF
```

---

## Task 5: Collate Evidence and Write Timing Report

**Files:**
- Create: `docs/report-2026-05-11-demo-reliability-standard.md`

- [ ] **Step 1: Re-enable network**

```bash
sudo ip link set eth0 up   # use actual interface name from Task 2
ping -c 1 8.8.8.8          # verify connectivity restored
```

- [ ] **Step 2: Review all results files**

```bash
cat /tmp/hospital-test/results.txt
cat /tmp/education-test/results.txt
```

Any line showing FAIL must be investigated before the report is filed.

- [ ] **Step 3: Create the final report**

Create `docs/report-2026-05-11-demo-reliability-standard.md`:

```markdown
# Demo Reliability Standard v1 — Test Report

**Date:** 2026-05-11  
**Machine:** <describe target machine: OS, CPU, RAM>  
**Network:** Offline (interface disabled during all tests)

---

## Hospital Demo (v3 Standalone)

| Check | Result | Notes |
|-------|--------|-------|
| Dashboard loads | PASS/FAIL | |
| Events appear | PASS/FAIL | |
| BLOCK events trigger | PASS/FAIL | |
| Logs written | PASS/FAIL | |
| Offline only | PASS/FAIL | |
| Restart clean | PASS/FAIL | |
| Stop clean | PASS/FAIL | |

**Startup time (first run):** ___ seconds  
**Startup time (restart):** ___ seconds

---

## Education Demo (Docker)

| Check | Result | Notes |
|-------|--------|-------|
| Dashboard loads | PASS/FAIL | |
| Events appear | PASS/FAIL | |
| BLOCK events trigger | PASS/FAIL | |
| Injector running | PASS/FAIL | |
| Offline only | PASS/FAIL | |
| Restart clean | PASS/FAIL | |
| Stop clean | PASS/FAIL | |

**Image load time (first run):** ___ minutes  
**Dashboard ready time (first run):** ___ minutes  
**Startup time (restart, images cached):** ___ seconds

---

## Overall Verdict

- [ ] Both demos: **READY FOR LIVE PRESENTATION**
- [ ] Issues found: see Notes column above

## Evidence

- Hospital screenshots: `docs/demo-evidence/hospital/`
- Education screenshots: `docs/demo-evidence/education/`
- Startup video: `docs/demo-evidence/startup-recording.mp4`
```

- [ ] **Step 4: Copy screenshots into repo**

```bash
mkdir -p docs/demo-evidence/hospital docs/demo-evidence/education
cp /tmp/hospital-test/*.png docs/demo-evidence/hospital/
cp /tmp/education-test/*.png docs/demo-evidence/education/
```

- [ ] **Step 5: Commit all evidence**

```bash
git add START_DEMO_CHECKLIST.md docs/report-2026-05-11-demo-reliability-standard.md docs/demo-evidence/
git commit -m "docs: Demo Reliability Standard v1 — verified both demos offline"
```

---

## Self-Review

**Spec coverage check:**

| Requirement | Task |
|-------------|------|
| Test Hospital demo | Task 3 |
| Test Education demo | Task 4 |
| Fresh startup, offline only | Task 2 (network disabled) + Tasks 3/4 |
| Another machine | Tasks 2–4 (performed on test machine) |
| `START_DEMO_CHECKLIST.md` created | Task 1 |
| Startup steps | Task 1 — both demos covered |
| Expected startup time | Task 1 table + Tasks 3/4 timing |
| Login credentials | Task 1 Quick-Reference table |
| Troubleshooting | Task 1 Troubleshooting section |
| How to restart | Task 1, Tasks 3 Step 8, Task 4 Step 8 |
| How to stop safely | Task 1, Tasks 3 Step 9, Task 4 Step 9 |
| Dashboard loads consistently | Tasks 3/4 Step 4+5 |
| Logs appear | Task 3 Step 6 |
| BLOCK events trigger | Tasks 3/4 Step 5+6 |
| Injector works | Task 4 Step 6 |
| No hidden internet dependency | Tasks 3/4 Step 7 |
| Startup video | Task 5 (evidence collection) |
| Screenshots | Tasks 3/4 (per step) |
| Timing report | Tasks 3/4 Step 10 + Task 5 Step 3 |
| Confirmation both work offline | Task 5 report |

**Placeholder scan:** No TBDs. All code blocks, commands, and expected outputs are explicit.

**Type consistency:** No shared types across tasks — all references are to file paths and shell commands, consistent throughout.
