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
- [ ] You are in the correct directory (paths below are relative to the repo root — if in doubt, use the full path): `cd /path/to/minifw-ai/dist/minifw-ai-usb-v2.2.0v3`
- [ ] Network is NOT required (fully offline)

### Startup Steps

1. Open a terminal
2. Navigate to the demo directory:
   ```bash
   cd dist/minifw-ai-usb-v2.2.0v3
   ```
3. Launch the demo:
   ```bash
   bash run_demo.sh
   ```
4. Wait for the uvicorn ready message (shown below), then open your browser. To confirm the engine also started, check: `cat logs/engine.log | head -5`

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
| venv rebuild needed (`pip install`) | 2–5 minutes (once only per machine) |

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
# Press Ctrl+C in the terminal to stop, then:
bash run_demo.sh
```

### How to Stop Safely

Press `Ctrl+C` in the terminal running the demo. Both the engine and dashboard stop cleanly.

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
- [ ] You are in the correct directory (paths below are relative to the repo root — if in doubt, use the full path): `cd /path/to/minifw-ai/dist/minifw-usb-education-v2.2.0`
- [ ] Network is NOT required (images load from local tar file)

### Startup Steps

1. Confirm Docker Desktop is open (or Docker daemon is running)
2. Open a terminal
3. Navigate to the demo directory:
   ```bash
   cd dist/minifw-usb-education-v2.2.0
   ```
4. Launch the demo:
   ```bash
   bash demo.sh
   ```
5. Wait — first run loads images (~2–3 min). Watch for the ready message, then open your browser

**First run only** — images load from the included `.tar` archive (~2–3 minutes). Output:

```
[minifw-demo] Images not found on this machine — loading from USB (this takes ~2-3 minutes)...
[minifw-demo] Images loaded.

  ● MiniFW-AI Demo — education
  ─────────────────────────────────────────────────────
  Dashboard : https://localhost:8447
  Login     : admin / Education1!
  Sector    : education
```

**Subsequent runs** start in < 30 seconds (images already cached in Docker).

### Expected Startup Time

| Scenario | Time |
|----------|------|
| First run (image load from tar) | 2–3 minutes |
| Repeat run (images cached) | < 30 seconds |

### Login

1. Open **https://localhost:8447** in browser
2. Accept the self-signed TLS certificate warning: click "Advanced" → "Proceed to localhost"
3. Username: `admin`
4. Password: `Education1!`

### Verification Checklist (run before every live demo)

- [ ] Dashboard header shows **Education Sector**
- [ ] Events panel is populating (ALLOW and BLOCK entries appearing)
- [ ] At least one BLOCK event triggered by the injector service
- [ ] Injector container is running: `docker ps | grep injector`
- [ ] No containers in "Restarting" state: `docker ps` (check Status column)
- [ ] No browser console errors (F12 → Console)

### How to Restart

```bash
# Press Ctrl+C in the terminal to stop, then run:
docker compose -f docker/docker-compose.usb-education.yml down
bash demo.sh
```

### How to Stop Safely

Press `Ctrl+C` in the terminal. The demo stops, but containers are NOT automatically removed — run the cleanup command before restarting:

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
# Disable network interface (replace eth0 with your interface: `ip link show`)
sudo ip link set eth0 down

# Run the demo — it must start and generate events without internet
cd dist/minifw-ai-usb-v2.2.0v3 && bash run_demo.sh   # or: cd dist/minifw-usb-education-v2.2.0 && bash demo.sh

# While demo runs, verify no external connections:
ss -tnp | grep -v '127.0.0\|::1'   # should return nothing external

# Re-enable when done
sudo ip link set eth0 up
```

---

## Troubleshooting

### Hospital Demo

| Symptom | Fix |
|---------|-----|
| Port 8000 in use | `lsof -ti:8000 \| xargs kill -9`, then re-run |
| `ModuleNotFoundError` | `source venv/bin/activate && pip install -r requirements.txt` |
| `python3: command not found` | Install: `sudo apt install python3.11` (Ubuntu/Debian) |
| No events appearing | Check `logs/engine.log`; verify `demo_data/` files exist |
| Database error on first run | `rm -f minifw.db` then re-run (auto-reprovisioned) |
| venv pre-built fails (wrong arch/OS) | `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt` |

### Education Demo

| Symptom | Fix |
|---------|-----|
| `Docker is not installed` | Install Docker Desktop (Win/Mac) or `sudo apt install docker.io` (Linux) |
| `Docker daemon is not running` | Open Docker Desktop, or `sudo systemctl start docker` |
| `docker compose version` fails | `sudo apt install docker-compose-plugin` (Linux) or update Docker Desktop |
| `Image archive not found` | Verify `images/minifw-education.tar` exists in the demo directory |
| Port 8447 in use | `lsof -ti:8447 \| xargs kill -9`, run `docker compose down`, re-run |
| TLS certificate warning | Click "Advanced" → "Proceed" — self-signed cert is expected and safe |
| Injector not triggering blocks | `docker logs minifw_education_injector`; then `docker restart minifw_education_injector` |
| Container in Restarting loop | `docker compose down` then `bash demo.sh` to start fresh |

---

## Pre-Demo Checklist (Day of Presentation)

Run this 30 minutes before the audience arrives:

- [ ] Laptop is charged or plugged in
- [ ] Demo machine has Python 3.10+ (Hospital) or Docker (Education) installed and working
> **If presenting only one demo today:** complete only the checklist for the demo you will show.

- [ ] **Hospital demo:** Run it once and walk through the "Verification Checklist" in the Hospital section above
- [ ] **Education demo:** Run it once and walk through the "Verification Checklist" in the Education section above
- [ ] Terminal is visible during demo (shows live engine output — use it as a talking point)
- [ ] Browser bookmarked or address bar pre-filled
- [ ] All unrelated browser tabs and applications closed
- [ ] Notifications disabled (macOS: Focus Mode; Linux: `notify-send` muted)
- [ ] For Education demo: images already loaded in Docker (avoid 2-3 min first-run delay)

---

*MiniFW-AI Demo Reliability Standard v1 — 2026-05-11*
