# Demo Recovery Procedure — MiniFW-AI Hospital v3 Standalone

## 30-Second Fix (try this first)

Run:
    bash recover_demo.sh

This script automatically: kills stale processes on port 8000, resets the database if
corrupted, relaunches the demo, and runs HEALTHCHECK.sh to confirm recovery.

---

## Manual Steps (if recover_demo.sh fails)

### Step 1 — Kill port conflict

Find and kill whatever is using port 8000:

    lsof -ti:8000 | xargs kill -9

Confirm the port is now free:

    lsof -i:8000
    # Expected: no output

### Step 2 — Kill orphaned engine process

    pgrep -f minifw_ai/main.py | xargs kill
    pgrep -f "uvicorn.*app.web.app" | xargs kill

### Step 3 — Reset the database

If the web app is throwing a database error:

    cd dist/minifw-ai-usb-v2.2.0v3
    rm -f minifw.db

The database is auto-recreated with default credentials on next start.

### Step 4 — Full wipe and restart

If all else fails:

    cd dist/minifw-ai-usb-v2.2.0v3
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    pgrep -f minifw_ai | xargs kill 2>/dev/null || true
    rm -f minifw.db logs/events.jsonl
    source venv/bin/activate
    bash run_demo.sh

---

## Pre-Demo Checklist (run the morning of)

Run this 30 minutes before the presentation:

    bash HEALTHCHECK.sh

All checks must pass. Also confirm manually:

- [ ] bash HEALTHCHECK.sh — all checks pass
- [ ] Browser opens http://localhost:8000 — login page appears, no errors
- [ ] Login with admin / Hospital1! — dashboard loads
- [ ] Wait ~2 minutes — first BLOCK event appears in the event feed
- [ ] AI Threat Synthesis panel shows a blocked domain + HIPAA reason

---

## Emergency Fallback

If the demo cannot be recovered before the audience arrives:

1. Open a pre-recorded demo video (screen recording) and share your screen
2. Location of video: (fill in per deployment — e.g., USB drive root or cloud link)

---

## Credentials

| Item          | Value                  |
|---------------|------------------------|
| Dashboard URL | http://localhost:8000  |
| Username      | admin                  |
| Password      | Hospital1!             |
| Port          | 8000 (HTTP)            |
