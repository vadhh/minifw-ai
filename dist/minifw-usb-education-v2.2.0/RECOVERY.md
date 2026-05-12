# Demo Recovery Procedure — MiniFW-AI Education Docker

## 30-Second Fix (try this first)

```bash
bash recover_demo.sh
```

This script automatically: stops stale containers, frees port 8447, relaunches the stack,
and runs HEALTHCHECK.sh to confirm recovery.

---

## Manual Steps (if recover_demo.sh fails)

### Step 1 — Stop all demo containers

```bash
docker compose -f docker/docker-compose.usb-education.yml down --remove-orphans
```

### Step 2 — Kill port conflict

```bash
lsof -ti:8447 | xargs -r kill -9
```

### Step 3 — Restart from scratch

```bash
docker compose -f docker/docker-compose.usb-education.yml up -d
# Wait 30s, then open https://localhost:8447
```

### Step 4 — Full wipe and restart

If a container is stuck in restart loop:

```bash
docker compose -f docker/docker-compose.usb-education.yml down -v --remove-orphans
docker compose -f docker/docker-compose.usb-education.yml up -d
```

The `-v` flag removes the named volume (logs) — clears audit log and DB. Demo starts fresh.

### Step 5 — Reload images

If containers fail to start with image-not-found errors:

```bash
docker load -i images/minifw-education.tar
docker compose -f docker/docker-compose.usb-education.yml up -d
```

---

## Pre-Demo Checklist (run the morning of)

```bash
bash setup_tls.sh   # one-time per machine — skip if already done
bash HEALTHCHECK.sh
```

All checks must pass. Also confirm manually:

- [ ] `bash HEALTHCHECK.sh` — all checks pass
- [ ] Browser opens `https://localhost:8447` — green padlock, no security warning
- [ ] Login with `admin / Education1!` — dashboard loads
- [ ] Within 60 seconds — first BLOCK event appears in event feed
- [ ] AI Threat Synthesis panel shows a blocked domain + SafeSearch / education policy reason

---

## TLS / Browser Warning

If browser shows "Your connection is not private":

```bash
bash setup_tls.sh
# Then restart demo
docker compose -f docker/docker-compose.usb-education.yml down
docker compose -f docker/docker-compose.usb-education.yml up -d
```

For Firefox specifically: open `about:preferences#privacy` → View Certificates →
Authorities → Import → select `docker/certs/minifw-demo-ca.crt` → trust for websites.

---

## Emergency Fallback

If the demo cannot be recovered before the audience arrives:

1. Open a pre-recorded demo video and share your screen
2. Location of video: *(fill in per deployment — e.g., USB drive root or cloud link)*

---

## Credentials

| Item | Value |
|------|-------|
| Dashboard URL | https://localhost:8447 |
| Username | admin |
| Password | Education1! |
| Port | 8447 (HTTPS) |
