# Demo Recovery Procedure — MiniFW-AI Education v2.2.0

## 30-Second Fix (try this first)

Run:
    bash fast_reset.sh

This stops all containers, clears the log volume, and relaunches fresh. The admin
user is re-provisioned automatically. Takes about 30–60 seconds.

---

## Manual Steps (if fast_reset.sh fails)

### Step 1 — Stop all containers

    docker compose -f docker/docker-compose.usb-education.yml down

### Step 2 — Clear the log volume

    docker volume rm minifw_education_logs

### Step 3 — Relaunch

    docker compose -f docker/docker-compose.usb-education.yml up -d

### Step 4 — Confirm dashboard

Wait 30 seconds, then open https://localhost:8447. Login with admin / Education1!

---

## Diagnosing a Stuck Demo

Check container logs:

    docker compose -f docker/docker-compose.usb-education.yml logs engine
    docker compose -f docker/docker-compose.usb-education.yml logs web
    docker compose -f docker/docker-compose.usb-education.yml logs injector

Check container status:

    docker compose -f docker/docker-compose.usb-education.yml ps

Port conflict on 8447:

    lsof -ti:8447 | xargs kill -9 2>/dev/null || true

---

## Pre-Demo Checklist (run the morning of)

Run 30 minutes before the presentation:

- [ ] `docker compose -f docker/docker-compose.usb-education.yml ps` — all 3 containers running
- [ ] Browser opens https://localhost:8447 — login page appears
- [ ] Login with admin / Education1! — dashboard loads
- [ ] Wait 15 seconds — event feed starts populating with allow events
- [ ] Wait 60 seconds — first BLOCK event appears (VPN bypass from student network)

---

## Emergency Fallback

If the demo cannot be recovered before the audience arrives:

1. Open a pre-recorded screen recording and share your screen
2. Video location: (fill in per deployment — USB root or cloud link)

---

## Credentials

| Item          | Value                   |
|---------------|-------------------------|
| Dashboard URL | https://localhost:8447  |
| Username      | admin                   |
| Password      | Education1!             |
| Port          | 8447 (HTTPS via Docker) |
