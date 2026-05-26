# Demo Recovery Procedure — MiniFW-AI Government v2.2.0

## 30-Second Fix (try this first)

    bash fast_reset.sh

Stops all containers, clears the log volume, relaunches fresh. Takes 30–60 seconds.

---

## Manual Steps

### Step 1 — Stop all containers

    docker compose -f docker/docker-compose.usb-government.yml down

### Step 2 — Clear the log volume

    docker volume rm minifw_government_logs

### Step 3 — Relaunch

    docker compose -f docker/docker-compose.usb-government.yml up -d

### Step 4 — Confirm dashboard

Open https://localhost:8449. Login with admin / Government1!

---

## Diagnosing a Stuck Demo

    docker compose -f docker/docker-compose.usb-government.yml logs engine
    docker compose -f docker/docker-compose.usb-government.yml logs web
    docker compose -f docker/docker-compose.usb-government.yml logs injector
    docker compose -f docker/docker-compose.usb-government.yml ps

Port conflict:

    lsof -ti:8449 | xargs kill -9 2>/dev/null || true

---

## Pre-Demo Checklist

- [ ] All 3 containers running (`docker compose ps`)
- [ ] https://localhost:8449 loads login page
- [ ] Login admin / Government1! — dashboard loads, shows Government sector
- [ ] Wait 15 seconds — allow events populate (data.gov, nist.gov, parliament.gov)
- [ ] Wait 60 seconds — first BLOCK event appears (APT28 C2 from classified segment)

---

## Credentials

| Item          | Value                   |
|---------------|-------------------------|
| Dashboard URL | https://localhost:8449  |
| Username      | admin                   |
| Password      | Government1!            |
| Port          | 8449 (HTTPS via Docker) |
