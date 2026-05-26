# Demo Recovery Procedure — MiniFW-AI Legal v2.2.0

## 30-Second Fix

    bash fast_reset.sh

---

## Manual Steps

    docker compose -f docker/docker-compose.usb-legal.yml down
    docker volume rm minifw_legal_logs
    docker compose -f docker/docker-compose.usb-legal.yml up -d

## Diagnosing

    docker compose -f docker/docker-compose.usb-legal.yml logs engine
    docker compose -f docker/docker-compose.usb-legal.yml logs injector
    docker compose -f docker/docker-compose.usb-legal.yml ps
    lsof -ti:8448 | xargs kill -9 2>/dev/null || true

## Pre-Demo Checklist

- [ ] All 3 containers running
- [ ] https://localhost:8448 loads login page
- [ ] Login admin / Legal1! — dashboard shows Legal sector
- [ ] 15 seconds: allow events from Westlaw/LexisNexis appear
- [ ] 60 seconds: first BLOCK event (Tor relay from client room)

## Credentials

| Item | Value |
|------|-------|
| Dashboard URL | https://localhost:8448 |
| Username | admin |
| Password | Legal1! |
| Port | 8448 (HTTPS) |
