# Demo Recovery Procedure — MiniFW-AI Establishment v2.2.0

## 30-Second Fix

    bash fast_reset.sh

---

## Manual Steps

    docker compose -f docker/docker-compose.usb-sme.yml down
    docker volume rm minifw_sme_logs
    docker compose -f docker/docker-compose.usb-sme.yml up -d

## Diagnosing

    docker compose -f docker/docker-compose.usb-sme.yml logs engine
    docker compose -f docker/docker-compose.usb-sme.yml logs injector
    docker compose -f docker/docker-compose.usb-sme.yml ps
    lsof -ti:8444 | xargs kill -9 2>/dev/null || true

## Pre-Demo Checklist

- [ ] All 3 containers running
- [ ] https://localhost:8444 loads login page
- [ ] Login admin / SME_Demo1! — dashboard shows Establishment sector
- [ ] 15 seconds: Office365 allow event appears
- [ ] 30 seconds: phishing monitor event appears
- [ ] 60 seconds: guest BLOCK event appears

## Credentials

| Item | Value |
|------|-------|
| Dashboard URL | https://localhost:8444 |
| Username | admin |
| Password | SME_Demo1! |
| Port | 8444 (HTTPS) |
