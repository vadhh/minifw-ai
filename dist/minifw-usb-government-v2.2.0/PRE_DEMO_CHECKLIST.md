# Pre-Demo Checklist — Government Sector (Docker)
**Run this 10 minutes before any client demo.**

---

## 1. Machine State

- [ ] Docker Engine running: `docker info >/dev/null 2>&1 && echo OK`
- [ ] Laptop charged / plugged in
- [ ] Browser open, sleep/lock disabled
- [ ] Terminal open in `minifw-usb-government-v2.2.0/`

---

## 2. Port Clear

```bash
ss -tlnp | grep 8449
```

- [ ] Port 8449 is free

If occupied: `lsof -ti:8449 | xargs kill -9`

---

## 3. Docker Image Loaded

```bash
docker images | grep minifw-government
```

- [ ] Image `minifw-government` appears in the list

If missing: `docker load -i images/minifw-government.tar` (takes ~2 minutes)

---

## 4. Clean State

```bash
bash fast_reset.sh
```

- [ ] Reset completed
- [ ] Dashboard reachable at `https://localhost:8449`

---

## 5. Dashboard Sanity Check

Open `https://localhost:8449` (accept self-signed cert)  
Login: `admin / Government1!`

- [ ] Sector label shows "Government"
- [ ] Protection status shows "Active"
- [ ] Event feed populates within 60 seconds
- [ ] Normal allow traffic visible (gov.uk, etc.)

---

## 6. Attack Readiness

- [ ] You know: **classified threshold 70**, **internal threshold 45**, **guest threshold 35**
- [ ] You know the trace ID prefix: **GOV-SOV-***
- [ ] You know the story: APT28 C2 beacon BLOCK (score 100), Tor relay BLOCK (score 75)
- [ ] You know the near-miss: score 40 on internal = MONITOR (threshold 45 — not blocked)
- [ ] `PRESENTER_CARD.md` open as reference

---

## 7. Recovery

- [ ] `bash fast_reset.sh` ready to run
- [ ] Docker volume name if manual reset needed: `minifw_government_logs`
  ```bash
  docker compose down && docker volume rm minifw_government_logs && docker compose up -d
  ```

---

## Go / No-Go

| Check | Status |
|-------|--------|
| Docker running | |
| Port 8449 free | |
| Image loaded | |
| Clean state | |
| Dashboard loads | |

**All five green = GO.**
