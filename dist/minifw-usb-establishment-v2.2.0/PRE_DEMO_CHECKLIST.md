# Pre-Demo Checklist — Establishment Sector (Docker)
**Run this 10 minutes before any client demo.**

---

## 1. Machine State

- [ ] Docker Engine running: `docker info >/dev/null 2>&1 && echo OK`
- [ ] Laptop charged / plugged in
- [ ] Browser open, sleep/lock disabled
- [ ] Terminal open in `minifw-usb-establishment-v2.2.0/`

---

## 2. Port Clear

```bash
ss -tlnp | grep 8444
```

- [ ] Port 8444 is free

If occupied: `lsof -ti:8444 | xargs kill -9`

---

## 3. Docker Image Loaded

```bash
docker images | grep minifw-sme
```

- [ ] Image appears in the list

If missing: `docker load -i images/minifw-sme.tar` (takes ~2 minutes)

---

## 4. Clean State

```bash
bash fast_reset.sh
```

- [ ] Reset completed
- [ ] Dashboard reachable at `https://localhost:8444`

---

## 5. Dashboard Sanity Check

Open `https://localhost:8444` (accept self-signed cert)  
Login: `admin / SME_Demo1!`

- [ ] Sector label shows "Establishment" or "SME"
- [ ] Protection status shows "Active"
- [ ] Event feed populates within 60 seconds

---

## 6. Attack Readiness

- [ ] You know the dual-threshold story: **office 80 = MONITOR on score 40**, **guest 40 = BLOCK on score 40**
- [ ] You know the trace ID prefix: **SME-EST-***
- [ ] Key story: same domain, same score (40) → different outcome on each segment
- [ ] Key story: ransomware C2 on office LAN = MONITOR (staff still working)
- [ ] `PRESENTER_CARD.md` open as reference

---

## 7. Recovery

- [ ] `bash fast_reset.sh` ready to run
- [ ] Docker volume name if manual reset needed: `minifw_sme_logs`
  ```bash
  docker compose down && docker volume rm minifw_sme_logs && docker compose up -d
  ```

---

## Go / No-Go

| Check | Status |
|-------|--------|
| Docker running | |
| Port 8444 free | |
| Image loaded | |
| Clean state | |
| Dashboard loads | |

**All five green = GO.**
