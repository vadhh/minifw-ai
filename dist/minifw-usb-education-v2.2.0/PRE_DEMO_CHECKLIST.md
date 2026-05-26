# Pre-Demo Checklist — Education Sector (Docker)
**Run this 10 minutes before any client demo.**

---

## 1. Machine State

- [ ] Docker Engine running: `docker info >/dev/null 2>&1 && echo OK`
- [ ] Laptop charged / plugged in
- [ ] Browser open, sleep/lock disabled
- [ ] Terminal open in `minifw-usb-education-v2.2.0/`

---

## 2. Port Clear

```bash
ss -tlnp | grep 8447
```

- [ ] Port 8447 is free

If occupied: `lsof -ti:8447 | xargs kill -9`

---

## 3. Docker Image Loaded

```bash
docker images | grep minifw-education
```

- [ ] Image `minifw-education` appears in the list

If missing: `docker load -i images/minifw-education.tar` (takes ~2 minutes)

---

## 4. Clean State

```bash
bash fast_reset.sh
```

- [ ] Reset completed — containers stopped, volume cleared, restarted clean
- [ ] Dashboard reachable at `https://localhost:8447`

---

## 5. Dashboard Sanity Check

Open `https://localhost:8447` (accept self-signed cert warning)  
Login: `admin / Education1!`

- [ ] Sector label shows "Education" or "School"
- [ ] Protection status shows "Active"
- [ ] Event feed populates within 60 seconds
- [ ] At least one ALLOW event (low score) appears
- [ ] No false positives on normal educational traffic (office365.com, etc.)

---

## 6. Attack Readiness

- [ ] You know the key numbers: **student threshold 70**, **guest threshold 60**
- [ ] You know the trace ID prefix: **EDU-SAFE-***
- [ ] `PRESENTER_CARD.md` open as reference
- [ ] You know the story: VPN bypass on student net (score 75 = BLOCK)

---

## 7. Recovery

- [ ] `bash fast_reset.sh` ready to run
- [ ] Docker volume name if manual reset needed: `minifw_education_logs`
  ```bash
  docker compose down && docker volume rm minifw_education_logs && docker compose up -d
  ```

---

## Go / No-Go

| Check | Status |
|-------|--------|
| Docker running | |
| Port 8447 free | |
| Image loaded | |
| Clean state | |
| Dashboard loads | |

**All five green = GO.**
