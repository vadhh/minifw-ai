# Pre-Demo Checklist — Legal Sector (Docker)
**Run this 10 minutes before any client demo.**

---

## 1. Machine State

- [ ] Docker Engine running: `docker info >/dev/null 2>&1 && echo OK`
- [ ] Laptop charged / plugged in
- [ ] Browser open, sleep/lock disabled
- [ ] Terminal open in `minifw-usb-legal-v2.2.0/`

---

## 2. Port Clear

```bash
ss -tlnp | grep 8448
```

- [ ] Port 8448 is free

If occupied: `lsof -ti:8448 | xargs kill -9`

---

## 3. Docker Image Loaded

```bash
docker images | grep minifw-legal
```

- [ ] Image `minifw-legal` appears in the list

If missing: `docker load -i images/minifw-legal.tar` (takes ~2 minutes)

---

## 4. Clean State

```bash
bash fast_reset.sh
```

- [ ] Reset completed
- [ ] Dashboard reachable at `https://localhost:8448`

---

## 5. Dashboard Sanity Check

Open `https://localhost:8448` (accept self-signed cert)  
Login: `admin / Legal1!`

- [ ] Sector label shows "Legal"
- [ ] Protection status shows "Active"
- [ ] Event feed populates within 60 seconds

---

## 6. Attack Readiness

- [ ] You know the threshold hierarchy: **partner 85 / associate 72 / client room 62**
- [ ] You know the trace ID prefix: **LEGAL-ACP-***
- [ ] Key story: ransomware C2 score 75 — BLOCKS on associate net, does NOT block on partner net
- [ ] Key story: Tor relay in client room (score 75) — BLOCK (threshold 62)
- [ ] `PRESENTER_CARD.md` open as reference

---

## 7. Recovery

- [ ] `bash fast_reset.sh` ready to run
- [ ] Docker volume name if manual reset needed: `minifw_legal_logs`
  ```bash
  docker compose down && docker volume rm minifw_legal_logs && docker compose up -d
  ```

---

## Go / No-Go

| Check | Status |
|-------|--------|
| Docker running | |
| Port 8448 free | |
| Image loaded | |
| Clean state | |
| Dashboard loads | |

**All five green = GO.**
