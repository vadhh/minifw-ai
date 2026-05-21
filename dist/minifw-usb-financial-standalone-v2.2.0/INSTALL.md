# Installation Guide — MiniFW-AI Financial Standalone Demo v2.2.0

---

## Prerequisites

| Requirement | Check | Minimum |
|---|---|---|
| Python 3 | `python3 --version` | 3.10+ |
| openssl | `openssl version` | any |
| libnss3-tools (optional) | `certutil -V` | for Firefox/Chrome NSS trust |
| Port 8443 free | `ss -tlnp \| grep 8443` | — |
| sudo access | for trust store install | one-time only |

---

## Step 1 — Set Up the Virtual Environment

A pre-built `venv/` is included. Try it first:

```bash
source venv/bin/activate
python3 -c "import fastapi; print('OK')"
```

If this prints `OK`, skip to Step 2.

**Rebuild venv if needed:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 2 — Set Up TLS (one-time, requires sudo)

```bash
bash setup_tls.sh
```

This generates a local CA and installs it to your system trust store and browser NSS databases. Run once per machine. If you switch machines, run it again on the new machine.

**Install certutil for Firefox/Chrome NSS support (recommended):**

```bash
sudo apt-get install libnss3-tools
```

Then re-run `bash setup_tls.sh`.

---

## Step 3 — Run the Demo

```bash
source venv/bin/activate
bash run_demo.sh
```

**Expected output:**
```
[minifw] Starting Financial Demo...
[minifw] Engine started (PID XXXXX)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
```

A browser window opens automatically. The dashboard shows live financial traffic. At ~T+75 seconds, a BLOCK event fires from the trading floor segment.

---

## Step 4 — After the Meeting

```bash
bash teardown_demo.sh
```

Removes the demo CA from trust stores. The demo machine is clean.

---

## Credentials

| Item | Value |
|---|---|
| URL | `https://localhost:8443` |
| Username | `admin` |
| Password | `Finance1!` |
| BLOCK fires at | ~75 seconds |

---

## Health Check

```bash
bash HEALTHCHECK.sh
```

Run before the meeting to verify all components are ready. Expected: `HEALTHCHECK PASSED (9/9)`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Browser shows cert warning | Re-run `bash setup_tls.sh`; close and reopen browser |
| Port 8443 in use | `lsof -ti:8443 \| xargs kill -9` then retry |
| Demo won't start | `bash recover_demo.sh` |
| venv broken | `python3 -m venv venv && pip install -r requirements.txt` |
