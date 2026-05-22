# Installation Guide — MiniFW-AI Financial Standalone Demo v2.2.0

Fresh machine setup, end to end.

---

## What You Need

- Ubuntu 22.04 / Debian 12 or newer (other Linux distros work but commands may differ)
- Python 3.10 or higher
- sudo access (needed once for TLS trust store install)
- Port 8443 free
- Internet access for `apt-get` and `pip` (one-time only)

---

## Step 1 — Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv openssl libnss3-tools
```

**What each package does:**

| Package | Why |
|---------|-----|
| `python3` | Runtime for the engine and dashboard |
| `python3-pip` | Needed to install Python dependencies |
| `python3-venv` | Creates the isolated Python environment |
| `openssl` | Generates the TLS certificate |
| `libnss3-tools` | Installs the CA into Chrome and Firefox so there is no browser cert warning |

Verify Python version is 3.10 or higher:

```bash
python3 --version
```

---

## Step 2 — Copy the Demo Package

If installing from USB:

```bash
cp -r /media/$USER/MINIFW-USB/minifw-usb-financial-standalone-v2.2.0 ~/minifw-demo
cd ~/minifw-demo
```

If installing from the repo:

```bash
cd dist/minifw-usb-financial-standalone-v2.2.0
```

All remaining commands run from inside this folder.

---

## Step 3 — Set Up the Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Expected output ends with something like:

```
Successfully installed fastapi-... uvicorn-... sqlalchemy-...
```

Verify it worked:

```bash
python3 -c "import fastapi, uvicorn, sqlalchemy; print('OK')"
```

If this prints `OK`, the environment is ready.

---

## Step 4 — Set Up TLS (one-time per machine)

```bash
sudo bash setup_tls.sh
```

This does four things:

1. Generates a local CA (`certs/minifw-ca.crt`) and a server certificate (`certs/server.crt`) valid for `localhost`
2. Installs the CA to the system trust store (`/usr/local/share/ca-certificates/`) — makes `curl` and Python requests trust the cert
3. Installs the CA into Chrome/Chromium's NSS database (`~/.pki/nssdb`) — removes the browser cert warning
4. Installs the CA into Firefox's NSS database (if Firefox is installed)

Expected output:

```
[minifw-tls] Step 1: Generating CA key and certificate...
[minifw-tls] Step 2: Generating server key and CSR...
[minifw-tls] Step 3: Signing server certificate with CA...
[minifw-tls] Certificates written to certs/
[minifw-tls] Step 4: Installing CA to system trust store (requires sudo)...
[minifw-tls] System trust store updated.
[minifw-tls] Step 5: Installing CA to NSS databases (Chrome/Firefox)...
[minifw-tls] Installed to ~/.pki/nssdb
[minifw-tls] TLS setup complete.
[minifw-tls] Now run: bash run_demo.sh
```

**This step runs once per machine.** If you move to a different laptop, run it again there.

**After installing the CA, close and reopen the browser** so it picks up the new certificate.

---

## Step 5 — Activate the venv and Run the Demo

```bash
source venv/bin/activate
bash run_demo.sh
```

The terminal will print exactly four lines and stop:

```
[minifw] Admin user created.
[minifw] Starting Financial Demo...
[minifw] Engine started (PID XXXXX)
[minifw] Dashboard ready → https://localhost:8443  (admin / Finance1!)
[minifw] Press Ctrl+C to stop.
```

A browser window opens automatically to `https://localhost:8443`.

On subsequent runs, the first line changes to:

```
[minifw] Admin user already exists — skipping creation.
```

---

## Step 6 — Log In

| Field | Value |
|-------|-------|
| URL | `https://localhost:8443` |
| Username | `admin` |
| Password | `Finance1!` |

---

## Step 7 — Watch the Demo

The dashboard shows live financial network traffic:

- **T+0 to T+90s** — Normal traffic: Bloomberg, Reuters, SWIFT, Oracle ERP, SAP, Refinitiv, NASDAQ. All green (allow), scores 18–22.
- **T+90s to T+120s** — Attack sequence on `10.50.0.1` (trading floor → ERP pivot):
  - `tor-exit-4f2a.net` — monitor, score 55
  - `c2.trickbot-gate.com` — monitor, score 72
  - `exfil.payment-collect.io` — monitor, score 82 (ERP subnet pivot)
  - `exfil.payment-collect.io` — monitor, score 89
  - `exfil.payment-collect.io` — **BLOCK, score 95** ← this is the moment
- **T+120s+** — Normal traffic resumes; attacker IP remains blocked

No presenter action needed. The BLOCK fires automatically.

---

## Step 8 — Stop the Demo

Press `Ctrl+C` in the terminal. Output:

```
[minifw] Demo stopped.
```

All processes are killed. Logs are kept in `logs/` for post-demo review.

---

## Step 9 — Clean Up After the Meeting (optional)

Removes the demo CA from the system trust store and browser databases:

```bash
bash teardown_demo.sh
```

Run this after the meeting if you do not want the demo CA permanently trusted on this machine.

---

## Pre-Demo Health Check

Run this before going into the meeting room to confirm everything is ready:

```bash
bash HEALTHCHECK.sh
```

Expected result:

```
HEALTHCHECK PASSED (9/9)
```

If any check fails, the output tells you exactly what is wrong and how to fix it.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python3 --version` shows 3.9 or lower | `sudo apt-get install python3.11` and use `python3.11 -m venv venv` |
| `pip install` fails with network error | Check internet connection; try `pip install --retries 3 -r requirements.txt` |
| Browser shows cert warning after setup_tls.sh | Close and reopen the browser completely; if still showing, run `sudo bash setup_tls.sh` again |
| Port 8443 already in use | `lsof -ti:8443 \| xargs kill -9` then retry |
| "Admin user already exists" but login fails | `rm minifw.db` and rerun `bash run_demo.sh` — the DB will be recreated with a fresh admin |
| Dashboard did not start in 20s | Check `logs/web.log` for errors; most common cause is a missing venv package |
| No BLOCK event after 2 minutes | Check `logs/scheduler.log`; restart with `bash recover_demo.sh` |
| Browser does not open automatically | Open `https://localhost:8443` manually |
