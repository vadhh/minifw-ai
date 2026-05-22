# MiniFW-AI — Hospital Sector Standalone Demo v2.2.0 (v3)

**Type:** Standalone Python Demo (no Docker required)  
**Sector:** Hospital (HIPAA / IoMT)  
**Version:** 2.2.0v3  
**Dashboard:** http://localhost:8000  
**Credentials:** `admin / Hospital1!`

---

## What This Is

A fully self-contained hospital sector demonstration that runs natively on any machine with Python 3.
Unlike the Docker-based kit, this starts in under 2 seconds and works completely offline — no container runtime needed.

Designed for **executive / CIO demos** where setup time and environment friction must be zero.

---

## What's Included

```
run_demo.sh                 # Single-command launcher
README.md                   # This file
README.txt                  # Quick-start card (plain text)
INSTALL.md                  # Full installation guide
requirements.txt            # Python dependencies
app/                        # MiniFW-AI engine + web admin (full source)
  minifw_ai/                  Engine daemon (scoring pipeline, sector rules)
  web/                        FastAPI dashboard (AdminLTE 3 UI)
config/
  feeds/                    # Domain/IP/ASN deny feeds
  modes/minifw_hospital/    # Hospital sector policy
demo_data/
  normal_traffic.json       # Simulated healthy hospital traffic
  attack_traffic.json       # Ransomware / C2 / data-exfil attack patterns
models/                     # Pre-trained MLP threat model
yara_rules/                 # YARA rules for payload scanning
logs/                       # Runtime logs (written here, not /opt/)
venv/                       # Pre-built Python virtual environment (optional)
```

---

## Quick Start

**First time on a fresh machine** — set up the Python environment once:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

**Every time** — start the demo:

```bash
bash run_demo.sh
```

Then open **http://localhost:8000** in your browser.  
Login: `admin` / `Hospital1!`

No Docker. No image loading. Starts in under 2 seconds.

---

## What You'll See

The engine runs in `DEMO_MODE`, cycling through simulated traffic from `demo_data/`:

| Phase | Traffic Pattern | Detection | Action |
|-------|----------------|-----------|--------|
| Normal | EMR system, PACS imaging, HL7 feeds | Clean | Allow |
| Attack | Ransomware C2 beacon | Domain feed match + MLP | Block |
| Attack | Suspicious API data leak | Burst + score | Block |
| Attack | Tor exit-node request | IP deny feed | Block |

Events appear on the dashboard in real time. The **AI Threat Synthesis Panel** shows HIPAA-aligned severity, active detections, and AI confidence scores.

---

## Sector Focus

- **Detection:** Ransomware C2, IoMT behavioural anomalies, Tor usage, self-signed TLS on patient-data paths
- **Enforcement:** HIPAA-aligned block/monitor thresholds (`config/modes/minifw_hospital/policy.json`)
- **Dashboard:** PHI risk indicators, HIPAA audit trail framing

---

## Advantages over Docker Kit

| | Standalone v3 | Docker Kit v2 |
|--|---------------|--------------|
| Startup time | < 2 seconds | 2-3 min (first load) |
| Docker required | No | Yes |
| Works offline | Yes | Yes |
| Source visible | Yes | No |
| Best for | Executive demo | Technical buyer demo |

---

## System Requirements

See `INSTALL.md` for full setup instructions.

Minimum: Python 3.10+, 4 GB RAM, any OS (Linux, macOS, Windows + WSL).
