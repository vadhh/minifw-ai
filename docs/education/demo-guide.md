# MiniFW-AI Education Sector — Demo Guide

**Audience:** Sales engineers and pre-sales staff presenting to school IT directors, network administrators, and school board decision makers.

**Port:** 8447 · **Password:** `Education1!` · **Mode:** `minifw_school`

---

## Quick Start

From the repo root (source build):

    docker compose -f docker/docker-compose.education.yml up

From USB:

    bash demo.sh

Open `https://localhost:8447` → accept the self-signed certificate → log in with `admin` / `Education1!`.

---

## What the Demo Shows

The demo runs a continuous loop of school network scenarios. Each cycle takes approximately 2 minutes.

### Phase 1 — BASELINE (normal study traffic)

Students browsing Khan Academy, BBC, Wikipedia. The dashboard shows green allow events.

**Talking point:** "This is what a normal school day looks like — legitimate educational traffic flows freely."

### Phase 2 — ANOMALY (first policy violations appear)

Instagram and nordvpn.com queries appear from the student subnet (10.10.0.x). Score reaches 40 → MONITOR.

**Talking point:** "The AI notices a student attempting to reach social media and a VPN service. It flags it for the administrator without disrupting the network yet."

### Phase 3 — ESCALATION (YARA triggers)

`nordvpn-bypass.proxy.io` appears — matches the `EducationVpnProxy` YARA rule, pushing score to 75. Student `block_threshold=70` → BLOCK.

**Talking point:** "Pattern matching catches the bypass tool even if the exact domain isn't on the blacklist yet."

### Phase 4 — BLOCK CASCADE (VPN burst)

200 rapid queries from `10.10.0.200` to `nordvpn-bypass.proxy.io`. The dashboard shows the burst block cascade. Trace ID and Decision Owner appear in the synthesis panel.

**Talking point:** "When a student runs a VPN client, the burst pattern is unmistakeable. The system blocks it in real time and records a full audit trail."

---

## Key Talking Points by Audience

| Audience | Focus |
|---|---|
| IT Director | Trace ID + Decision Owner — audit trail for complaints and reporting |
| School Board | Risk % badge — clear visual of threat severity without jargon |
| Safeguarding Lead | YARA rule matching catches bypass tools not yet on the blacklist |
| Network Admin | Per-segment thresholds — student net is stricter than staff net |

---

## Dashboard Sections to Highlight

1. **AI Threat Synthesis panel** — show the BLOCKED event with risk %, action badge, Decision Owner, Trace ID
2. **Events page** — filter by `blocked` to show the audit log
3. **Policy page** — show different thresholds for `student` vs `staff` vs `guest` segments

---

## Reset Between Demos

    docker compose -f docker/docker-compose.education.yml down -v
    docker compose -f docker/docker-compose.education.yml up

The `-v` flag clears the log volume so the dashboard starts fresh.
