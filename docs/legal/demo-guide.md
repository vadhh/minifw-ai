# MiniFW-AI Legal Sector — Demo Guide

**Audience:** Sales engineers presenting to managing partners, IT directors, and compliance officers at law firms.

**Port:** 8448 · **Password:** `Legal1!` · **Mode:** `minifw_legal`

---

## Quick Start

From the repo root (source build):

    docker compose -f docker/docker-compose.legal.yml up

From USB:

    bash demo.sh

Open `https://localhost:8448` → accept the self-signed certificate → log in with `admin` / `Legal1!`.

---

## What the Demo Shows

The demo runs a continuous loop of law firm network scenarios. Each cycle takes approximately 2 minutes.

### Phase 1 — BASELINE (normal legal research)

Partners and associates browsing Westlaw, LexisNexis, and courts.gov. The dashboard shows green allow events.

**Talking point:** "This is what a normal day at the firm looks like — case research flows freely with no friction."

### Phase 2 — ANOMALY (unauthorised cloud upload)

`wetransfer-legal.io` appears from the paralegal subnet (10.20.2.x). Score reaches 40 → MONITOR.

**Talking point:** "The AI notices a paralegal attempting to upload files to an unauthorised transfer service. It flags it for the administrator — no disruption yet, but a full audit trail is created."

### Phase 3 — ESCALATION (Tor exit relay)

`tor-exit-relay.onion-gw.net` from a client meeting room (192.168.200.x). Feed match + YARA push score to 75 → BLOCK (client block threshold: 62).

**Talking point:** "A device in a client meeting room tried to reach the Tor network. The system blocks it immediately — client meeting rooms have the tightest thresholds because we don't know those devices."

### Phase 4 — BLOCK (Ransomware C2)

`clio-encrypt.c2-server.ru` from the associate subnet — feed + YARA, score 75 → BLOCK (associate threshold: 72).

**Talking point:** "This is a ransomware command-and-control beacon. The pattern matches our YARA rule for case management system targeting. It's blocked before a single file is encrypted."

### Phase 5 — BLOCK (Privilege breach)

`opposing-counsel.harvest.io` from the paralegal subnet — feed + YARA, score 75 → BLOCK (paralegal threshold: 70).

**Talking point:** "This domain is associated with opposing counsel data harvesting. The YARA rule catches it even if the exact domain hasn't been seen before."

### Phase 6 — BURST CASCADE

200 rapid queries to `clio-encrypt.c2-server.ru` from `10.20.1.99`. The dashboard shows the block cascade with Trace ID and Decision Owner.

**Talking point:** "When ransomware starts its beacon loop, the burst pattern is unmistakeable. Blocked in real time, full audit trail for your incident response team."

---

## Key Talking Points by Audience

| Audience | Focus |
|----------|-------|
| Managing Partner | Trace ID + Decision Owner — audit trail for privilege complaints and regulatory enquiries |
| IT Director | Per-segment thresholds — partner net is relaxed; client rooms are tightest |
| Compliance Officer | YARA catches unknown C2 and privilege-breach variants not yet on blocklists |
| Associate | AI Reason field — clear explanation of why each event was blocked or monitored |

---

## Dashboard Sections to Highlight

1. **AI Threat Synthesis panel** — show the BLOCKED event with risk %, action badge, AI Reason, Decision Owner, Trace ID
2. **Events page** — filter by `blocked` to show the audit log
3. **Policy page** — show different thresholds for `partner` vs `paralegal` vs `client` segments

---

## Reset Between Demos

    docker compose -f docker/docker-compose.legal.yml down -v
    docker compose -f docker/docker-compose.legal.yml up

The `-v` flag clears the log volume so the dashboard starts fresh.
