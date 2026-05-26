# MiniFW-AI Hospital Demo — Presenter Script
**Scenario:** St. Roch Memorial Hospital — Ransomware + PHI exfiltration, stopped in real time
**Duration:** ~7 minutes live demo (3 min setup + 4 min run)
**Audience:** Hospital CIO, CISO, Compliance Officer, IT Director

---

## Before the Demo

Run this 30 minutes before:

```bash
bash HEALTHCHECK.sh
```

All checks must pass. Then confirm manually:
- Browser opens `http://localhost:8000` — login page loads
- Login with `admin / Hospital1!` — dashboard shows Financial mode
- Event feed starts populating within 60 seconds
- Wait for first MONITOR event to appear

---

## Phase 1 — Clean Baseline (T+0 to T+90s)

**What the audience sees:** EMR, PACS, HL7, pharmacy, FHIR, lab all scoring 18–22. Green rows. Zero alerts.

**Say:**
> "This is St. Roch Memorial Hospital on a normal Tuesday morning. Every device you see here is legitimate clinical traffic — Epic EMR queries, radiology PACS lookups, HL7 interface messages, pharmacy management system. All scoring 18 to 22. Zero alerts, zero blocks."

> "Notice the network segments on the left. `mednet` is our medical device network — infusion pumps, patient monitors, ventilator controllers. That segment has a different threat model than the general hospital network, and MiniFW-AI enforces different thresholds for it. We'll see why that matters in about 90 seconds."

**Wait for 5–8 clean events to populate the feed.**

---

## Phase 2 — IoMT Device Compromised (T+90s to T+120s)

**What happens:** Device 172.16.2.50 (patient monitor on mednet) starts scoring. First MONITOR at 33. Escalates to 39, 43. BLOCK fires at 47.

**When score 33 appears (MONITOR):**
> "Here it is. A patient monitoring device — IP 172.16.2.50, mednet segment — just queried a domain it has never queried before. Score 33. That puts it in the Monitor zone. The AI is not blocking yet. It's watching."

**When score 39 appears:**
> "Score 39. Now we're seeing a known firmware exploit C2 domain. The feed matcher has flagged it, the MLP is building its case. Still monitoring. Still not blocking — the AI accumulates evidence before it acts."

**When score 43 appears:**
> "Score 43. Ransomware staging host. The same compromised device is now pulling down a ransomware payload. We are two points from the IoMT block threshold."

**When BLOCK fires at score 47:**
> "Blocked. Score 47. The AI crossed the mednet threshold — which is 45, not 85. For medical devices, we draw the line much earlier. That ransomware never reached the EMR. No patient record touched. No clinical operation interrupted."

> "This is the IoMT protection story. The general hospital threshold is 85. If this device were treated like a laptop, we would have kept watching until score 85. That ransomware would have had 38 more points of damage time."

---

## Phase 3 — Recovery Normal Traffic (T+120s to T+150s)

**What the audience sees:** Clean clinical traffic resumes. First attacker's IP is blocked in the feed. New allows coming in.

**Say:**
> "One attacker blocked. Normal clinical operations continue without interruption. The EMR is still up. Nursing staff still accessing patient records. The blocked IP is isolated — nothing else on the network was affected."

---

## Phase 4 — PHI Exfiltration Attempt (T+150s to T+180s)

**What happens:** Workstation 192.168.1.75 (internal segment) escalates from score 52 to BLOCK at 82.

**When score 52 appears (MONITOR):**
> "Second event. This one is from the internal clinical network — a workstation that a nursing coordinator uses. Score 52. Credential harvesting tool. This is the phishing vector — someone clicked on a malicious email attachment earlier today."

**When score 64 appears:**
> "Score 64. The attacker now queried a PHI bulk export endpoint. They're using the FHIR API to try to pull a bulk patient data export — name, date of birth, diagnosis codes, insurance information. 82,000 patients on record."

**When score 75 appears:**
> "Score 75. Patient data staging host. They've established an external drop zone and they're about to send it."

**When BLOCK fires at score 82:**
> "Blocked. Score 82. Zero bytes of patient data left the building."

> "For HIPAA compliance, what matters is right here in the event detail — HIPAA-PHI trace ID, decision owner: HIPAA Compliance Engine, detection method: AI SCORED. That goes directly into your audit log. If a breach were to be alleged, this is your evidence that you detected it, blocked it, and logged it within seconds."

---

## Phase 5 — Sustained Safe State (T+180s+)

**What the audience sees:** Both attackers blocked. Clean clinical traffic continuing. Event counter shows 2 blocked, 15+ allowed.

**Say:**
> "Two attackers stopped. Both IPs isolated. Clinical operations never interrupted. The EMR has been up the entire time. Patients in the ICU — their monitors, their infusion pumps, their ventilators — none of that was touched."

> "What you're seeing is behavioral detection. MiniFW-AI did not block on a signature match. It built a score across multiple signals — the feed matcher, the ML model, the YARA scanner, the burst tracker — and made a decision with a documented reason trail. Every reason you see in that event detail is defensible in a HIPAA audit."

---

## Q&A Responses

**"How is this different from a traditional firewall?"**
> "A traditional firewall blocks on rules: port 443 open, port 23 closed. MiniFW-AI blocks on behavior — a device that has never called out to an external host suddenly does, and the score builds based on what that domain is, where it is, and what pattern it fits. No rule would have caught that IoMT device. A rule would need to be written after the fact."

**"What about false positives?"**
> "The clean traffic you saw — EMR, PACS, HL7, pharmacy — all scored 18 to 22. Not a single monitor event from any of them. The AI learns what normal looks like for this hospital. Bloomberg.com would be suspicious on a mednet device. Google.com on a patient monitor is unusual. The segmentation means each device type is judged against its own baseline."

**"Does it work offline?"**
> "Completely offline. There's no cloud call. The ML model runs locally. The YARA rules are local. The threat feed is bundled with the package. This USB drive is the entire system."

**"What happens when an IoMT device is legitimately calling out — software update, telemetry?"**
> "The allowed domains are on a feed — vendor update servers, legitimate telemetry endpoints — and they score low. An IoMT device calling out to a GE HealthCare update server scores the same as an EMR calling Epic's servers. The threat is when the device calls something that isn't on any known-good list and matches behavioral patterns. That's what scored 33 and escalated."

**"How do we deploy this?"**
> "Two options. USB standalone — plug this in, run one script, dashboard is up in under 60 seconds. Or `.deb` package — `dpkg -i minifw-ai_2.2.0-hospital_amd64.deb`, systemd service starts automatically, logging goes to structured JSONL. The deb integrates with your existing syslog stack."

---

## Timing Reference

| Time | Event |
|------|-------|
| T+0  | Start. Clean baseline. |
| T+90s | First IoMT MONITOR appears (score 33) |
| T+96s | Score 39 — firmware exploit C2 |
| T+102s | Score 43 — ransomware staging |
| T+108s | **BLOCK #1** — score 47, mednet, IoMT |
| T+150s | First PHI MONITOR (score 52) |
| T+156s | Score 64 — FHIR abuse |
| T+162s | Score 75 — PHI staging |
| T+168s | **BLOCK #2** — score 82, internal, PHI |
| T+168s+ | Sustained safe state — both blocked |
