# 5-Minute Executive Demo Script
**Hospital Sector · St. Roch Memorial Hospital**  
**Audience:** Non-technical decision maker (CFO, CEO, board member, owner)

---

## Before They Walk In

```bash
bash fast_reset.sh          # 45-second clean reset
bash five_min_demo.sh       # start with 5-min scheduler
```

Browser open at `http://localhost:8000`, logged in, event feed visible.  
Wait until you see the first ALLOW event before starting the clock.

---

## The Script (5 minutes)

### Minute 1 — Set the Scene (T+0 to T+30s)

*Point to the event feed showing ALLOW events.*

> "This is St. Roch Memorial Hospital's network right now. Normal Tuesday.
> EMR system, PACS imaging, lab feeds — everything running, everything green.
> No alerts. No blocked traffic. The system is just watching."

*Wait for the first row to appear. Point to the score column (score 18–22).*

> "Every DNS lookup gets a risk score. Zero to one hundred. Low score — allowed through.
> The system is silent when nothing is wrong. That's important: no false alarms,
> no tickets, no one chasing noise."

---

### Minute 2 — The First Attack (T+30s to T+60s)

*Watch for MONITOR events (score 39, then 43). Then the BLOCK.*

> "Something just changed. Score 39 — not a block yet, the system is watching it.
> Score 43 — still watching, building the case. Score 47 — **blocked.**"

*Click the BLOCK event row to expand it. Point to the trace ID.*

> "That was a patient monitor on the medical device network — IoMT.
> Unpatched firmware. An attacker was using it to phone home to a ransomware server.
> The system blocked it. Automatically. In under 30 seconds."

*Point to the segment field.*

> "The medical device network has a lower block threshold than the staff network.
> Score 47 on a patient monitor is a block. Score 47 on a staff PC is just a watch.
> The same engine enforces both simultaneously."

---

### Minute 3 — Staff Keep Working (T+60s to T+90s)

*ALLOW events are back in the feed. Point to them.*

> "This is the part most systems get wrong. When the attack was blocked,
> nothing else stopped. EMR is still running. Lab feeds are still running.
> The nurse at the nursing station didn't lose her session.
> The attacker was isolated — not the hospital."

*Pause. Let this land.*

---

### Minute 4 — The Second Attack (T+90s to T+120s)

*Watch for MONITOR events from 192.168.1.75, then the BLOCK at score 82.*

> "Now a staff workstation — different network segment, different threshold.
> This one required more evidence: score 64... score 75... score 82.
> It was a phishing attack. A staff member opened a malicious attachment.
> The credential harvesting tool tried to bulk-pull patient records
> and stage them to an external server. Score 82 — **blocked.**"

*Point to the HIPAA-PHI trace ID.*

> "This trace ID is the audit record. Timestamped, scored, decision logged.
> If a HIPAA auditor asks 'did you have a contemporaneous record of detecting this?' —
> that's your answer."

---

### Minute 5 — The Takeaway (T+120s+)

*Feed shows clean ALLOW events again. Both attackers gone.*

> "Both attackers are isolated. Staff is still working. Patient data wasn't exfiltrated.
> The ransomware server never got a callback. And we have an audit trail for both incidents."

*Close the event feed. Show the dashboard summary numbers.*

> "Two attacks. Zero downtime. Zero false positives on normal clinical traffic.
> This is running on a standard Linux appliance that costs less than one day of
> incident response."

---

## Q&A Answers (Under 30 Seconds Each)

**"How does it know it's ransomware?"**
> "DNS threat feeds — known ransomware C2 domains — plus a neural network that scores
> behavioural patterns. The YARA scanner pattern-matches the specific malware signature.
> Three independent signals, each adding to the score."

**"What if it blocks something legitimate?"**
> "It hasn't in this demo — Office365, Teams, clinical domains all scored zero.
> If it ever does, there's a one-click release on the dashboard. The block expires
> automatically in 24 hours. And you can tune the threshold up or down in the config."

**"Does it need an agent on every device?"**
> "No agents. It sits on the gateway and watches DNS. Every device on the network
> is covered without installing anything on the devices themselves.
> That's critical for IoMT — you can't install agents on a ventilator."

**"Can it run offline?"**
> "Yes. The threat feeds are loaded at startup and cached locally.
> The AI model runs on-device. No cloud dependency, no call home."

**"How fast is blocking?"**
> "The block fires in the same processing loop as the detection — typically
> under one second from the DNS query to the nftables rule drop.
> The attacker's C2 server receives no response."

---

## Numbers to Have Ready

| Metric | Value |
|--------|-------|
| IoMT block threshold | 45 |
| Internal block threshold | 80 |
| Attack 1 block score | 47 |
| Attack 2 block score | 82 |
| Time to first block | ~38 seconds |
| False positives on clinical traffic | 0 |
| Human interventions required | 0 |
| Trace ID format | HIPAA-PHI-* |
