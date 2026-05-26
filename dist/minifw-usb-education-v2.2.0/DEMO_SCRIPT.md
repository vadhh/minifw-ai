# MiniFW-AI Education Demo — Presenter Script
**Scenario:** Westgate Academy — student VPN bypass and content filter evasion, blocked in real time
**Duration:** ~5 minutes live demo (2 min setup + 3 min run)
**Audience:** School CTO, IT Manager, Safeguarding Lead, MAT (Multi-Academy Trust) Director

---

## Before the Demo

Confirm the demo is running:

```bash
docker compose -f docker/docker-compose.usb-education.yml ps
```

All three containers (engine, web, injector) must show `Up`. Then confirm:
- Browser opens `https://localhost:8447` — login page loads
- Login with `admin / Education1!` — dashboard shows education mode
- Event feed shows allow events (Khan Academy, BBC, Wikipedia) within 30 seconds

---

## Phase 1 — Clean Baseline (first 20–30 seconds)

**What the audience sees:** Khan Academy, BBC, Wikipedia — all scoring 18–22, all green allows.

**Say:**
> "This is Westgate Academy's student network on a normal school morning. Every request you see here is legitimate educational traffic — Khan Academy, BBC, Wikipedia. Scoring 18 to 22. Nothing flagged, nothing blocked."

> "You'll notice three network segments on the left: student, staff, and guest. Each has its own policy. The student network blocks at score 70. The guest WiFi — for visitors and parents — blocks at score 60. Staff have a standard threshold of 80. MiniFW-AI enforces all three simultaneously."

**Wait for 4–6 clean events to populate the feed.**

---

## Phase 2 — Social Media and VPN Attempts (next 20 seconds)

**What happens:** Instagram and nordvpn.com appear as MONITOR events (score ~40).

**When instagram.com appears as MONITOR:**
> "Instagram. Score 40 — in the monitor zone. The AI is watching but not blocking yet. It doesn't block instagram.com outright because not every school has the same policy, and the score hasn't crossed the student threshold of 70. This is appropriate ambiguity — the AI is gathering evidence."

**When nordvpn.com appears as MONITOR:**
> "NordVPN. Score 40 — same monitor zone. A student is looking for a way around the content filter. Not unusual. Still below the block threshold."

---

## Phase 3 — BLOCK: VPN Bypass Domain (key moment)

**What happens:** `nordvpn-bypass.proxy.io` appears as BLOCK, score 75. Red row, AI SCORED badge.

**Say:**
> "There it is. Score 75. BLOCK."

> "This is different from nordvpn.com — this is `nordvpn-bypass.proxy.io`. A domain specifically designed to tunnel through content filters. The YARA scanner recognized the pattern: `nordvpn-bypass` and `-bypass.proxy` are both in the education ruleset. Feed match plus YARA elevated the score to 75, which crosses the student threshold of 70."

> "The student was blocked before the VPN tunnel was established. The content filter bypass never happened."

**Click into the Event Details modal.**

> "Detection Method: AI SCORED. Score breakdown: Feed match 40, YARA 35. The AI documented its reasoning. This isn't a black box — every decision has a traceable chain."

---

## Phase 4 — BLOCK: Guest Network Content Filter Evasion

**What happens:** `filter-bypass.student.io` appears as BLOCK from 192.168.100.10, score 75. Guest segment.

**Say:**
> "Second block. Different segment — this is the guest WiFi. 192.168.100.10 — a visitor, a parent, someone on the open network. Score 75, which crosses the guest threshold of 60."

> "The guest network has a lower threshold precisely because we know less about who's on it. A legitimate visitor has no reason to query a domain called `filter-bypass.student.io`. The AI doesn't need to know who this person is — the behavior is enough."

---

## Phase 5 — Sustained Normal (closing)

**What the audience sees:** Both blocked IPs isolated. Khan Academy, BBC, Wikipedia continuing normally. 2 blocks in the counter, clean allows in the feed.

**Say:**
> "Both blocked. Student traffic and staff traffic continue normally. The legitimate learning destinations — Khan Academy, BBC, Wikipedia — are completely unaffected."

> "From a safeguarding perspective: the school has a log with a timestamp, a decision, and a documented reason for every event. If a parent, a governor, or Ofsted asks 'what was this student trying to access and what did you do about it?' — this is the answer. Not 'we think our filter probably caught it.' A timestamped, AI-documented decision."

---

## Q&A Responses

**"How is this different from a DNS filter we already have?"**
> "A DNS filter works on a blocklist — you block TikTok.com, students try TikTok-proxy.cc. It's a cat-and-mouse game. MiniFW-AI scores behavior: a domain called `nordvpn-bypass.proxy.io` triggers YARA and the feed matcher because of what it looks like, not because it's on a list. The blocklist approach requires someone to add every new bypass domain manually. This approach catches patterns."

**"What about false positives — will this block teaching resources?"**
> "The clean baseline you saw — Khan Academy, BBC, Wikipedia — none of those generated a monitor event, let alone a block. The YARA rules are written specifically for education threat patterns: VPN bypass strings, SafeSearch circumvention strings, content filter evasion strings. A legitimate education domain doesn't match any of those patterns."

**"Can we set different policies for different year groups?"**
> "Yes. The segment system maps subnets to policies. You could have GCSE students at one threshold, sixth form at another, staff at a third. The subnets are configured in policy.json and don't require a software change."

**"What happens to the blocked data — is it logged?"**
> "Every event, allow and block, is written to structured JSONL. The block events include the student IP, the domain, the timestamp, the score, and the reasons. That log is your audit trail for safeguarding conversations."

**"Does this need cloud connectivity?"**
> "No. The YARA rules, the ML model, and the threat feed all run locally. This USB drive is the entire system. Useful for school networks that are segmented from the internet by design."

---

## Timing Reference

| Time    | Event                                             |
|---------|---------------------------------------------------|
| T+0     | Clean baseline — Khan Academy, BBC, Wikipedia     |
| T+15s   | instagram.com MONITOR score ~40                   |
| T+20s   | nordvpn.com MONITOR score ~40                     |
| T+25s   | **BLOCK #1** — nordvpn-bypass.proxy.io score 75, student net |
| T+35s   | **BLOCK #2** — filter-bypass.student.io score 75, guest net  |
| T+40s+  | VPN burst (200 queries) → cascade block           |
| T+50s+  | Sustained normal, both IPs blocked                |

*(Exact timing depends on Docker startup. Loop repeats every ~30 seconds.)*
