# MiniFW-AI Establishment Demo — Presenter Script
**Scenario:** The Crown Hotel Group — ransomware, crypto miner, guest WiFi blocks
**Duration:** ~5 minutes live demo
**Audience:** Owner, IT Manager, Operations Director, Insurance Broker

---

## Before the Demo

    docker compose -f docker/docker-compose.usb-sme.yml ps

All three containers running. https://localhost:8444 loads login. admin / SME_Demo1!

---

## Phase 1 — Clean Baseline

**What the audience sees:** Office365 from 192.168.1.10 — score 0 or low, ALLOW. Green.

**Say:**
> "This is the Crown Hotel Group's office network on a Tuesday. One employee on Microsoft 365. Normal business traffic. Scoring 0. Zero alerts."

> "Two network segments: the office LAN — staff, management, reception — and the guest WiFi, which is on a separate VLAN for guests and visitors. Each has a different policy. We'll see why that matters in about 30 seconds."

---

## Phase 2 — Phishing on Office Network (MONITOR)

**What happens:** `login-paypal-secure-verify.com` from 192.168.1.50 — MONITOR, score 40.

**Say:**
> "Phishing domain. Score 40. Monitor. An employee clicked a link in an email. The browser queried `login-paypal-secure-verify.com`. The firewall recognized it from the threat feed — score 40. But on the office network, the block threshold is 80. Score 40 is below it. The AI monitors and flags. It doesn't block."

> "That's by design. The office network trusts employees enough to surface the event for a human decision rather than block autonomously. If you want to change that, you lower the office threshold in policy.json."

---

## Phase 3 — Ransomware C2 (MONITOR on office, then BLOCK on guest)

**What happens:** `locky-decrypt-files.xyz` from 192.168.1.100 — MONITOR on office (score 75, below 80). Then a guest device queries the same domain — BLOCK (score 40, guest threshold IS 40).

**Say:**
> "Ransomware C2 beacon from an office device — score 75. That's feed plus YARA. MONITOR, not block, because the office threshold is 80. The AI is watching. Score 75 is five points from a block."

**When the guest block appears:**
> "Now watch the guest network. 172.16.1.x — a guest device on the hotel WiFi. Score 40. BLOCK. Immediately."

> "Guest WiFi threshold is 40. That's the same score as a simple feed-match. Any domain that appears in the threat feed — one signal — blocks a guest device. The AI doesn't wait for YARA to confirm. It doesn't give a guest device the benefit of the doubt. You know nothing about that device."

> "The office network waits for score 80. The guest network acts at 40. Same engine. Two policies. No manual device configuration."

---

## Phase 4 — Crypto Miner (office MONITOR)

**What happens:** `xmrig.c2-miner.io` from 192.168.1.200 — MONITOR, score 75.

**Say:**
> "Crypto miner C2. Someone's laptop on the office network is mining Monero and using the hotel's electricity to do it. Score 75 — YARA matched `xmrig`. MONITOR on office, because office threshold is 80."

> "In practice, you'd lower the threshold or add this domain to the block feed. The AI is showing you where the threshold needs to be. Score 75 on a crypto miner isn't ambiguous — it's five points below a block."

---

## Phase 5 — Guest Burst (cascade BLOCK)

**What happens:** 250 queries from 172.16.1.99 (guest) — BLOCK cascade, score 40+.

**Say:**
> "Guest device — 250 DNS queries in 5 seconds. Burst tracker fires. All queries blocked. The guest's device is isolated."

> "A guest with a malware-infected phone connected to your WiFi. Without this, that device is on your network, hitting your bandwidth, potentially pivoting to your POS system or your back-office server. With MiniFW-AI, it's isolated the moment it hits the burst threshold."

---

## Q&A Responses

**"Why is the office threshold 80 and the guest threshold 40?"**
> "You know your staff. You don't know your guests. A score of 40 from an office device might be a false positive — a legitimate tool that's on a threat feed. A score of 40 from a guest device is enough to act. The policy reflects that difference. Both are configurable."

**"What about POS systems?"**
> "POS devices would go on the DMZ segment — threshold 70. Feed match alone (40) doesn't block. Feed plus YARA (75) does. More sensitive than office, less hair-trigger than guest. You can tune it for your specific POS vendor's traffic patterns."

**"Do we need to run this on-site?"**
> "Yes — it's a USB appliance that connects to your gateway or managed switch. No cloud, no subscription, no monthly call home. The threat feeds and YARA rules are bundled and updated when you update the USB."

**"What happens if the firewall blocks something it shouldn't?"**
> "Blocked IPs are isolated for 24 hours by default. You can release them manually from the dashboard in about 10 seconds. The block reason is in the event detail — you can see exactly why it was blocked and make an informed decision."

---

## Timing Reference

| Time | Event |
|------|-------|
| T+0 | Office365 allow — normal business traffic |
| T+10s | Phishing MONITOR score 40, office |
| T+20s | Ransomware MONITOR score 75, office |
| T+30s | **Crypto miner MONITOR score 75, office** |
| T+40s | **Guest BLOCK score 40** — first denied domain from guest |
| T+50s | **Guest burst BLOCK score 100** — 250 queries cascade |
| T+60s+ | Office allows continue alongside guest blocks |
