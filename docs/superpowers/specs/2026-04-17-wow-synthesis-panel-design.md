# Wow Synthesis Panel — Design Spec
Date: 2026-04-17

## Goal
Replace the 3-panel row (Live Block Feed + AI Decision Explanation + Kernel Proof) on the dashboard with a single full-width "Hero Alert" synthesis card. The panel tells the complete story of a block event — threat, AI reason, kernel enforcement, and response time — at a glance.

## What Changes

### Files
- `app/web/templates/admin/dashboard.html` — replace 3-column row, update JS

### No backend changes required
Uses existing endpoints: `/admin/api/live-blocks`, `/admin/api/kernel-proof`

## Panel Structure

```
┌─────────────────────────────────────────────────────────┐
│ ● AI Threat Synthesis              [LIVE] [N in last 5s] │
│ ┌─────────────────────────────────────────────────────┐  │
│ │ THREAT BLOCKED                               [LIVE] │  │
│ │ <source IP> → <domain>                              │  │
│ │ <timestamp>                                         │  │
│ │ ┌─────────────────┐ ┌─────────────────┐            │  │
│ │ │ AI REASON       │ │ KERNEL          │            │  │
│ │ │ <category>      │ │ ✔ nftables DROP │            │  │
│ │ │ Score <N>       │ │ inet/minifw     │            │  │
│ │ └─────────────────┘ └─────────────────┘            │  │
│ │ ┌─────────────────┐ ┌─────────────────┐            │  │
│ │ │ TIME TO BLOCK   │ │ THREAT TYPE     │            │  │
│ │ │   <N> ms        │ │ <category>      │            │  │
│ │ │                 │ │ <signals>       │            │  │
│ │ └─────────────────┘ └─────────────────┘            │  │
│ └─────────────────────────────────────────────────────┘  │
│ FEED: • <ip> → <domain>  score <N> · <time>              │
│       • …                                                │
└─────────────────────────────────────────────────────────┘
```

## Data Fields

| Field | Source | Notes |
|---|---|---|
| Threat detected | `live-blocks` → `ev.source`, `ev.domain` | IP → domain |
| AI reason | `ev.ai_explanation.category`, `ev.ai_explanation.score` | Score + category label |
| Kernel blocked | `/api/kernel-proof` → `d.active` | ✔ nftables DROP or warning |
| Time = X ms | Simulated: `Math.floor(Math.random() * 18) + 8` | New value on each new event |
| Mini-feed | Last 3 events from `live-blocks` | IP, domain, score, time |

## Visual Style
- Dark card: `background: linear-gradient(135deg, #7f1d1d, #1e293b)` hero area
- "LIVE" animated red badge on new events
- 2×2 grid inside hero: AI Reason (purple), Kernel (green), Time (cyan), Threat Type (red)
- Mini-feed (last 3 blocks) in card footer area, replacing old scrolling list

## JS Changes
- Remove: `renderAiExplain()` function and its DOM targets (`aiExplainBody`)
- Remove: separate `loadKernelProof()` polling loop (15s interval)
- Add: `renderSynthesis(ev, kernelActive)` — updates the single synthesis card
- Kernel state cached from last `/api/kernel-proof` poll; poll continues at 15s but result fed into synthesis render
- `pollLiveBlocks()` calls `renderSynthesis()` on new event, passing cached kernel state

## HTML Changes
- Remove: `<div class="col-lg-5">` (Live Block Feed)
- Remove: `<div class="col-lg-4">` (AI Decision Explanation)
- Remove: `<div class="col-lg-3">` (Kernel Proof Indicator)
- Add: single `<div class="col-12">` containing the synthesis card

## Out of Scope
- No changes to spike chart, stat cards, system intelligence, or protection summary
- No backend/API changes
- No real pipeline timing instrumentation
