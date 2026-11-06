---
title: "Reviewing independent test evidence: DNS fallback timing, public evidence, client PDFs"
author: St4rdhoom
date: 2026-11-06
branch: fix/monday-core-20261102
cost: { minutes: 24, tokens: 203634 }
touches:
  - docs/delivery/2026-11-06-financial-v2.2.13/recovery-procedure.md
  - docs/delivery/2026-11-06-financial-v2.2.13/release-notes.md
  - docs/delivery/2026-11-06-financial-v2.2.13/setup-guide.md
  - ".DS_Store"
  - ".serena/.gitignore"
  - ".serena/project.yml"
  - docs/.DS_Store
  - docs/2026-11-06_daily-work-report.md
  - docs/2026-11-06_daily-work-report.sha256
  - docs/2026-11-06_financial-c22-recommendation.md
---

## Decided
- Financial v2.2.13 was handed over with the connection-rate AI in shadow mode (management approved 6 Nov), because the customer's segments and exemptions were not available. Turning AI isolation on is the site's step after the shadow review (setup guide sections 14-15).
- Client documents are written in docs/delivery/<date>-<edition>-<version>/*.md and shipped as PDF only. They are rendered with markdown-it-py (commonmark + table) and a headless Chromium --print-to-pdf. The "## Sources" code-provenance section is stripped from the client PDFs and kept in the repo copy.

## Tried and ruled out
- python-markdown for the guides: it breaks the 3-space nested lists under numbered steps. markdown-it-py renders them correctly.
- Brave --headless --print-to-pdf hung here. Playwright's chrome-headless-shell printed in about 3 s.

## Watch out
- The engine drops to BASELINE_PROTECTION 90-120 s after the last DNS query: the 60 s telemetry timeout, then 2 failed checks 30 s apart. It returns 60-90 s after queries resume: 3 healthy checks. A DNS-outage test shorter than about 2 minutes never reaches baseline. Require the `[STATE_TRANSITION]` journal lines as evidence, not the web health 503 (that flips at about 30 s).
- An nft element's `expires` countdown lets you back-compute when a block was added. Use it to cross-check a tester's claimed timeline. It caught a block reported as "after DNS returned" that began before DNS returned.
- The dpkg install log prints the initial ADMIN PASSWORD. Strip it before evidence goes anywhere public; export_public_evidence.py strips only keys, tokens and env secrets. Lab licence/deployment IDs are treated as non-secret in our evidence, but never publish a signed licence file.
- Reports committed to this public repo should describe licence-signing controls neutrally. Keep key locations and who can sign out of them.
