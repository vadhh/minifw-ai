---
title: "Send a client package's SHA-256 by a different channel than the package"
author: St4rdhoom
date: 2026-11-09
branch: fix/monday-core-20261102
cost: { minutes: 12, tokens: 68817 }
id: l-4eb6f41a
scope: repo
status: active
src: agent
touches:
  - docs/2026-11-09_financial-closure.md
  - docs/delivery/2026-11-06-financial-v2.2.13/handover.md
---

## Decided
- A client handoff zip goes through the private file share, and its SHA-256 goes separately (chat, email, phone) so the recipient can check the download. The 6 Nov Financial package went through sydecloud without its hash; it was sent afterwards as a closure item.

## Tried and ruled out
- Relying on the SHA256SUMS file inside the zip: it vouches for the files in the zip only if the zip itself is genuine, so it cannot replace the separately sent zip hash.

## Watch out
- A daily report committed before the send will still say "not sent". Record the actual send time, recipient and channel in the closure record, not by editing the old report (it has a .sha256).

In the code: docs/2026-11-09_financial-closure.md (delivery row), docs/delivery/2026-11-06-financial-v2.2.13/handover.md ("Check the files").
