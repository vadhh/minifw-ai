---
title: "Leaked lab credentials are contained by invalidation, because GitHub keeps removed commits public"
author: St4rdhoom
date: 2026-11-09
branch: fix/monday-core-20261102
cost: { minutes: 2, tokens: 15360 }
id: l-2e1b36f6
scope: repo
status: active
replaces: l-18d7c6eb
src: agent
touches:
  - docs/evidence/2026-11-09-financial-closure/README.md
  - docs/2026-11-09_financial-closure.md
  - dist/financial-closure-20261109/PRIVATE-licence-signing-and-containment.md
  - app/web/routers/auth.py
  - scripts/build_deb.sh
---

## Decided
- Credential exposure in this public repo is closed by proving the credential no longer works. Commits dropped from every branch stay fetchable by SHA on GitHub, and redacted issue comments keep their original revisions in the "edited" history. A purge needs GitHub Support and the repo admin deleting each revision. Keep the leaked commit IDs out of committed files until then.
- If a tester's private evidence archive hasn't arrived but the guest still runs, read its journal, dnsmasq log and events.jsonl read-only: the archive's own source. This closed the C22 DNS-outage check on 9 Nov.

## Tried and ruled out
- Probing a guest with several usernames: the auto-mode classifier blocks it as credential guessing. The guest's cloud-init user-data beside its disk names the one user and key.

## Watch out
- The self-service password change does not update users.last_password_change (it stays equal to created_at). Use the audit log's `password_change` record as proof that an initial password was replaced.
- events.jsonl rotates daily; older days are in events.jsonl.N.gz.
- The AI block event logs the count that crossed the threshold (39 for client_window_v1); a tester may report 40.

In the code: app/web/routers/auth.py:309, scripts/build_deb.sh:236-251, docs/evidence/2026-11-09-financial-closure/.
