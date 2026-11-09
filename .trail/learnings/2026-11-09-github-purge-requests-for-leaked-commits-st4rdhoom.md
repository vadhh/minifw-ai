---
title: "GitHub purge requests for leaked commits go through Other support, not Repositories > Deletes"
author: St4rdhoom
date: 2026-11-09
branch: fix/monday-core-20261102
cost: { minutes: 21, tokens: 70147 }
id: l-7a6fbbb5
scope: repo
status: active
src: agent
touches:
  - docs/2026-11-09_financial-closure.md
---

## Decided
- To ask GitHub to purge commits still served by SHA after a branch reset: support.github.com > Other support > category Other ("Sensitive data removal"). GitHub's assistant then routes it as a sensitive-data removal ticket. Give owner/repo, full commit SHAs, number of affected PRs (0 here), and that no forks or branches reference them. 9 Nov request: ticket #4974713.

## Tried and ruled out
- Repositories > Deletes: that topic is for deleting the whole repository (it asks for "the URL of the repository you would like to delete"). Repositories > Repository features has no fitting option either.

## Watch out
- GitHub only purges when rotating the credentials cannot mitigate the risk. If the leaked credentials are already invalidated, expect a decline; containment must not depend on the purge.
