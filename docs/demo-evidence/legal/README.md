# MiniFW-AI Legal Sector — Evidence Pack
**Version:** 2.2.0  
**Scenario:** Clifton & Associates LLP — ransomware C2 + Tor relay + privilege breach
**Evidence captured:** 2026-05-26

---

## What's in This Pack

| File | Purpose |
|------|---------|
| `report/evidence-report.md` | **Main document.** Four blocks with raw JSON + key numbers. |
| `logs/score-timeline.md` | Timeline + ASCII threshold architecture diagram. |
| `logs/block-events.jsonl` | 4 raw block decisions with LEGAL-ACP trace IDs. |
| `screenshots/CAPTURE_GUIDE.md` | Screenshot index (to be captured during demo run). |

---

## The Threshold Architecture (key slide)

```
Partner    ── 85  ← feed+YARA (75) does NOT block
Associate  ── 72  ← feed+YARA (75) DOES block
Paralegal  ── 70
Client     ── 62
Guest      ── 60
```

This is the legal sector's trust hierarchy enforced in real time by a single engine.

## LEGAL-ACP Trace IDs

Every block carries `LEGAL-ACP-*` trace ID and `decision_owner: Legal Privilege Policy Engine`.
Use these as the correlation key in any bar association inquiry or post-incident review.
