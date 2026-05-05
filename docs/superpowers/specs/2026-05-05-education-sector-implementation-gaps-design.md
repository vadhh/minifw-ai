# Education Sector — Implementation Gap Closure Design

**Date:** 2026-05-05  
**Scope:** A-only (close declared-but-inert flags; no new features)  
**Approach:** Engine-only wiring — all changes stay inside MiniFW-AI, no system dependencies  

---

## Background

The education sector (`MINIFW_SECTOR=education`, `PRODUCT_MODE=minifw_school`) was delivered in the `feat/education-sector` branch (merged 2026-04-30). Five configuration flags are declared in `app/minifw_ai/sector_config.py` and `config/modes/minifw_school/policy.json` but have no runtime effect. Two template files contain a wrong JS object key that prevents the sector icon from rendering.

This spec closes those gaps without introducing new capabilities.

---

## Gap Inventory

| # | Flag / Key | Declared in | Current runtime effect | Severity |
|---|-----------|-------------|----------------------|----------|
| 1 | `force_safesearch: True` | `sector_config.py` | None — `should_force_safesearch()` never called | Medium |
| 2 | `block_vpns: True` | `sector_config.py` | None — `should_block_vpns()` never called | Medium |
| 3 | `block_proxies: True` | `sector_config.py` | None — key never read in engine | Medium |
| 4 | `log_student_activity: True` | `sector_config.py` | None — key never read in engine | Low |
| 5 | `strict_logging: True` | `sector_config.py` | None — same log behaviour as all sectors | Low |
| 6 | `school` icon key | `events.html:539`, `scripts.html:85` | Sector icon never renders in education mode | Low (visual) |

---

## Architecture

All changes fall into three layers:

```
sector_config.py (data, unchanged)
        ↓
main.py startup hook      ← Gap 1, 2, 3 wired here
main.py event write path  ← Gap 4, 5 wired here
        ↓
events.html / scripts.html ← Gap 6 fixed here
```

No new modules. No new config keys. No system-level dependencies (no dnsmasq, no nft changes).

---

## Detailed Changes

### Gap 1 — `force_safesearch`

**File:** `app/minifw_ai/main.py`  
**Where:** After `feeds.load_sector_feeds(extra_feeds)` call (~line 392)

**Behaviour:** When `force_safesearch=True`, add all `safesearch_domains` from sector config into `feeds.allow_domains`. This guarantees that `google.com`, `bing.com`, `youtube.com`, and `duckduckgo.com` can never be blocked by a deny feed entry or future policy change — they are unconditionally allowed.

Detection of SafeSearch bypass patterns is already handled by the `EducationSafeSearchBypass` YARA rule. This change protects the legitimate domains from false positives.

```python
if sector_config.get("force_safesearch"):
    safesearch_domains = sector_config.get("safesearch_domains", [])
    feeds.allow_domains.extend(safesearch_domains)
    logger.info(
        f"[SECTOR] SafeSearch enforcement: protected {len(safesearch_domains)} domains from blocking"
    )
```

---

### Gap 2 & 3 — `block_vpns` / `block_proxies`

**File:** `app/minifw_ai/main.py`  
**Where:** Same startup block, immediately after Gap 1 code

**Behaviour:** When either flag is true, log a confirmation that the feed-based VPN/proxy blocking is active. The `school_blacklist.txt` extra feed (already loaded via `extra_feeds`) contains the VPN domain entries — this call confirms they are active and provides a clear audit log entry at startup.

Additionally, in the event write path: when either flag is true and the event's YARA matches include `EducationVpnProxy`, tag the event with `"vpn_block_enforced": true`. This makes the enforcement visible in the event log and dashboard.

```python
# startup
if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
    logger.info(
        "[SECTOR] VPN/proxy blocking active — entries loaded via school_blacklist.txt"
    )

# event write path
if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
    yara_hits = event.get("yara_matches", [])
    if any("VpnProxy" in m for m in yara_hits):
        event["vpn_block_enforced"] = True
```

---

### Gap 4 — `log_student_activity`

**File:** `app/minifw_ai/main.py`  
**Where:** Event write path, near the `redact_payloads` check (~line 841)

**Behaviour:** When `log_student_activity=True`, check whether the event's source IP falls within the `student` subnet(s) defined in `policy.json` (`segment_subnets.student`). If it does, add `"student_flagged": true` to the event JSON. This gives administrators a filterable field for student network activity in the dashboard and exported audit logs.

Uses stdlib `ipaddress` (already importable in the engine context). A small module-level helper `_ip_in_subnets(ip, subnets)` is added — 6 lines.

```python
# module-level helper
import ipaddress

def _ip_in_subnets(ip: str, subnets: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(s, strict=False) for s in subnets)
    except ValueError:
        return False

# event write path
if sector_config.get("log_student_activity"):
    student_subnets = policy.get("segment_subnets", {}).get("student", [])
    src_ip = event.get("src_ip", "")
    if src_ip and _ip_in_subnets(src_ip, student_subnets):
        event["student_flagged"] = True
```

---

### Gap 5 — `strict_logging`

**File:** `app/minifw_ai/main.py`  
**Where:** Event write path, before the existing `writer.write(event)` call

**Behaviour:** Normally, `allow` decisions are not written to the event log (only `monitor` and `block`). When `strict_logging=True`, all actions including `allow` are written. This gives education administrators a complete audit trail of every DNS query, not just policy violations.

```python
action = event.get("action", "")
if action in ("monitor", "block") or sector_config.get("strict_logging"):
    writer.write(event)
```

---

### Gap 6 — Icon key mismatch

**File:** `app/web/templates/admin/events.html:539`  
**File:** `app/web/templates/admin/partials/scripts.html:85`

**Behaviour:** The JS `sectorIcons` object uses `school` as the key but the sector value in event data is `education`. The mortarboard icon (`bi-mortarboard`) never renders. Fix: rename the key.

```js
// Before (both files)
school: 'bi-mortarboard'

// After (both files)
education: 'bi-mortarboard'
```

---

## Data Flow After Fix

```
DNS event (src_ip: 10.10.0.50, domain: nordvpn-bypass.proxy.io)
  → FeedMatcher: domain_denied=True (+40)
  → YARA: EducationVpnProxy match (+35)
  → score_and_decide: score=75 > student block_threshold=70 → BLOCK
  → event write path:
      block_vpns=True + yara hit "VpnProxy" → event["vpn_block_enforced"] = True
      log_student_activity=True + 10.10.0.50 in 10.10.0.0/16 → event["student_flagged"] = True
      strict_logging=True → always written (action=block, so written regardless)
  → EventWriter.write(event)
```

---

## Files Changed

| File | Change type |
|------|------------|
| `app/minifw_ai/main.py` | Add `_ip_in_subnets` helper; wire 5 flags in startup and event write path |
| `app/web/templates/admin/events.html` | Fix `school` → `education` in sectorIcons |
| `app/web/templates/admin/partials/scripts.html` | Fix `school` → `education` in sectorIcons |
| `testing/test_education_sector.py` | Add 4 new unit tests |

---

## Tests

Four new tests appended to `testing/test_education_sector.py`:

| Test | Verifies |
|------|---------|
| `test_safesearch_domains_added_to_allow_list` | When `force_safesearch=True`, `google.com` is in `feeds.allow_domains` after startup hook |
| `test_student_flagged_tag_for_student_ip` | Event with src_ip `10.10.0.5` gets `student_flagged: True` |
| `test_student_flagged_not_set_for_staff_ip` | Event with src_ip `192.168.1.5` has no `student_flagged` key |
| `test_vpn_block_enforced_tag_on_yara_match` | Event with `yara_matches=["EducationVpnProxy"]` gets `vpn_block_enforced: True` |

All existing tests (246 passed, 1 skipped) must continue passing.

---

## Out of Scope

- DNS-level SafeSearch redirection via dnsmasq (Approach 2 — rejected)
- New dashboard pages or widgets
- Feed content expansion (school_blacklist.txt entries)
- Any other sector beyond education
