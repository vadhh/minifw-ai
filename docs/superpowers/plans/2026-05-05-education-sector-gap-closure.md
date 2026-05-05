# Education Sector — Implementation Gap Closure Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire five declared-but-inert education sector flags into the engine and fix a sector icon key mismatch in two dashboard templates.

**Architecture:** Three layers of change — (1) extend the `Event` dataclass with 3 optional fields, (2) wire sector flags in `main.py`'s startup block and event-write path, (3) fix a JS key in two Jinja2 templates. No new modules, no system dependencies. All changes are isolated and independently testable.

**Tech Stack:** Python 3.10+, dataclasses, ipaddress stdlib, Jinja2 HTML templates, pytest.

---

## File Map

| Action | Path | Change |
|--------|------|--------|
| Modify | `app/minifw_ai/events.py` | Add 3 optional fields to `Event` dataclass |
| Modify | `app/minifw_ai/main.py` | Add `_ip_in_subnets` helper; wire 5 flags in startup + event-write path |
| Modify | `app/web/templates/admin/events.html` | Fix `school` → `education` in sectorIcons JS object |
| Modify | `app/web/templates/admin/partials/scripts.html` | Fix `school` → `education` in sectorIcons JS object |
| Modify | `testing/test_education_sector.py` | Append 4 new unit tests |

---

## Task 1: Extend the Event dataclass

**Files:**
- Modify: `app/minifw_ai/events.py`
- Test: `testing/test_education_sector.py`

The `Event` dataclass is serialized with `dataclasses.asdict()`, so any new per-event flags must be declared as fields here. Three flags are needed: `student_flagged`, `vpn_block_enforced`, `audit_mode`. All default to `False` so existing event creation sites need no changes.

- [ ] **Step 1.1: Write the failing test**

Append to `testing/test_education_sector.py`:

```python
# ── Task 1: Event dataclass fields ───────────────────────────────────────────

def test_event_has_student_flagged_field():
    """Event must have student_flagged=False by default."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.events import Event
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="student",
        client_ip="10.10.0.1",
        domain="example.com",
        action="allow",
        score=0,
        reasons=[],
    )
    assert hasattr(ev, "student_flagged")
    assert ev.student_flagged is False


def test_event_has_vpn_block_enforced_field():
    """Event must have vpn_block_enforced=False by default."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.events import Event
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="student",
        client_ip="10.10.0.1",
        domain="example.com",
        action="block",
        score=80,
        reasons=["yara_EducationVpnProxy"],
    )
    assert hasattr(ev, "vpn_block_enforced")
    assert ev.vpn_block_enforced is False


def test_event_has_audit_mode_field():
    """Event must have audit_mode=False by default."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.events import Event
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="staff",
        client_ip="192.168.1.1",
        domain="example.com",
        action="allow",
        score=0,
        reasons=[],
    )
    assert hasattr(ev, "audit_mode")
    assert ev.audit_mode is False
```

- [ ] **Step 1.2: Run to confirm failure**

```bash
cd /home/sydeco/minifw-ai
PYTHONPATH=app pytest testing/test_education_sector.py::test_event_has_student_flagged_field -v
```

Expected: `FAILED — AttributeError: Event has no attribute 'student_flagged'`

- [ ] **Step 1.3: Add the three fields to the Event dataclass**

In `app/minifw_ai/events.py`, the current `Event` dataclass ends at `decision_owner`. Add three optional boolean fields after `decision_owner`:

```python
@dataclass
class Event:
    ts: str
    segment: str
    client_ip: str
    domain: str
    action: str
    score: int
    reasons: list[str]
    sector: str = "unknown"
    severity: str = "info"
    trace_id: str = ""
    decision_owner: str = "Policy Engine"
    student_flagged: bool = False
    vpn_block_enforced: bool = False
    audit_mode: bool = False
```

- [ ] **Step 1.4: Run all three new tests**

```bash
PYTHONPATH=app pytest testing/test_education_sector.py::test_event_has_student_flagged_field \
  testing/test_education_sector.py::test_event_has_vpn_block_enforced_field \
  testing/test_education_sector.py::test_event_has_audit_mode_field -v
```

Expected: `3 passed`

- [ ] **Step 1.5: Run the full test suite — no regressions**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `249 passed, 1 skipped, 0 failed` (246 existing + 3 new)

- [ ] **Step 1.6: Commit**

```bash
git add app/minifw_ai/events.py testing/test_education_sector.py
git commit -m "feat(education): extend Event dataclass with student_flagged, vpn_block_enforced, audit_mode fields"
```

---

## Task 2: Add `_ip_in_subnets` helper

**Files:**
- Modify: `app/minifw_ai/main.py`
- Test: `testing/test_education_sector.py`

A small pure function using stdlib `ipaddress`. It is needed by the `log_student_activity` wiring in Task 3. Testing it in isolation means Task 3 tests can trust the helper.

Note: `ipaddress` is already in the Python stdlib — no new dependency.

- [ ] **Step 2.1: Write the failing test**

Append to `testing/test_education_sector.py`:

```python
# ── Task 2: _ip_in_subnets helper ────────────────────────────────────────────

def test_ip_in_subnets_returns_true_for_student_ip():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("10.10.0.5", ["10.10.0.0/16"]) is True


def test_ip_in_subnets_returns_false_for_staff_ip():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("192.168.1.5", ["10.10.0.0/16"]) is False


def test_ip_in_subnets_returns_false_for_invalid_ip():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.main import _ip_in_subnets
    assert _ip_in_subnets("not-an-ip", ["10.10.0.0/16"]) is False
```

- [ ] **Step 2.2: Run to confirm failure**

```bash
PYTHONPATH=app pytest testing/test_education_sector.py::test_ip_in_subnets_returns_true_for_student_ip -v
```

Expected: `FAILED — ImportError: cannot import name '_ip_in_subnets' from 'minifw_ai.main'`

- [ ] **Step 2.3: Add the helper to `app/minifw_ai/main.py`**

`ipaddress` is already in the stdlib. Add the import at the top of `main.py` (after the existing stdlib imports, before the project imports — around line 7):

```python
import ipaddress
```

Then add the helper function immediately before the `run()` function definition (search for `def run(` and insert before it):

```python
def _ip_in_subnets(ip: str, subnets: list[str]) -> bool:
    """Return True if ip falls within any of the given CIDR subnets."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(s, strict=False) for s in subnets)
    except ValueError:
        return False
```

- [ ] **Step 2.4: Run the three new tests**

```bash
PYTHONPATH=app pytest testing/test_education_sector.py::test_ip_in_subnets_returns_true_for_student_ip \
  testing/test_education_sector.py::test_ip_in_subnets_returns_false_for_staff_ip \
  testing/test_education_sector.py::test_ip_in_subnets_returns_false_for_invalid_ip -v
```

Expected: `3 passed`

- [ ] **Step 2.5: Full suite — no regressions**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `252 passed, 1 skipped, 0 failed`

- [ ] **Step 2.6: Commit**

```bash
git add app/minifw_ai/main.py testing/test_education_sector.py
git commit -m "feat(education): add _ip_in_subnets helper to main.py"
```

---

## Task 3: Wire sector flags in `main.py`

**Files:**
- Modify: `app/minifw_ai/main.py`

Two insertion points: the startup block (for `force_safesearch` and VPN/proxy logging) and the event-write path (for `log_student_activity`, `vpn_block_enforced`, and `strict_logging`).

### 3A — Startup block

**Where:** In `app/minifw_ai/main.py`, inside the `if SECTOR_LOCK_AVAILABLE:` block, after the Tor exit node loading block (the block that ends around line 406 with `logging.info(f"[SECTOR_LOCK] Tor/anonymizer blocking enabled...")`). Insert immediately after that block, before the `# Get IoMT subnets` comment.

- [ ] **Step 3.1: Wire `force_safesearch` and `block_vpns`/`block_proxies` at startup**

Insert the following block after the Tor loading block in `main.py`:

```python
            # Education sector: SafeSearch domain protection
            if sector_config.get("force_safesearch"):
                safesearch_domains = sector_config.get("safesearch_domains", [])
                feeds.allow_domains.extend(safesearch_domains)
                logging.info(
                    f"[SECTOR_LOCK] SafeSearch enforcement: protected {len(safesearch_domains)} domains from blocking"
                )

            # Education sector: VPN/proxy blocking confirmation
            if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
                logging.info(
                    "[SECTOR_LOCK] VPN/proxy blocking active — entries loaded via school_blacklist.txt"
                )
```

- [ ] **Step 3.2: Verify the startup block inserts correctly — run the full suite**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `252 passed, 1 skipped, 0 failed` (no change — startup code runs at daemon launch, not in unit tests)

### 3B — Event-write path

**Where:** In `app/minifw_ai/main.py`, inside the main event loop, after the `ev = Event(...)` block and after the `if sector_config.get("redact_payloads"):` block (currently around line 841–843). Insert before the `writer.write(ev)` call.

The code currently looks like:

```python
            # HIPAA: Redact domain/SNI from event logs when sector requires it
            if sector_config.get("redact_payloads"):
                ev.domain = "[REDACTED]"

            writer.write(ev)
```

- [ ] **Step 3.3: Insert the three event-write-path flag checks**

Replace that block with:

```python
            # HIPAA: Redact domain/SNI from event logs when sector requires it
            if sector_config.get("redact_payloads"):
                ev.domain = "[REDACTED]"

            # Education: tag events from student subnet
            if sector_config.get("log_student_activity"):
                student_subnets = pol.cfg.get("segment_subnets", {}).get("student", [])
                if _ip_in_subnets(client_ip, student_subnets):
                    ev.student_flagged = True

            # Education: tag events where VPN/proxy YARA rule fired
            if sector_config.get("block_vpns") or sector_config.get("block_proxies"):
                if any("VpnProxy" in r for r in ev.reasons):
                    ev.vpn_block_enforced = True

            # Strict-logging sectors: mark all events as audit-mode
            if sector_config.get("strict_logging"):
                ev.audit_mode = True

            writer.write(ev)
```

- [ ] **Step 3.4: Run the full test suite**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `252 passed, 1 skipped, 0 failed`

- [ ] **Step 3.5: Commit**

```bash
git add app/minifw_ai/main.py
git commit -m "feat(education): wire force_safesearch, block_vpns, log_student_activity, strict_logging flags in engine"
```

---

## Task 4: Fix sector icon key in templates

**Files:**
- Modify: `app/web/templates/admin/events.html`
- Modify: `app/web/templates/admin/partials/scripts.html`

The JS `sectorIcons` object uses the key `school` but the sector value in event data is `education`. This causes the mortarboard icon (`bi-mortarboard`) to never render for education-sector events.

- [ ] **Step 4.1: Fix `events.html`**

In `app/web/templates/admin/events.html`, find the line at approximately line 539:

```js
var sectorIcon = {hospital:'bi-hospital',finance:'bi-bank',school:'bi-mortarboard',government:'bi-building',legal:'bi-briefcase',establishment:'bi-shop'}[segment] || 'bi-globe';
```

Change `school:'bi-mortarboard'` to `education:'bi-mortarboard'`:

```js
var sectorIcon = {hospital:'bi-hospital',finance:'bi-bank',education:'bi-mortarboard',government:'bi-building',legal:'bi-briefcase',establishment:'bi-shop'}[segment] || 'bi-globe';
```

- [ ] **Step 4.2: Fix `partials/scripts.html`**

In `app/web/templates/admin/partials/scripts.html`, find the line at approximately line 85:

```js
var sectorIcons = {hospital:'bi-hospital',finance:'bi-bank',school:'bi-mortarboard',government:'bi-building',legal:'bi-briefcase',establishment:'bi-shop'};
```

Change `school:'bi-mortarboard'` to `education:'bi-mortarboard'`:

```js
var sectorIcons = {hospital:'bi-hospital',finance:'bi-bank',education:'bi-mortarboard',government:'bi-building',legal:'bi-briefcase',establishment:'bi-shop'};
```

- [ ] **Step 4.3: Verify both files are fixed**

```bash
grep -n "school" app/web/templates/admin/events.html app/web/templates/admin/partials/scripts.html
```

Expected: no output (zero matches remaining).

```bash
grep -n "education" app/web/templates/admin/events.html app/web/templates/admin/partials/scripts.html
```

Expected: two lines, one per file, showing `education:'bi-mortarboard'`.

- [ ] **Step 4.4: Full test suite**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `252 passed, 1 skipped, 0 failed`

- [ ] **Step 4.5: Commit**

```bash
git add app/web/templates/admin/events.html app/web/templates/admin/partials/scripts.html
git commit -m "fix(education): correct sectorIcons JS key from 'school' to 'education' in both templates"
```

---

## Task 5: Integration smoke test

Verify that the three Event fields appear correctly in serialised output, which is what the dashboard and export features consume.

- [ ] **Step 5.1: Write integration smoke test**

Append to `testing/test_education_sector.py`:

```python
# ── Task 5: Event serialisation ───────────────────────────────────────────────

def test_student_flagged_serialises_to_json():
    """student_flagged must appear in asdict output (used by EventWriter)."""
    import sys, os, json
    from dataclasses import asdict
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.events import Event
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="student",
        client_ip="10.10.0.5",
        domain="nordvpn-bypass.proxy.io",
        action="block",
        score=75,
        reasons=["yara_EducationVpnProxy", "dns_denied_domain"],
        student_flagged=True,
        vpn_block_enforced=True,
        audit_mode=True,
    )
    serialised = json.loads(json.dumps(asdict(ev)))
    assert serialised["student_flagged"] is True
    assert serialised["vpn_block_enforced"] is True
    assert serialised["audit_mode"] is True


def test_event_fields_default_false_in_json():
    """New fields must default to False in serialised output."""
    import sys, os, json
    from dataclasses import asdict
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from minifw_ai.events import Event
    ev = Event(
        ts="2026-01-01T00:00:00+00:00",
        segment="staff",
        client_ip="192.168.1.1",
        domain="khanacademy.org",
        action="allow",
        score=0,
        reasons=[],
    )
    serialised = json.loads(json.dumps(asdict(ev)))
    assert serialised["student_flagged"] is False
    assert serialised["vpn_block_enforced"] is False
    assert serialised["audit_mode"] is False
```

- [ ] **Step 5.2: Run the new tests**

```bash
PYTHONPATH=app pytest testing/test_education_sector.py::test_student_flagged_serialises_to_json \
  testing/test_education_sector.py::test_event_fields_default_false_in_json -v
```

Expected: `2 passed`

- [ ] **Step 5.3: Run the full suite — final gate**

```bash
PYTHONPATH=app pytest testing/ -m "not integration" -q
```

Expected: `254 passed, 1 skipped, 0 failed`

- [ ] **Step 5.4: Commit**

```bash
git add testing/test_education_sector.py
git commit -m "test(education): add serialisation smoke tests for new Event fields"
```

---

## Self-Review

### Spec coverage

| Spec requirement | Task |
|---|---|
| Gap 1: `force_safesearch` → extend allow_domains at startup | Task 3A |
| Gap 2: `block_vpns` → startup log + `vpn_block_enforced` event tag | Task 3A + 3B |
| Gap 3: `block_proxies` → same as `block_vpns` | Task 3A + 3B |
| Gap 4: `log_student_activity` → `student_flagged` event field | Task 1 + 3B |
| Gap 5: `strict_logging` → `audit_mode` event field | Task 1 + 3B |
| Gap 6: Icon key `school` → `education` in two templates | Task 4 |
| `_ip_in_subnets` helper needed by Gap 4 | Task 2 |
| Event dataclass extended for new fields | Task 1 |
| 4+ new unit tests | Tasks 1, 2, 5 |
| No regressions in existing 246 tests | Every task |

### Placeholder scan

No TBD, TODO, or "similar to above" patterns. Every step includes the exact code or command.

### Type consistency

- `_ip_in_subnets` defined in Task 2, used in Task 3B — signature `(ip: str, subnets: list[str]) -> bool` matches both sites.
- `ev.student_flagged`, `ev.vpn_block_enforced`, `ev.audit_mode` — fields added in Task 1, assigned in Task 3B, verified in Task 5. Field names are identical across all three tasks.
- `pol.cfg.get("segment_subnets", {}).get("student", [])` — `pol` is `Policy(policy_path)` from line 347 of main.py; `pol.cfg` is confirmed at line 410 (`pol.cfg.get("iomt_subnets", [])`). Same pattern.
- `ev.reasons` — confirmed as `list[str]` at Event definition; `any("VpnProxy" in r for r in ev.reasons)` is safe.
