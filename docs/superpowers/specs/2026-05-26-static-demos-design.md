# Static Demo Pages — Design Spec
**Date:** 2026-05-26  
**Scope:** 4 minifw-ai sectors (Financial, Healthcare, Education, Legal)  
**RITAPI:** separate repo, out of scope here

---

## Goal

Add a `static/index.html` to each of the 4 sector dist packages. The page opens directly in a browser — no Python, no Docker, no server. It shows the architecture diagram, a screenshot walkthrough (where screenshots exist), and a block-event log table. Used as the STATIC tier in the product demo lineup.

---

## Sectors and Source Evidence

| Product | Dist package | Evidence path | Screenshots | Block events |
|---|---|---|---|---|
| MINIFW-AI_FINANCIAL | `dist/minifw-usb-financial-standalone-v2.2.0/` | `docs/demo-evidence/financial/` | 13 (named) | yes |
| MINIFW-AI_HEALTHCARE | `dist/minifw-usb-hospital-standalone-v2.2.0/` | `docs/demo-evidence/hospital/` | none | yes |
| MINIFW-AI_SCHOOLS | `dist/minifw-usb-education-v2.2.0/` | `docs/demo-evidence/education/` | 6 (dated) | yes |
| MINIFW-AI_LEGAL | `dist/minifw-usb-legal-v2.2.0/` | `docs/demo-evidence/legal/` | none | yes |

---

## Output Structure (per sector)

```
dist/<package>/static/
    index.html          — self-contained, all styles inlined
    screenshots/        — copied from docs/demo-evidence/{sector}/screenshots/
    architecture.svg    — copied from docs/demo-evidence/{sector}/report/
```

---

## Page Layout

Each `index.html` is a single scrollable page with these sections in order:

1. **Header** — product name, version badge, sector tagline, sector colour accent
2. **Architecture** — `architecture.svg` embedded as `<img>` with full-width display
3. **Demo Walkthrough** — present only if screenshots exist; each screenshot shown with a caption derived from the filename or a hardcoded dict keyed by filename
4. **Block Event Log** — table rendered from the sector's `block-events.jsonl` data baked inline; columns: timestamp, host, domain, score, action (colour-coded: BLOCK=red, MONITOR=amber, ALLOW=green)
5. **Footer** — sector lock string, version, GPG key fingerprint `BDB471E1FB46F58A`

---

## Sector Styling

| Sector | Accent colour | Compliance tagline |
|---|---|---|
| Financial | `#1a3a5c` deep blue | PCI-DSS / Trading Floor Protection |
| Healthcare | `#0d6b6b` teal | HIPAA / IoMT Protection |
| Education | `#b45309` amber | SafeSearch / Student Network Protection |
| Legal | `#1e3a5f` navy | Attorney-Client Privilege Protection |

Dark background (`#0f1117`), white body text, monospace for log table.

---

## Build Script

**Path:** `tools/build_static_demos.py`  
**Run:** `python3 tools/build_static_demos.py` from repo root  
**Dependencies:** stdlib only (`pathlib`, `json`, `shutil`, `base64`)

The script:
1. Iterates over a sector config dict (sector → dist path, evidence path, accent colour, tagline)
2. Reads `block-events.jsonl` and parses up to 50 most recent events
3. Collects screenshots (sorted by filename) if the screenshots dir is non-empty
4. Copies assets into `dist/<package>/static/`
5. Renders and writes `index.html`

Caption mapping for financial screenshots is derived from the filename (replace `-` with spaces, strip leading index number). Education screenshots use the capture timestamp as caption with a generic label.

---

## What Is Not In Scope

- Interactive filtering of the log table (static only)
- Live data refresh
- RITAPI ADVANCED or RITAPI V-SENTINEL (separate repo)
- Government or Establishment sectors (not in the product lineup provided)
