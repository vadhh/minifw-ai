# Design: Deployable Demo Package — Structure & Credibility Cleanup

**Date:** 2026-05-13  
**Status:** Approved  
**Goal:** Create a professionally structured, reproducible demo package set in `dist/` with a navigational index document and clean folder naming.

---

## Problem

`dist/` has accumulated naming debt and stale artifacts:
- The hospital standalone package is named `minifw-ai-usb-v2.2.0v3` — does not follow the sector-named convention
- Three superseded hospital revisions (`v1`, `v2`) and the original multi-sector demo exist alongside current packages
- The standalone package contains runtime-generated artifacts (`__pycache__`, `logs/`, `minifw.db`)
- `minifw-usb-gambling-v2.2.0` is on disk but absent from the index
- No single document explains the package set to an external reviewer

---

## Approach: Git-aware single-commit cleanup

All changes land in one coherent commit using `git mv` (preserving rename history) and `git rm` (clean staging of deletions). Untracked artifacts are removed via `find` / `rm`.

---

## Section 1 — Renames and Deletions

| Operation | Target |
|---|---|
| `git mv` | `dist/minifw-ai-usb-v2.2.0v3/` → `dist/minifw-usb-hospital-standalone-v2.2.0/` |
| `git rm -rf` | `dist/minifw-usb-hospital-v2.2.0v1/` |
| `git rm -rf` | `dist/minifw-usb-hospital-v2.2.0v2/` |
| `git rm -rf` | `dist/minifw-ai-demo-v2.2.0/` |
| `git rm` | `dist/minifw-ai-demo-v2.2.0.zip` |
| `find -delete` | All `__pycache__/` inside `minifw-usb-hospital-standalone-v2.2.0/` |
| `rm` | `logs/audit.jsonl`, `logs/engine.log`, `minifw.db` inside standalone |

`venv/` is intentionally kept — it makes the standalone offline-ready without a pip install step.

---

## Section 2 — `dist/INDEX.md` Updates

1. Replace `minifw-ai-usb-v2.2.0v3` reference with `minifw-usb-hospital-standalone-v2.2.0`
2. Remove `minifw-usb-hospital-v2.2.0v2` from Current Packages (package deleted)
3. Add `minifw-usb-gambling-v2.2.0` as a current package (port 8448, `admin / Gambling1!`, `bash demo.sh`)
4. Trim Legacy table to remove now-deleted entries; keep a single archived-packages note

---

## Section 3 — `dist/DEMO_PACKAGE_STRUCTURE.md` (new file)

Content scope:
- **Overview table** — all current packages: sector, type (standalone vs Docker), port, credentials, entry point
- **Folder anatomy** — annotated tree for a Docker kit and for the standalone kit
- **Exclusions note** — `venv/` bundled intentionally; `__pycache__`/`logs`/`minifw.db` are runtime-generated, not shipped
- **Reproducibility** — per-package one-liner: `bash HEALTHCHECK.sh` in pre-flight mode
- **Build provenance** — `build_usb.sh` pointer, `v2.2.0` tag, GPG key `BDB471E1FB46F58A`

---

## Post-implementation

- All changes in one commit on `main`
- `dist/INDEX.md` becomes the operational reference; `dist/DEMO_PACKAGE_STRUCTURE.md` is the credibility/reviewer document
