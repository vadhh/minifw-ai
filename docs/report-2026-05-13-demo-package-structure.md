# Demo Package Structure — Implementation Report

**Date:** 2026-05-13  
**Scope:** `dist/` directory — all demo packages  
**Goal:** Establish deployable credibility through consistent folder naming, removal of archived packages, clean runtime artifact state, and a reviewer-facing structure document.  
**Result:** All 5 tasks complete. 2 commits (spec/plan + cleanup). Working tree clean. Pushed to `main`.

---

## Summary

| Area | Before | After |
|------|--------|-------|
| Standalone package name | `minifw-ai-usb-v2.2.0v3/` | `minifw-usb-hospital-standalone-v2.2.0/` |
| Archived packages in `dist/` | 4 (hospital-v1, hospital-v2, demo-v2.2.0, demo zip) | 0 |
| Runtime artifacts in standalone | `__pycache__/`, `logs/`, `minifw.db` present | Removed (venv kept) |
| Gambling sector in index | Missing | Listed as current package |
| Reviewer document | None | `dist/DEMO_PACKAGE_STRUCTURE.md` |

---

## Files Delivered

### `dist/` — renames and deletions

| Operation | Target | Method |
|-----------|--------|--------|
| Rename | `minifw-ai-usb-v2.2.0v3/` → `minifw-usb-hospital-standalone-v2.2.0/` | `git mv` (history preserved, 100% similarity) |
| Delete | `minifw-usb-hospital-v2.2.0v1/` | `rm -rf` (untracked) |
| Delete | `minifw-usb-hospital-v2.2.0v2/` | `rm -rf` (untracked) |
| Delete | `minifw-ai-demo-v2.2.0/` | `rm -rf` (untracked) |
| Delete | `minifw-ai-demo-v2.2.0.zip` | `rm -f` (untracked) |
| Remove | `__pycache__/` (standalone) | `find -exec rm -rf` |
| Remove | `logs/audit.jsonl`, `logs/engine.log` (standalone) | `rm -f` |
| Remove | `minifw.db` (standalone) | `rm -f` |

### `dist/INDEX.md` — modified

| Change | Detail |
|--------|--------|
| Standalone reference updated | `minifw-ai-usb-v2.2.0v3` → `minifw-usb-hospital-standalone-v2.2.0` |
| Hospital Docker v2 row removed | Package deleted; row removed from Current Packages table |
| Gambling sector added | New section: port 8446, `admin / Gambling1!`, `bash demo.sh` |
| Port table updated | 4 entries: Hospital Docker (8443), Hospital Standalone (8000), Education (8447), Gambling (8446) |
| Legacy table cleaned | Replaced superseded rows with a single git-history pointer note |
| Build commands updated | Added `bash build_usb.sh education` and `bash build_usb.sh gambling` |

### `dist/DEMO_PACKAGE_STRUCTURE.md` — new

| Section | Content |
|---------|---------|
| Current Packages | Overview table: all 4 packages with sector, type, port, credentials, entry point |
| Folder Anatomy | Annotated tree for Docker USB kit and standalone kit |
| What Is and Is Not Shipped | Table: venv ✅, images/*.tar ✅, __pycache__ ❌, logs contents ❌, minifw.db ❌ |
| Reproducibility | Per-package pre-flight: `bash HEALTHCHECK.sh` → 11/11 PASS |
| Build Provenance | Version tag `v2.2.0`, GPG key `BDB471E1FB46F58A`, `git verify-tag v2.2.0` |

---

## Current `dist/` State

```
dist/
├── DEMO_PACKAGE_STRUCTURE.md          ← new — reviewer/handoff document
├── INDEX.md                           ← updated — 4 current packages listed
├── minifw-usb-education-v2.2.0/       ← Docker kit, port 8447
├── minifw-usb-gambling-v2.2.0/        ← Docker kit, port 8446 (now indexed)
├── minifw-usb-hospital-standalone-v2.2.0/  ← renamed from minifw-ai-usb-v2.2.0v3
└── minifw-usb-hospital-v2.2.0/        ← Docker kit, port 8443
```

---

## Commits

| SHA | Message |
|-----|---------|
| `71c290b` | `docs: add demo package structure spec and implementation plan` |
| `0776900` | `chore(dist): rename standalone package, remove archived packages, add DEMO_PACKAGE_STRUCTURE.md` |
