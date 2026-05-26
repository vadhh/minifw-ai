#!/bin/bash
# validate_install.sh — Pre-flight checker for Hospital Standalone Demo
# Run this BEFORE a demo. Prints [ OK ] or [FAIL] for every check.
# No server is started. Safe to run at any time.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PASS=0
FAIL=0
WARN=0

ok()   { echo "[ OK ] $*"; ((PASS++)); }
fail() { echo "[FAIL] $*"; ((FAIL++)); }
warn() { echo "[WARN] $*"; ((WARN++)); }
hdr()  { echo ""; echo "── $* ──────────────────────────────"; }

# ── Python ────────────────────────────────────────────────────────────────────
hdr "Python"
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$MAJOR" -ge 3 && "$MINOR" -ge 10 ]]; then
        ok "Python $PY_VER (≥ 3.10)"
    else
        fail "Python $PY_VER — need 3.10+. Install: sudo apt install python3.11"
    fi
else
    fail "python3 not found — install: sudo apt install python3"
fi

# ── Virtual Environment ───────────────────────────────────────────────────────
hdr "Virtual Environment"
if [[ -f venv/bin/activate ]]; then
    ok "venv/bin/activate exists"
    source venv/bin/activate 2>/dev/null
    if python3 -c "import fastapi" 2>/dev/null; then
        ok "fastapi importable"
    else
        fail "fastapi not importable — run: pip install -r requirements.txt"
    fi
    if python3 -c "import uvicorn" 2>/dev/null; then
        ok "uvicorn importable"
    else
        fail "uvicorn not importable — run: pip install -r requirements.txt"
    fi
    if python3 -c "import sqlalchemy" 2>/dev/null; then
        ok "sqlalchemy importable"
    else
        fail "sqlalchemy not importable — run: pip install -r requirements.txt"
    fi
    if python3 -c "import bcrypt" 2>/dev/null; then
        ok "bcrypt importable"
    else
        warn "bcrypt not importable — auth may fail without it"
    fi
    if python3 -c "import yara" 2>/dev/null; then
        ok "yara-python importable"
    else
        warn "yara-python not importable — YARA scanning disabled"
    fi
else
    fail "venv/ not found — run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
fi

# ── Network: Port 8000 ────────────────────────────────────────────────────────
hdr "Network"
if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ':8000'; then
        fail "Port 8000 already in use — run: lsof -ti:8000 | xargs kill -9"
    else
        ok "Port 8000 free"
    fi
elif command -v lsof >/dev/null 2>&1; then
    if lsof -ti:8000 >/dev/null 2>&1; then
        fail "Port 8000 already in use"
    else
        ok "Port 8000 free"
    fi
else
    warn "Cannot check port 8000 (no ss or lsof) — verify manually"
fi

# ── Core Files ────────────────────────────────────────────────────────────────
hdr "Core Files"
REQUIRED_FILES=(
    "run_demo.sh"
    "fast_reset.sh"
    "INSTALL.md"
    "DEMO_SCRIPT.md"
    "PRESENTER_CARD.md"
    "scheduler/demo_scheduler.py"
    "app/minifw_ai/main.py"
    "app/web/app.py"
    "config/policy.json"
    "demo_data/normal_traffic.json"
    "demo_data/attack_traffic.json"
)
for f in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        ok "$f"
    else
        fail "$f missing"
    fi
done

# ── YARA Rules ────────────────────────────────────────────────────────────────
hdr "YARA Rules"
YARA_COUNT=$(find yara_rules/ -name "*.yar" 2>/dev/null | wc -l)
if [[ "$YARA_COUNT" -eq 1 ]]; then
    YARA_FILE=$(find yara_rules/ -name "*.yar" | head -1)
    ok "1 YARA file: $YARA_FILE"
    if python3 -c "import yara" 2>/dev/null; then
        if python3 -c "
import yara, glob
rules = {f: open(f).read() for f in glob.glob('yara_rules/*.yar')}
yara.compile(sources=rules)
print('compiled')
" 2>/dev/null | grep -q compiled; then
            ok "YARA rules compile without error"
        else
            fail "YARA rules failed to compile — check yara_rules/*.yar syntax"
        fi
    else
        warn "yara-python not installed — skipping YARA compile check"
    fi
elif [[ "$YARA_COUNT" -eq 0 ]]; then
    fail "No .yar files in yara_rules/ — YARA scanning will be disabled"
else
    warn "$YARA_COUNT YARA files found — expected exactly 1 (hospital_rules.yar); extra files may cause cross-sector contamination"
fi

# ── Logs Directory ────────────────────────────────────────────────────────────
hdr "Logs"
mkdir -p logs
if [[ -w logs ]]; then
    ok "logs/ directory is writable"
else
    fail "logs/ is not writable — check permissions"
fi

STALE_EVENTS=""
if [[ -f logs/events.jsonl ]]; then
    STALE_EVENTS=$(wc -l < logs/events.jsonl)
    warn "logs/events.jsonl exists ($STALE_EVENTS lines) — dashboard will show old events. Run: bash fast_reset.sh"
else
    ok "logs/events.jsonl does not exist (clean start)"
fi

if [[ -f minifw.db ]]; then
    warn "minifw.db exists from a prior run — if dashboard shows stale data, run: bash fast_reset.sh"
else
    ok "minifw.db does not exist (clean start)"
fi

# ── Config ────────────────────────────────────────────────────────────────────
hdr "Configuration"
if python3 -c "import json; json.load(open('config/policy.json'))" 2>/dev/null; then
    ok "config/policy.json is valid JSON"
else
    fail "config/policy.json is invalid JSON or missing"
fi

PRODUCT_MODE_IN_POLICY=$(python3 -c "
import json
p = json.load(open('config/policy.json'))
print(p.get('product_mode', p.get('sector', 'NOT_FOUND')))
" 2>/dev/null || echo "error")
if echo "$PRODUCT_MODE_IN_POLICY" | grep -qi "hospital"; then
    ok "policy.json sector: $PRODUCT_MODE_IN_POLICY"
else
    warn "policy.json sector: $PRODUCT_MODE_IN_POLICY (expected hospital)"
fi

# ── App Import Smoke Test ─────────────────────────────────────────────────────
hdr "App Import Test"
export MINIFW_SECRET_KEY="validate-preflight-key"
export MINIFW_SECTOR="hospital"
export PRODUCT_MODE="minifw_hospital"
export PYTHONPATH="$(pwd):$(pwd)/app"
if python3 -c "from app.minifw_ai.events import Event, EventWriter" 2>/dev/null; then
    ok "app.minifw_ai.events imports OK"
else
    fail "app.minifw_ai.events import failed — PYTHONPATH or app/ issue"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo " RESULT: $PASS passed  $FAIL failed  $WARN warnings"
echo "═══════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    echo " STOP. Fix the failures above before running the demo."
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    echo " READY (with warnings — review before a client demo)."
    exit 0
else
    echo " ALL CLEAR. System is ready for demo."
    exit 0
fi
