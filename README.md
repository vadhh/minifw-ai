# MiniFW-AI — AI Behavioral Firewall Engine

MiniFW-AI is an AI-powered behavioral firewall engine deployed on Linux gateway
hardware. It detects unknown network threats by building behavioral models of
normal traffic and flagging deviations using hard rule gates, threat intelligence
scoring, ML inference (MLP), and YARA pattern matching. Enforcement is performed
at the packet level via nftables/ipset across six vertically-locked sectors
(hospital, school, government, finance, legal, establishment).

## Documentation

| Document | Description |
|----------|-------------|
| [PRD_3_MiniFW-AI_v3.docx](PRD_3_MiniFW-AI_v3.docx) | Product Requirements Document — full requirements, threat model (S14), compliance matrix (S15), quality targets & QA test plan (S16) |
| [CHANGELOG.md](CHANGELOG.md) | Version history and known issues |
| [DEVELOPER.md](DEVELOPER.md) | Developer guidance, architecture reference, and 11-stage development model |
| [TODO.md](TODO.md) | Stage 4 readiness task list |

## Current Development Stage

**Stage 3 — Integration** (core pipeline)

Stage 0 documentation: Complete as of March 2026

Next milestone: Stage 4 (QA) — see [QA_TEST_PLAN.md](QA_TEST_PLAN.md) for entry criteria

## Quick Start

### Run Daemon
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit as needed
export $(cat .env | xargs)
GAMBLING_ONLY=1 python -m app.minifw_ai
```

### Run Web Admin (FastAPI)
```bash
uvicorn app.web.app:app --host 0.0.0.0 --port 8080 --reload
```

### Run Tests
```bash
pytest testing/               # all tests
pytest testing/ -m "not integration"  # skip root/network tests
```
