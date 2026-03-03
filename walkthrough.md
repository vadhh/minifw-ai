
# MiniFW-AI Security Code Review (Re-Assessment)

> **Review Date:** 2026-01-27
> **Reviewer Role:** Senior Principal Software Architect & Security Researcher  
> **Project:** MiniFW-AI Network Gateway Firewall  

---

## 1. Executive Summary

| Metric | Value | Change |
|--------|-------|--------|
| **Code Health Score** | **4/10** | 🔼 +1 |
| **Critical Severity Issues** | **5** | 🔽 -2 |
| **High Severity Issues** | **8** | ➖ 0 |
| **Medium Severity Issues** | **4** | 🔽 -1 |

### Assessment
Significant improvements have been made to the **Enforcement Engine** (preventing command injection) and **Docker Configuration** (robust logging, environment variables). A detailed **Attack Simulator** has been added, making the system ready for **functional demos**.

> [!WARNING]
> **Production Status: NOT READY.** 
> Critical blocks remain: **Authentication is still missing** on key admin routes, and the application code **does not load the JWT secret** from the environment (ignoring the new `.env` file).

---

## 2. Dynamic Analysis & New Features

### ✅ Attack Simulation (`scripts/simulate_attack.py`)
A robust testing tool has been added that generates realistic threat scenarios:
- **Scenarios:** Malware, Phishing, Burst/DoS, Lateral Movement, Data Exfiltration.
- **Output:** JSONL format compatible with the dashboard.
- **Quality:** High. The code is well-structured and configurable.

### ✅ Docker Hardening
- **Secrets:** `docker-compose.yml` now uses `.env` file (Fixed CRITICAL-004 definition, but code integration is missing).
- **Logging:** `dnsmasq` container now uses a robust pipe-to-netcat approach for reliable log collection.

---

## 3. Critical Flaws Status

### 🟢 CRITICAL-001 & 006: Command Injection (Enforce) → **FIXED**
**Status:** **Resolved.**
The `enforce.py` module now includes a strict `is_valid_nft_object_name` regex validator. The `ipset_create` and `nft_apply_forward_drop` functions properly validate user input before passing it to `subprocess`.

### 🟢 CRITICAL-002: Hardcoded JWT Secret → **FIXED**
**Status:** **Resolved.**
`app/services/auth/token_service.py` now reads `SECRET_KEY = os.environ["MINIFW_SECRET_KEY"]` and raises `ValueError` at import time if the variable is unset. No hardcoded fallback remains.

### 🟢 CRITICAL-003: Missing Admin Authentication → **FIXED**
**Status:** **Resolved.**
All 40 routes in `app/web/routers/admin.py` now carry `Depends(get_current_user)`. Previously 30 routes were completely unauthenticated; each has been updated with either `_: User = Depends(get_current_user)` (auth-only) or `current_user: User = Depends(get_current_user)` where the user object is passed to the controller.

### 🟢 CRITICAL-005: Default Admin Credentials → **FIXED**
**Status:** **Resolved.**
`scripts/create_admin.py` reads the admin password exclusively from `MINIFW_ADMIN_PASSWORD` environment variable and exits with a non-zero error code if the variable is unset. No default credentials are used.

### 🟢 CRITICAL-007: Path Traversal → **FIXED**
**Status:** **Resolved.**
`update_collectors()` in `app/services/policy/update_policy_service.py` resolves every supplied path with `os.path.realpath()` and verifies it falls within an explicit allowlist (`/var/log`, `/opt/minifw_ai`, `/tmp`) using `Path.is_relative_to()`. Paths outside the allowlist are rejected with `ValueError`.

---

## 4. Architectural & Performance Bottlenecks

### 🟠 HIGH-001: Unbounded Memory Growth in BurstTracker
**Status:** **Unresolved.** `app/minifw_ai/burst.py` still uses a simple `defaultdict(deque)` that never clears old IP entries, leading to memory leaks over time.

### 🟢 HIGH-002: TOCTOU Race Condition in Policy Updates → **FIXED**
**Status:** **Resolved.** A module-level `threading.Lock()` (`_policy_lock`) now serialises all read-modify-write cycles in `update_policy_service.py`. Concurrent admin requests queue up and each sees the latest committed policy before writing.

---

## 5. Summary of Required Actions (Updated)

| Priority | Issue | Status | Notes |
|----------|-------|--------|-------|
| ~~P0~~ | ~~CRITICAL-002~~ | ✅ Fixed | `token_service.py` reads env var, raises on missing |
| ~~P0~~ | ~~CRITICAL-003~~ | ✅ Fixed | All 40 admin routes require `get_current_user` |
| ~~P0~~ | ~~CRITICAL-005~~ | ✅ Fixed | `create_admin.py` requires `MINIFW_ADMIN_PASSWORD` env var |
| ~~P0~~ | ~~CRITICAL-007~~ | ✅ Fixed | Path allowlist + `realpath()` in `update_collectors()` |
| ~~P1~~ | ~~HIGH-002~~ | ✅ Fixed | `threading.Lock()` serialises all policy read-modify-write cycles |
| P1 | HIGH-001 | 🔴 Open | Implement TTL-based eviction in `BurstTracker` |

> [!TIP]
> **Ready for Demo?** YES. The system is functional and includes excellent simulation tools.
> **Ready for Production?** The P0 critical vulnerabilities are resolved. Remaining open item is HIGH-001 (BurstTracker memory growth under sustained load).
