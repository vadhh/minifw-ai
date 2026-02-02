# Operational Hygiene Implementation

This document describes the operational hygiene security controls implemented for MiniFW-AI.

## Implemented Features

### 1. Password Change on First Login (P0 - Critical)

**Purpose:** Force users to change their generated password immediately after their first successful login.

**Implementation:**
- Added `must_change_password` field to User model (already existed at line 56)
- Modified login endpoint (`app/web/routers/auth.py`) to check flag after authentication
- Updated `create_user` function to set `must_change_password=True` by default for new users
- Added middleware check in `app/middleware/auth_middleware.py` to block dashboard access
- Change password endpoint clears the flag and logs the event

**User Experience:**
- New users are redirected to `/auth/change-password?force=1` on first login
- Users cannot access dashboard or other protected routes until password is changed
- After password change, users are forced to re-login with their new password

### 2. Login Rate Limiting (P1)

**Purpose:** Prevent brute-force attacks on the web dashboard.

**Implementation:**
- Created `app/middleware/rate_limiter.py` with Token Bucket algorithm
- Applied rate limiter to `POST /auth/login` endpoint
- Policy: **5 failed attempts per minute per IP address**
- Returns HTTP 429 "Too Many Requests" with `Retry-After` header
- Custom error handler in `app/web/app.py` shows user-friendly message

**Technical Details:**
- In-memory rate limiter (no external dependencies)
- Per-IP tracking with automatic cleanup
- Thread-safe implementation with Lock
- Respects X-Forwarded-For header for proxy scenarios

### 3. Audit Log Rotation (P2)

**Purpose:** Prevent `audit.jsonl` from consuming all disk space while preserving evidence.

**Implementation:**
- Created `config/minifw-audit.logrotate` configuration file
- Rotation rules:
  - Rotate daily
  - Retain 30 days of logs
  - Compress old logs
  - Preserve permissions (640 minifw adm)
- Updated `scripts/install_systemd.sh` to install logrotate config to `/etc/logrotate.d/`

**Testing:**
```bash
# Dry-run test (safe, doesn't actually rotate)
sudo logrotate -d /etc/logrotate.d/minifw-audit

# Force rotation (for testing)
sudo logrotate -f /etc/logrotate.d/minifw-audit
```

### 4. CI/CD Discipline

**Purpose:** Ensure we don't regress on the audit binding logic.

**Implementation:**
- Added explicit comment to `TestDetectionEnforcementBinding` in `scripts/verify_sprint.py`
- Marked as "CRITICAL CI/CD COMPONENT - DO NOT REMOVE"
- Ensures detection-to-enforcement UUID binding remains functional

## Verification

### Unit Tests

Run the comprehensive unit test suite:

```bash
cd /home/runner/work/minifw-ai/minifw-ai
python3 testing/test_ops_hygiene.py
```

This tests:
- Rate limiter Token Bucket algorithm
- User model has `must_change_password` field
- All code changes are in place
- File structure is correct

### Shell Script Verification

Run the shell-based verification script:

```bash
cd /home/runner/work/minifw-ai/minifw-ai
bash scripts/verification_ops.sh
```

This verifies:
- Logrotate configuration validity
- Rate limiting behavior (requires web service running)
- Password change enforcement in code
- CI/CD test presence

## Security Properties

### Fail-Closed Behavior

All security controls are designed to fail closed:

1. **Rate Limiter:** If limiter check fails, request is blocked (not allowed)
2. **Password Change:** If flag check fails, user is redirected (not allowed through)
3. **Audit Logging:** Operations log before execution; missing logs mean audit trail exists

### Thread Safety

- Rate limiter uses threading.Lock for thread-safe operations
- Token bucket refill is atomic
- No race conditions in request counting

### Production Considerations

1. **Rate Limiter Cleanup:**
   - Automatic cleanup removes stale entries (>1 hour old)
   - Call `login_rate_limiter.cleanup_old_entries()` periodically if needed
   - Consider moving to Redis for distributed deployments

2. **Logrotate:**
   - Installed by `install_systemd.sh` automatically
   - Runs daily via cron (typically 3 AM)
   - Compressed logs saved for compliance (30 days)

3. **Password Policy:**
   - Current minimum: 8 characters
   - Cannot reuse old password
   - Future: Add complexity requirements, password history

## File Changes Summary

### New Files
- `app/middleware/rate_limiter.py` - Token Bucket rate limiter
- `config/minifw-audit.logrotate` - Logrotate configuration
- `scripts/verification_ops.sh` - Verification script
- `testing/test_ops_hygiene.py` - Unit tests

### Modified Files
- `app/web/routers/auth.py` - Login rate limiting, password change enforcement
- `app/middleware/auth_middleware.py` - Dashboard access blocking
- `app/services/auth/user_service.py` - create_user sets must_change_password
- `app/web/app.py` - Custom error handlers for 429 and password change
- `scripts/verify_sprint.py` - CRITICAL comment added
- `scripts/install_systemd.sh` - Logrotate installation

## Testing in Development

To manually test rate limiting:

```bash
# Start web service
export MINIFW_SECRET_KEY=$(openssl rand -hex 32)
export PYTHONPATH=$(pwd):$(pwd)/app
python3 -m uvicorn app.web.app:app --host 127.0.0.1 --port 8000

# In another terminal, test rate limiting
for i in {1..7}; do
  echo "Attempt $i:"
  curl -X POST http://127.0.0.1:8000/auth/login \
    -d "username=test&password=wrong" \
    -w "\nHTTP Status: %{http_code}\n\n"
done
```

Expected: First 5 attempts return errors, 6th attempt returns 429.

## Compliance Notes

These controls address:
- **NIST 800-53:** AC-7 (Unsuccessful Logon Attempts), IA-5 (Authenticator Management)
- **CIS Controls:** 4.3 (Configure Account Lockout), 5.2 (Collect Audit Logs)
- **SOC 2:** CC6.1 (Logical Access Controls), CC7.2 (System Operations)

## Future Enhancements

1. **Rate Limiter:**
   - Move to Redis for multi-instance deployments
   - Add progressive delay (exponential backoff)
   - CAPTCHA after N failures

2. **Password Policy:**
   - Password complexity requirements
   - Password expiration (90 days)
   - Password history (prevent reuse of last 5 passwords)

3. **Audit Logs:**
   - Forward to SIEM (Splunk, ELK)
   - Real-time alerting on security events
   - Encrypted log storage
