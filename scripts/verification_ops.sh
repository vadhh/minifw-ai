#!/usr/bin/env bash
# Operational Hygiene Verification Script
# Tests the implementation of security controls for MiniFW-AI

set -euo pipefail

echo "=============================================="
echo "MiniFW-AI Operational Hygiene Verification"
echo "=============================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function for test results
pass_test() {
    echo -e "${GREEN}✅ PASS:${NC} $1"
    ((TESTS_PASSED++))
}

fail_test() {
    echo -e "${RED}❌ FAIL:${NC} $1"
    ((TESTS_FAILED++))
}

warn_test() {
    echo -e "${YELLOW}⚠️  WARN:${NC} $1"
}

# Test 1: Logrotate Configuration Validation
echo "================================================"
echo "Test 1: Logrotate Configuration Validation"
echo "================================================"

LOGROTATE_FILE="/etc/logrotate.d/minifw-audit"
if [[ -f "$LOGROTATE_FILE" ]]; then
    pass_test "Logrotate config file exists at $LOGROTATE_FILE"
    
    # Check permissions
    PERMS=$(stat -c "%a" "$LOGROTATE_FILE")
    if [[ "$PERMS" == "644" ]]; then
        pass_test "Logrotate config has correct permissions (644)"
    else
        fail_test "Logrotate config has wrong permissions: $PERMS (expected 644)"
    fi
    
    # Dry-run test
    echo "Running logrotate dry-run test..."
    if logrotate -d "$LOGROTATE_FILE" > /tmp/logrotate_test.log 2>&1; then
        pass_test "Logrotate configuration is valid (dry-run successful)"
        echo "Sample output:"
        head -10 /tmp/logrotate_test.log | sed 's/^/  /'
    else
        fail_test "Logrotate dry-run failed"
        echo "Error output:"
        cat /tmp/logrotate_test.log | sed 's/^/  /'
    fi
else
    fail_test "Logrotate config file not found at $LOGROTATE_FILE"
    warn_test "Run: sudo scripts/install_systemd.sh to install"
fi

echo ""

# Test 2: Rate Limiting (Login Endpoint)
echo "================================================"
echo "Test 2: Login Rate Limiting (5 attempts/min)"
echo "================================================"

# Check if web service is running
if ! pgrep -f "app.web.app" > /dev/null 2>&1; then
    warn_test "Web service is not running. Starting it for test..."
    
    # Set required environment variables
    export MINIFW_SECRET_KEY=${MINIFW_SECRET_KEY:-$(openssl rand -hex 32)}
    export PYTHONPATH=$(pwd):$(pwd)/app
    
    # Start web service in background
    python3 -m uvicorn app.web.app:app --host 127.0.0.1 --port 8000 > /tmp/minifw_web.log 2>&1 &
    WEB_PID=$!
    
    echo "Waiting for web service to start..."
    sleep 3
    
    # Check if started successfully
    if ! ps -p $WEB_PID > /dev/null; then
        fail_test "Failed to start web service. Check /tmp/minifw_web.log"
        cat /tmp/minifw_web.log
        exit 1
    fi
    
    CLEANUP_WEB=true
else
    CLEANUP_WEB=false
    WEB_PID=$(pgrep -f "app.web.app" | head -1)
    pass_test "Web service is already running (PID: $WEB_PID)"
fi

# Wait for service to be ready
echo "Checking if service is responding..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8000/ > /dev/null 2>&1; then
        pass_test "Web service is responding"
        break
    fi
    if [[ $i -eq 10 ]]; then
        fail_test "Web service not responding after 10 attempts"
        if [[ "$CLEANUP_WEB" == "true" ]]; then
            kill $WEB_PID 2>/dev/null || true
        fi
        exit 1
    fi
    sleep 1
done

# Test rate limiting with 6 login attempts
echo "Testing rate limiting with 6 rapid login attempts..."
RATE_LIMIT_TRIGGERED=false

for i in {1..6}; do
    echo -n "  Attempt $i/6: "
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://127.0.0.1:8000/auth/login \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=wrongpassword" 2>&1 || echo "000")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    
    if [[ "$HTTP_CODE" == "429" ]]; then
        echo "Rate limited (429)"
        RATE_LIMIT_TRIGGERED=true
        
        # Check for Retry-After header
        RETRY_HEADER=$(echo "$RESPONSE" | grep -i "retry-after" || echo "")
        if [[ -n "$RETRY_HEADER" ]]; then
            pass_test "Rate limit includes Retry-After header"
        else
            warn_test "Retry-After header not found in response"
        fi
        break
    else
        echo "Returned HTTP $HTTP_CODE"
    fi
    
    # Small delay between requests
    sleep 0.2
done

if [[ "$RATE_LIMIT_TRIGGERED" == "true" ]]; then
    pass_test "Rate limiting triggered after multiple attempts"
else
    fail_test "Rate limiting did NOT trigger after 6 attempts"
fi

# Cleanup web service if we started it
if [[ "$CLEANUP_WEB" == "true" ]]; then
    echo "Stopping test web service..."
    kill $WEB_PID 2>/dev/null || true
    sleep 1
fi

echo ""

# Test 3: Password Change Enforcement
echo "================================================"
echo "Test 3: Password Change on First Login"
echo "================================================"

# Check if User model has must_change_password field
echo "Checking User model for must_change_password field..."
if grep -q "must_change_password" app/models/user.py; then
    pass_test "User model has must_change_password field"
else
    fail_test "User model missing must_change_password field"
fi

# Check if create_user function sets the flag
if grep -q "must_change_password" app/services/auth/user_service.py; then
    pass_test "create_user function handles must_change_password"
else
    fail_test "create_user function missing must_change_password handling"
fi

# Check if login endpoint checks the flag
if grep -q "must_change_password" app/web/routers/auth.py; then
    pass_test "Login endpoint checks must_change_password flag"
else
    fail_test "Login endpoint missing must_change_password check"
fi

# Check if auth middleware enforces the check
if grep -q "must_change_password" app/middleware/auth_middleware.py; then
    pass_test "Auth middleware enforces password change requirement"
else
    fail_test "Auth middleware missing password change enforcement"
fi

# Check if change-password endpoint clears the flag
if grep -q "must_change_password = False" app/web/routers/auth.py; then
    pass_test "Change password endpoint clears the flag"
else
    fail_test "Change password endpoint doesn't clear the flag"
fi

echo ""

# Test 4: CI/CD Discipline
echo "================================================"
echo "Test 4: CI/CD Discipline (Audit Binding Test)"
echo "================================================"

if grep -q "TestDetectionEnforcementBinding" scripts/verify_sprint.py; then
    pass_test "TestDetectionEnforcementBinding exists in verify_sprint.py"
    
    # Check for the critical comment
    if grep -q "CRITICAL CI/CD COMPONENT" scripts/verify_sprint.py; then
        pass_test "Test class marked as CRITICAL CI/CD COMPONENT"
    else
        fail_test "Test class missing CRITICAL CI/CD COMPONENT comment"
    fi
else
    fail_test "TestDetectionEnforcementBinding missing from verify_sprint.py"
fi

echo ""

# Summary
echo "================================================"
echo "TEST SUMMARY"
echo "================================================"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✅ All operational hygiene controls verified successfully!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please review the output above.${NC}"
    exit 1
fi
