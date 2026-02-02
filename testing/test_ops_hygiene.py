#!/usr/bin/env python3
"""
Unit tests for operational hygiene controls
Tests rate limiter, password change enforcement, and other security controls
"""
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def test_rate_limiter():
    """Test Token Bucket Rate Limiter"""
    print("\n" + "="*50)
    print("TEST: Rate Limiter (Token Bucket)")
    print("="*50)
    
    from app.middleware.rate_limiter import TokenBucketRateLimiter
    
    # Create limiter: 5 requests per 60 seconds
    limiter = TokenBucketRateLimiter(max_requests=5, time_window=60)
    
    # Test 1: First 5 requests should succeed
    print("Test 1: First 5 requests should be allowed...")
    test_ip = "192.168.1.100"
    for i in range(5):
        allowed, retry_after = limiter.is_allowed(test_ip)
        if not allowed:
            print(f"❌ FAIL: Request {i+1}/5 was blocked (should be allowed)")
            return False
    print("✅ PASS: First 5 requests allowed")
    
    # Test 2: 6th request should be blocked
    print("\nTest 2: 6th request should be rate limited...")
    allowed, retry_after = limiter.is_allowed(test_ip)
    if allowed:
        print("❌ FAIL: 6th request was allowed (should be blocked)")
        return False
    print(f"✅ PASS: 6th request blocked with retry_after={retry_after}s")
    
    # Test 3: Different IP should not be affected
    print("\nTest 3: Different IP should not be rate limited...")
    test_ip2 = "192.168.1.200"
    allowed, _ = limiter.is_allowed(test_ip2)
    if not allowed:
        print("❌ FAIL: Request from different IP was blocked")
        return False
    print("✅ PASS: Different IP not affected by rate limit")
    
    # Test 4: Check retry_after is reasonable
    print("\nTest 4: Verify retry_after is reasonable (1-60s)...")
    if retry_after < 1 or retry_after > 60:
        print(f"❌ FAIL: retry_after={retry_after} is out of range")
        return False
    print(f"✅ PASS: retry_after={retry_after}s is reasonable")
    
    print("\n✅ ALL RATE LIMITER TESTS PASSED")
    return True


def test_password_change_model():
    """Test User model has must_change_password field"""
    print("\n" + "="*50)
    print("TEST: Password Change Model")
    print("="*50)
    
    from app.models.user import User
    
    # Check if User model has the field
    if not hasattr(User, 'must_change_password'):
        print("❌ FAIL: User model missing must_change_password field")
        return False
    print("✅ PASS: User model has must_change_password field")
    
    # Check default value
    print("\nChecking default value...")
    user_class = User.__table__.columns.get('must_change_password')
    if user_class is not None:
        print("✅ PASS: must_change_password column exists in table definition")
    else:
        print("⚠️  WARN: Could not verify column definition")
    
    print("\n✅ PASSWORD CHANGE MODEL TESTS PASSED")
    return True


def test_code_structure():
    """Test that all required code changes are in place"""
    print("\n" + "="*50)
    print("TEST: Code Structure and Implementation")
    print("="*50)
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Rate limiter module exists
    tests_total += 1
    try:
        from app.middleware import rate_limiter
        print("✅ PASS: Rate limiter module exists")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ FAIL: Rate limiter module missing: {e}")
    
    # Test 2: Auth middleware checks must_change_password
    tests_total += 1
    try:
        with open('app/middleware/auth_middleware.py', 'r') as f:
            content = f.read()
            if 'must_change_password' in content:
                print("✅ PASS: Auth middleware checks must_change_password")
                tests_passed += 1
            else:
                print("❌ FAIL: Auth middleware missing must_change_password check")
    except Exception as e:
        print(f"❌ FAIL: Could not read auth middleware: {e}")
    
    # Test 3: Login router uses rate limiter
    tests_total += 1
    try:
        with open('app/web/routers/auth.py', 'r') as f:
            content = f.read()
            if 'check_rate_limit' in content and 'rate_limiter' in content:
                print("✅ PASS: Login router uses rate limiter")
                tests_passed += 1
            else:
                print("❌ FAIL: Login router missing rate limiter")
    except Exception as e:
        print(f"❌ FAIL: Could not read auth router: {e}")
    
    # Test 4: Change password endpoint clears flag
    tests_total += 1
    try:
        with open('app/web/routers/auth.py', 'r') as f:
            content = f.read()
            if 'must_change_password = False' in content:
                print("✅ PASS: Change password endpoint clears flag")
                tests_passed += 1
            else:
                print("❌ FAIL: Change password endpoint doesn't clear flag")
    except Exception as e:
        print(f"❌ FAIL: Could not read auth router: {e}")
    
    # Test 5: Logrotate config exists
    tests_total += 1
    try:
        import os
        if os.path.exists('config/minifw-audit.logrotate'):
            print("✅ PASS: Logrotate config file exists")
            tests_passed += 1
        else:
            print("❌ FAIL: Logrotate config file missing")
    except Exception as e:
        print(f"❌ FAIL: Could not check logrotate config: {e}")
    
    # Test 6: verify_sprint.py has critical comment
    tests_total += 1
    try:
        with open('scripts/verify_sprint.py', 'r') as f:
            content = f.read()
            if 'CRITICAL CI/CD COMPONENT' in content:
                print("✅ PASS: verify_sprint.py marked as CRITICAL")
                tests_passed += 1
            else:
                print("❌ FAIL: verify_sprint.py missing CRITICAL comment")
    except Exception as e:
        print(f"❌ FAIL: Could not read verify_sprint.py: {e}")
    
    print(f"\n{tests_passed}/{tests_total} CODE STRUCTURE TESTS PASSED")
    return tests_passed == tests_total


def main():
    """Run all tests"""
    print("="*50)
    print("Operational Hygiene Unit Tests")
    print("="*50)
    
    all_passed = True
    
    # Test 1: Rate Limiter
    try:
        if not test_rate_limiter():
            all_passed = False
    except Exception as e:
        print(f"❌ FAIL: Rate limiter test crashed: {e}")
        all_passed = False
    
    # Test 2: Password Change Model
    try:
        if not test_password_change_model():
            all_passed = False
    except Exception as e:
        print(f"❌ FAIL: Password change model test crashed: {e}")
        all_passed = False
    
    # Test 3: Code Structure
    try:
        if not test_code_structure():
            all_passed = False
    except Exception as e:
        print(f"❌ FAIL: Code structure test crashed: {e}")
        all_passed = False
    
    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    if all_passed:
        print("✅ ALL TESTS PASSED")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
