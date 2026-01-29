#!/usr/bin/env python3
import os
import sys
import unittest
import shutil
import json
import time
import threading
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

class TestHardening(unittest.TestCase):
    def setUp(self):
        # Clear env vars to test fail-fast
        if "MINIFW_SECRET_KEY" in os.environ:
            del os.environ["MINIFW_SECRET_KEY"]
        if "MINIFW_ADMIN_PASSWORD" in os.environ:
            del os.environ["MINIFW_ADMIN_PASSWORD"]

    def test_jwt_fail_fast(self):
        print("\n[TEST] JWT Fail-Fast")
        # Should raise ValueError if env var missing
        try:
            from app.services.auth import token_service
            import importlib
            importlib.reload(token_service)
            self.fail("Did not raise ValueError when MINIFW_SECRET_KEY is missing")
        except ValueError as e:
            print(f"✅ Correctly raised: {e}")
        except ImportError:
            # Should not happen
            self.fail("Import error instead of ValueError")

    def test_symlink_bypass(self):
        print("\n[TEST] Symlink Bypass Detection")
        # Setup env
        os.environ["MINIFW_SECRET_KEY"] = "test-key"
        from app.services.policy import update_policy_service
        
        # Setup: Link /tmp/minifw_fake_log -> /etc/passwd
        # We use /etc/passwd because it definitely exists and is readable, so realpath works predictably
        target = "/etc/passwd"
        link = "/tmp/minifw_fake_log"
        if os.path.exists(link):
            os.remove(link)
        try:
            os.symlink(target, link)
        except OSError:
            print("⚠️  Skipping symlink test (insufficient privileges to create symlink)")
            return

        try:
            update_policy_service.update_collectors(
                dnsmasq_log_path=link,
                zeek_ssl_log_path="/tmp/ssl.log",
                use_zeek_sni=False
            )
            self.fail("FAILED: System allowed access to /etc/passwd via symlink!")
        except ValueError as e:
            if "Security Error" in str(e):
                print(f"✅ Correctly blocked symlink-based traversal: {e}")
            else:
                self.fail(f"Blocked but with wrong error: {e}")
        finally:
            if os.path.exists(link):
                os.remove(link)

    def test_partial_path_traversal(self):
        print("\n[TEST] Partial Path Traversal (/tmp_fake)")
        from app.services.policy import update_policy_service
        
        # Test path that starts with allowed prefix string but is a sibling directory
        # e.g. allowed: /tmp
        # attempt: /tmp_fake/log
        
        bad_path = "/tmp_fake_dir/data.log"
        
        try:
            update_policy_service.update_collectors(
                dnsmasq_log_path=bad_path,
                zeek_ssl_log_path="/tmp/ssl.log",
                use_zeek_sni=False
            )
            self.fail(f"FAILED: Partial path traversal allowed for {bad_path}")
        except ValueError as e:
            if "Security Error" in str(e):
                print(f"✅ Correctly blocked partial path: {e}")
            else:
                self.fail(f"Blocked but with wrong error: {e}")

    def test_env_file_permissions(self):
        print("\n[TEST] Systemd Environment Permissions")
        env_file = "/etc/minifw/minifw.env"
        
        if not os.path.exists(env_file):
            print("⚠️  Skipping env permission test (file not found - maybe not running as root/installed)")
            return

        stat = os.stat(env_file)
        mode = stat.st_mode & 0o777
        
        # Check 600 (owner read/write only)
        if mode != 0o600:
            # If we are strictly checking 600. 
            # Note: If verify_sprint.py created it, it might be different, but install_systemd.sh sets 600.
            self.fail(f"FAILED: /etc/minifw/minifw.env has insecure permissions: {oct(mode)}. Expected 0o600.")
        
        print(f"✅ Secure permissions confirmed: {oct(mode)}")

    def test_atomic_concurrency(self):
        print("\n[TEST] Atomic Concurrency")
        from app.services.policy import update_policy_service
        
        # Create dummy policy
        policy_path = "/tmp/test_policy.json"
        with open(policy_path, 'w') as f:
            json.dump({"test": 0}, f)
        
        os.environ["MINIFW_POLICY"] = policy_path
        
        failures = []
        
        def update_worker(i):
            try:
                update_policy_service._save_policy({"test": i})
            except Exception as e:
                failures.append(f"Thread {i}: {e}")
                
        threads = []
        for i in range(100): # High load stress test
            t = threading.Thread(target=update_worker, args=(i,))
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join()
            
        if failures:
            self.fail(f"Concurrency caused failures: {failures}")
            
        # Check integrity
        try:
            with open(policy_path, 'r') as f:
                data = json.load(f)
            # Check not empty (json.load would raise error if empty)
            print(f"✅ Policy file is valid JSON after concurrent writes. Last value: {data}")
        except Exception as e:
            self.fail(f"Corrupted or empty JSON file: {e}")


class TestAuditCoverage(unittest.TestCase):
    """P2: Verify audit trail coverage for governance compliance"""
    
    def setUp(self):
        """Set up test environment with isolated audit log"""
        self.audit_path = "/tmp/minifw_test_audit.jsonl"
        os.environ["MINIFW_AUDIT_LOG"] = self.audit_path
        os.environ["MINIFW_SECRET_KEY"] = "test-key-for-audit-coverage"
        os.environ["MINIFW_POLICY"] = "/tmp/test_policy_audit.json"
        
        # Reset audit logger to pick up new env vars
        from app.minifw_ai.utils.audit_logger import reset_audit_logger
        reset_audit_logger()
        
        # Clear audit file
        if os.path.exists(self.audit_path):
            os.remove(self.audit_path)
        
        # Create test policy file
        with open("/tmp/test_policy_audit.json", 'w') as f:
            json.dump({"test": "initial"}, f)
    
    def tearDown(self):
        """Clean up test files"""
        for path in [self.audit_path, "/tmp/test_policy_audit.json"]:
            if os.path.exists(path):
                os.remove(path)
    
    def test_policy_update_audited(self):
        """Test Case 1: Policy update must generate audit entry"""
        print("\n[TEST] Policy Update Audit Coverage")
        
        # Get initial file size
        initial_size = os.path.getsize(self.audit_path) if os.path.exists(self.audit_path) else 0
        
        # Trigger policy update
        from app.services.policy import update_policy_service
        import importlib
        importlib.reload(update_policy_service)  # Reload to pick up new env vars
        
        update_policy_service._save_policy({"test": "audit_coverage_test"})
        
        # Assert file size increased
        self.assertTrue(os.path.exists(self.audit_path), "Audit log file should be created")
        new_size = os.path.getsize(self.audit_path)
        self.assertGreater(new_size, initial_size, "Audit log should grow after policy update")
        
        # Verify content contains POLICY event
        with open(self.audit_path, 'r') as f:
            content = f.read()
        self.assertIn('"event_type": "POLICY"', content, "Audit log should contain POLICY event")
        self.assertIn('"action": "POLICY_UPDATED"', content, "Audit log should contain POLICY_UPDATED action")
        
        print("✅ Policy update correctly logged to audit trail")
    
    def test_enforcement_audited(self):
        """Test Case 2: Enforcement actions must generate audit entry with event_type ENFORCEMENT"""
        print("\n[TEST] Enforcement Action Audit Coverage")
        
        # Get initial file size
        initial_size = os.path.getsize(self.audit_path) if os.path.exists(self.audit_path) else 0
        
        # Simulate enforcement action (direct call to audit logger)
        from app.minifw_ai.utils.audit_logger import append_audit
        append_audit(
            event_type="ENFORCEMENT",
            action="BLOCK",
            target="192.168.1.100",
            details={"reason": "test_verification", "score": 95}
        )
        
        # Assert file was created and has content
        self.assertTrue(os.path.exists(self.audit_path), "Audit log file should be created")
        new_size = os.path.getsize(self.audit_path)
        self.assertGreater(new_size, initial_size, "Audit log should grow after enforcement")
        
        # Verify JSON structure
        with open(self.audit_path, 'r') as f:
            content = f.read()
        
        # Parse the last line as JSON
        lines = content.strip().split('\n')
        last_entry = json.loads(lines[-1])
        
        self.assertEqual(last_entry["event_type"], "ENFORCEMENT", "event_type should be ENFORCEMENT")
        self.assertEqual(last_entry["action"], "BLOCK", "action should be BLOCK")
        self.assertEqual(last_entry["target"], "192.168.1.100", "target should match blocked IP")
        self.assertIn("timestamp", last_entry, "Entry should have timestamp")
        
        print(f"✅ Enforcement action correctly logged: {last_entry}")


if __name__ == '__main__':
    unittest.main()

