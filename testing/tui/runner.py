"""
Polymorphic Test Runner for MiniFW-AI

Handles execution of both pytest-style tests and standalone scripts
with output capture and threading support for UI responsiveness.
"""
from __future__ import annotations

import subprocess
import sys
import time
import io
import os
import threading
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable
from contextlib import redirect_stdout, redirect_stderr

# Setup debug logger for test results
LOG_DIR = Path(__file__).parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
TEST_LOG_PATH = LOG_DIR / "test_results.log"

# Configure file logging
_test_logger = logging.getLogger("minifw.test_runner")
_test_logger.setLevel(logging.DEBUG)
_test_logger.propagate = False

# Clear old handlers
for h in _test_logger.handlers[:]:
    _test_logger.removeHandler(h)

# File handler with detailed format
_fh = logging.FileHandler(TEST_LOG_PATH, mode='a', encoding='utf-8')
_fh.setFormatter(logging.Formatter(
    '%(asctime)s | %(levelname)-5s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
_test_logger.addHandler(_fh)

def log_test(level: str, message: str):
    """Log test-related message."""
    getattr(_test_logger, level.lower(), _test_logger.info)(message)

# Try to import pytest for programmatic execution
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False


@dataclass
class TestResult:
    """Result of a single test execution."""
    test_id: str
    name: str
    success: bool
    output: str
    duration: float
    error: Optional[str] = None


class TestRunner:
    """
    Polymorphic test runner supporting both pytest and standalone scripts.
    
    Executes tests in a background thread to keep TUI responsive.
    """
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.results: List[TestResult] = []
        self._running = False
        self._current_test: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._on_test_complete: Optional[Callable[[TestResult], None]] = None
        self._on_all_complete: Optional[Callable[[], None]] = None
    
    @property
    def is_running(self) -> bool:
        """Check if tests are currently running."""
        return self._running
    
    @property
    def current_test(self) -> Optional[str]:
        """Get the ID of the currently running test."""
        return self._current_test
    
    def run_tests_async(
        self,
        tests: List,  # List[TestInfo]
        on_test_complete: Optional[Callable[[TestResult], None]] = None,
        on_all_complete: Optional[Callable[[], None]] = None
    ):
        """
        Run tests in a background thread.
        
        Args:
            tests: List of TestInfo objects to execute
            on_test_complete: Callback after each test finishes
            on_all_complete: Callback when all tests finish
        """
        if self._running:
            return
        
        self._on_test_complete = on_test_complete
        self._on_all_complete = on_all_complete
        self.results = []
        
        self._thread = threading.Thread(
            target=self._run_tests_worker,
            args=(tests,),
            daemon=True
        )
        self._running = True
        self._thread.start()
    
    def _run_tests_worker(self, tests: List):
        """Worker thread for test execution."""
        for test_info in tests:
            self._current_test = test_info.id
            result = self._run_single_test(test_info)
            self.results.append(result)
            
            if self._on_test_complete:
                self._on_test_complete(result)
        
        self._current_test = None
        self._running = False
        
        if self._on_all_complete:
            self._on_all_complete()
    
    def _check_dependencies(self, test_info) -> List[str]:
        """
        Check if required dependencies are available.
        
        Returns list of missing package names.
        """
        if not hasattr(test_info, 'requires_deps') or not test_info.requires_deps:
            return []
        
        # Map package names to import names
        IMPORT_MAP = {
            "scikit-learn": "sklearn",
            "yara-python": "yara",
            "python-jose": "jose",
            "pytest": "pytest",
            "pandas": "pandas",
        }
        
        missing = []
        for dep in test_info.requires_deps:
            import_name = IMPORT_MAP.get(dep, dep)
            try:
                __import__(import_name)
            except ImportError:
                missing.append(dep)
        
        return missing
    
    def _run_single_test(self, test_info) -> TestResult:
        """
        Execute a single test using the appropriate method.
        
        Returns TestResult with success status, output, and duration.
        """
        start_time = time.time()
        test_path = self.project_root / test_info.path
        
        log_test("info", f"=" * 60)
        log_test("info", f"STARTING: {test_info.name} ({test_info.id})")
        log_test("info", f"  Path: {test_path}")
        log_test("info", f"  Type: {test_info.type}")
        log_test("info", f"  Timeout: {test_info.timeout}s")
        
        # Handle auto-skip tests (require manual execution)
        if hasattr(test_info, 'auto_skip') and test_info.auto_skip:
            skip_msg = test_info.skip_reason if test_info.skip_reason else "Requires manual execution"
            log_test("info", f"SKIPPED: {skip_msg}")
            return TestResult(
                test_id=test_info.id,
                name=test_info.name,
                success=True,
                output=f"SKIPPED: {skip_msg}",
                duration=0.0,
                error=None
            )
        
        # Check dependencies before running
        missing_deps = self._check_dependencies(test_info)
        if missing_deps:
            skip_msg = f"Missing dependencies: {', '.join(missing_deps)}"
            if hasattr(test_info, 'skip_reason') and test_info.skip_reason:
                skip_msg += f". {test_info.skip_reason}"
            log_test("info", f"SKIPPED: {skip_msg}")
            return TestResult(
                test_id=test_info.id,
                name=test_info.name,
                success=True,  # Mark as passed but with skip note
                output=f"SKIPPED: {skip_msg}",
                duration=0.0,
                error=None
            )
        
        # Handle manually skipped tests (requires_root without root, etc)
        if hasattr(test_info, 'requires_root') and test_info.requires_root and os.geteuid() != 0:
            skip_msg = "Requires root privileges"
            if hasattr(test_info, 'skip_reason') and test_info.skip_reason:
                skip_msg = test_info.skip_reason
            log_test("info", f"SKIPPED: {skip_msg}")
            return TestResult(
                test_id=test_info.id,
                name=test_info.name,
                success=True,
                output=f"SKIPPED: {skip_msg}",
                duration=0.0,
                error=None
            )
        
        try:
            if test_info.type == "pytest":
                success, output = self._run_pytest(test_path)
            elif test_info.type == "script":
                success, output = self._run_script(test_path, test_info.timeout)
            else:
                success = False
                output = f"Unknown test type: {test_info.type}"
        except Exception as e:
            success = False
            output = f"Execution error: {str(e)}"
            log_test("error", f"Exception during execution: {e}")
        
        duration = time.time() - start_time
        
        # Log result
        status = "PASS" if success else "FAIL"
        log_test("info", f"RESULT: {status} ({duration:.2f}s)")
        
        if not success:
            log_test("warning", f"OUTPUT (last 1000 chars):")
            for line in output[-1000:].split('\n'):
                log_test("warning", f"  {line}")
        
        result = TestResult(
            test_id=test_info.id,
            name=test_info.name,
            success=success,
            output=output,
            duration=duration,
            error=None if success else self._extract_error(output)
        )
        
        return result
    
    def _run_pytest(self, test_path: Path) -> tuple[bool, str]:
        """
        Run a pytest/unittest test file programmatically.
        
        Falls back to subprocess if pytest not available.
        """
        if PYTEST_AVAILABLE:
            # Capture stdout/stderr
            capture = io.StringIO()
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            
            try:
                sys.stdout = capture
                sys.stderr = capture
                
                # Run pytest programmatically
                result = pytest.main([
                    "-q",
                    "--tb=short",
                    str(test_path)
                ])
                
                output = capture.getvalue()
                success = (result == pytest.ExitCode.OK)
                return success, output
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        else:
            # Fallback to subprocess with unittest
            return self._run_script(test_path, timeout=60)
    
    def _run_script(self, test_path: Path, timeout: int = 60) -> tuple[bool, str]:
        """
        Run a standalone script as a subprocess.
        
        This is the safe way to execute scripts that have __main__ blocks.
        """
        env = {
            **dict(__import__('os').environ),
            "PYTHONPATH": str(self.project_root),
            "MINIFW_SECRET_KEY": "test-secret-key-for-runner"
        }
        
        try:
            proc = subprocess.run(
                [sys.executable, str(test_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.project_root),
                env=env
            )
            
            output = proc.stdout
            if proc.stderr:
                output += "\n--- STDERR ---\n" + proc.stderr
            
            success = (proc.returncode == 0)
            return success, output
        
        except subprocess.TimeoutExpired:
            return False, f"TIMEOUT: Test exceeded {timeout}s limit"
        except Exception as e:
            return False, f"EXECUTION ERROR: {str(e)}"
    
    def _extract_error(self, output: str) -> str:
        """Extract the most relevant error message from output."""
        lines = output.strip().split('\n')
        
        # Look for common error patterns
        for i, line in enumerate(lines):
            if 'FAILED' in line or 'ERROR' in line or 'AssertionError' in line:
                # Return this line and next few for context
                return '\n'.join(lines[i:i+3])
        
        # Return last few lines as fallback
        return '\n'.join(lines[-5:]) if lines else "Unknown error"
    
    def get_summary(self) -> dict:
        """Get summary of test results."""
        passed = sum(1 for r in self.results if r.success)
        failed = len(self.results) - passed
        total_time = sum(r.duration for r in self.results)
        
        return {
            "total": len(self.results),
            "passed": passed,
            "failed": failed,
            "duration": total_time
        }


# Quick test
if __name__ == "__main__":
    from testing.test_registry import TEST_REGISTRY, get_tests_by_category
    
    project_root = Path(__file__).parent.parent.parent
    runner = TestRunner(project_root)
    
    # Get unit tests only for quick test
    tests = get_tests_by_category("security")[:1]
    
    print(f"Running {len(tests)} test(s)...")
    
    def on_complete(result: TestResult):
        status = "✅" if result.success else "❌"
        print(f"{status} {result.name} ({result.duration:.2f}s)")
    
    runner.run_tests_async(tests, on_test_complete=on_complete)
    
    # Wait for completion
    while runner.is_running:
        time.sleep(0.1)
    
    summary = runner.get_summary()
    print(f"\nSummary: {summary['passed']}/{summary['total']} passed")
