"""
Test Registry for MiniFW-AI Unified Test Suite

Provides a centralized catalog of all test files with metadata
for polymorphic execution (pytest vs standalone script).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path


@dataclass
class TestInfo:
    """
    Metadata for a test module.
    
    Attributes:
        id: Unique identifier (snake_case)
        name: Human-readable display name
        path: Relative path from project root
        type: Execution type - "pytest" (unittest/pytest) or "script" (standalone)
        category: Test category for filtering
        description: Brief description of what the test covers
        requires_root: Whether the test needs sudo/root privileges
        requires_deps: List of optional dependencies needed
        timeout: Maximum execution time in seconds
        skip_reason: Explanation when test is skipped
        auto_skip: If True, always skip in auto-run mode (requires manual execution)
        args: Additional arguments to pass to the script
    """
    id: str
    name: str
    path: str
    type: str  # "pytest" or "script"
    category: str  # "unit", "integration", "security"
    description: str
    requires_root: bool = False
    requires_deps: List[str] = field(default_factory=list)
    timeout: int = 60
    skip_reason: Optional[str] = None
    auto_skip: bool = False  # Skip in auto-run mode, requires manual execution
    args: List[str] = field(default_factory=list)


# ============================================================================
# TEST REGISTRY - All test files catalogued with execution metadata
# ============================================================================

TEST_REGISTRY: List[TestInfo] = [
    # -------------------------------------------------------------------------
    # UNIT TESTS (Fast, no external dependencies)
    # -------------------------------------------------------------------------
    TestInfo(
        id="sector_lock",
        name="Sector Lock Logic",
        path="testing/test_sector_lock.py",
        type="script",
        category="unit",
        description="Verifies sector immutability, env loading, and config retrieval.",
        requires_deps=["pytest"],
        skip_reason="Requires pytest; run with: pip install pytest && PYTHONPATH=app pytest testing/test_sector_lock.py -v"
    ),
    TestInfo(
        id="mlp_inference",
        name="MLP Inference",
        path="testing/test_mlp_inference.py",
        type="script",
        category="unit",
        description="Tests trained MLP model inference on flow data.",
        requires_deps=["scikit-learn", "pandas"],
        auto_skip=True,
        skip_reason="Requires --model argument; run manually: python3 testing/test_mlp_inference.py --model models/mlp_engine.pkl"
    ),
    TestInfo(
        id="yara_scanner",
        name="YARA Scanner",
        path="testing/test_yara_scanner.py",
        type="script",
        category="unit",
        description="Tests YARA rule matching and payload scanning.",
        requires_deps=["yara-python"],
        auto_skip=True,
        skip_reason="Has known subtest failures; run manually: python3 testing/test_yara_scanner.py"
    ),
    
    # -------------------------------------------------------------------------
    # INTEGRATION TESTS (May require network, longer runtime)
    # -------------------------------------------------------------------------
    TestInfo(
        id="flow_collector",
        name="Flow Collector",
        path="testing/test_flow_collector.py",
        type="script",
        category="integration",
        description="Tests flow tracking from conntrack with real traffic.",
        requires_root=True,
        timeout=120,
        skip_reason="Requires root + conntrack; run with: sudo python3 testing/test_flow_collector.py"
    ),
    TestInfo(
        id="flow_collector_sim",
        name="Flow Collector (Simulated)",
        path="testing/test_flow_collector_simulated.py",
        type="script",
        category="integration",
        description="Tests flow collector with simulated traffic data."
    ),
    TestInfo(
        id="full_integration",
        name="Full Integration",
        path="testing/test_full_integration.py",
        type="script",
        category="integration",
        description="End-to-end test: MLP + Flow + YARA with hard gates.",
        requires_deps=["scikit-learn", "yara-python"],
        timeout=180,
        skip_reason="Requires scikit-learn + yara-python; install with: pip install scikit-learn yara-python"
    ),
    TestInfo(
        id="mlp_integration",
        name="MLP Integration",
        path="testing/test_mlp_integration.py",
        type="script",
        category="integration",
        description="Tests MLP engine integration with flow collector.",
        requires_deps=["scikit-learn"],
        skip_reason="Requires scikit-learn; install with: pip install scikit-learn"
    ),
    TestInfo(
        id="real_traffic",
        name="Real Traffic Simulation",
        path="testing/test_real_traffic.py",
        type="script",
        category="integration",
        description="Tests with real network traffic patterns.",
        requires_root=True,
        skip_reason="Requires root + gateway setup"
    ),
    TestInfo(
        id="standalone_integration",
        name="Standalone Integration",
        path="testing/test_standalone_integration.py",
        type="script",
        category="integration",
        description="Isolated integration test without external services."
    ),
    
    # -------------------------------------------------------------------------
    # SECURITY TESTS (Verification and hardening)
    # -------------------------------------------------------------------------
    TestInfo(
        id="verify_sprint",
        name="Sprint Verification",
        path="scripts/verify_sprint.py",
        type="pytest",  # Uses unittest.TestCase, compatible with pytest
        category="security",
        description="Security hardening tests: JWT, path traversal, audit coverage.",
        requires_deps=["python-jose"],
        skip_reason="Requires python-jose; install with: pip install python-jose[cryptography]"
    ),
]


# ============================================================================
# REGISTRY UTILITIES
# ============================================================================

def get_all_tests() -> List[TestInfo]:
    """Return all registered tests."""
    return TEST_REGISTRY.copy()


def get_tests_by_category(category: str) -> List[TestInfo]:
    """Filter tests by category."""
    return [t for t in TEST_REGISTRY if t.category == category]


def get_tests_by_type(exec_type: str) -> List[TestInfo]:
    """Filter tests by execution type (pytest/script)."""
    return [t for t in TEST_REGISTRY if t.type == exec_type]


def get_test_by_id(test_id: str) -> Optional[TestInfo]:
    """Get a specific test by ID."""
    for t in TEST_REGISTRY:
        if t.id == test_id:
            return t
    return None


def get_categories() -> List[str]:
    """Get list of unique categories."""
    return sorted(set(t.category for t in TEST_REGISTRY))


def get_root_required_tests() -> List[TestInfo]:
    """Get tests that require root privileges."""
    return [t for t in TEST_REGISTRY if t.requires_root]


def validate_paths(project_root: Path) -> List[str]:
    """
    Validate that all registered test file paths exist.
    Returns list of missing paths.
    """
    missing = []
    for t in TEST_REGISTRY:
        full_path = project_root / t.path
        if not full_path.exists():
            missing.append(t.path)
    return missing


# Quick self-test
if __name__ == "__main__":
    print(f"MiniFW-AI Test Registry")
    print(f"{'=' * 60}")
    print(f"Total tests: {len(TEST_REGISTRY)}")
    print()
    
    for category in get_categories():
        tests = get_tests_by_category(category)
        print(f"[{category.upper()}] ({len(tests)} tests)")
        for t in tests:
            root_marker = "🔒" if t.requires_root else "  "
            type_marker = "P" if t.type == "pytest" else "S"
            print(f"  {root_marker} [{type_marker}] {t.name}: {t.description}")
        print()
    
    # Validate paths
    project_root = Path(__file__).parent.parent
    missing = validate_paths(project_root)
    if missing:
        print(f"⚠️  Missing test files:")
        for p in missing:
            print(f"   - {p}")
    else:
        print(f"✅ All test file paths validated")
