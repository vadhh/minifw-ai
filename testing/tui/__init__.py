"""
TUI Package for MiniFW-AI Test Suite

Provides terminal-based user interface for interactive test selection
and execution with real-time results display.
"""
from testing.tui.runner import TestRunner, TestResult
from testing.tui.screen import Screen

__all__ = ["TestRunner", "TestResult", "Screen"]
