#!/usr/bin/env python3
"""
MiniFW-AI Unified Test Suite TUI

Interactive terminal interface for test selection and execution
with real-time results display.

Usage:
    python3 testing/run_tests_tui.py
    
Controls:
    ↑/↓ or j/k  : Navigate test list
    SPACE       : Toggle test selection
    a           : Select all tests
    n           : Deselect all tests
    c           : Cycle category filter
    ENTER       : Run selected tests
    r           : View results
    q           : Quit
"""
from __future__ import annotations

import sys
import time
import curses
from pathlib import Path
from typing import List, Optional, Set

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from testing.test_registry import (
    TEST_REGISTRY,
    TestInfo,
    get_all_tests,
    get_tests_by_category,
    get_categories
)
from testing.tui.runner import TestRunner, TestResult
from testing.tui.screen import Screen, Colors


class TestSuiteTUI:
    """
    Main TUI application for test suite management.
    """
    
    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.tests = get_all_tests()
        self.categories = ["ALL"] + get_categories()
        self.current_category = 0
        
        self.cursor = 0
        self.selected: Set[str] = set()
        self.scroll_offset = 0
        
        self.runner = TestRunner(self.project_root)
        self.results: List[TestResult] = []
        
        self.view = "list"  # "list" or "results"
        self.status_message = ""
    
    def get_visible_tests(self) -> List[TestInfo]:
        """Get tests filtered by current category."""
        category = self.categories[self.current_category]
        if category == "ALL":
            return self.tests
        return get_tests_by_category(category)
    
    def run(self):
        """Main entry point - run the TUI."""
        with Screen() as screen:
            self.screen = screen
            self._main_loop()
    
    def _main_loop(self):
        """Main event loop."""
        while True:
            self._draw()
            
            # Set timeout for non-blocking check when tests running
            timeout = 100 if self.runner.is_running else -1
            key = self.screen.get_key(timeout)
            
            if key == -1:
                continue
            
            if self.view == "list":
                if not self._handle_list_key(key):
                    break
            elif self.view == "results":
                if not self._handle_results_key(key):
                    break
    
    def _handle_list_key(self, key: int) -> bool:
        """Handle key press in list view. Returns False to quit."""
        visible_tests = self.get_visible_tests()
        
        # Quit
        if key == ord('q'):
            return False
        
        # Navigation
        elif key in (curses.KEY_UP, ord('k')):
            self.cursor = max(0, self.cursor - 1)
            self._adjust_scroll()
        
        elif key in (curses.KEY_DOWN, ord('j')):
            self.cursor = min(len(visible_tests) - 1, self.cursor + 1)
            self._adjust_scroll()
        
        elif key == curses.KEY_PPAGE:  # Page Up
            self.cursor = max(0, self.cursor - 10)
            self._adjust_scroll()
        
        elif key == curses.KEY_NPAGE:  # Page Down
            self.cursor = min(len(visible_tests) - 1, self.cursor + 10)
            self._adjust_scroll()
        
        # Selection
        elif key == ord(' '):  # Toggle single
            if visible_tests:
                test_id = visible_tests[self.cursor].id
                if test_id in self.selected:
                    self.selected.discard(test_id)
                else:
                    self.selected.add(test_id)
        
        elif key == ord('a'):  # Select all
            for t in visible_tests:
                self.selected.add(t.id)
            self.status_message = f"Selected {len(visible_tests)} tests"
        
        elif key == ord('n'):  # Deselect all
            for t in visible_tests:
                self.selected.discard(t.id)
            self.status_message = "Cleared selection"
        
        # Category filter
        elif key == ord('c'):
            self.current_category = (self.current_category + 1) % len(self.categories)
            self.cursor = 0
            self.scroll_offset = 0
            self.status_message = f"Category: {self.categories[self.current_category]}"
        
        # Run tests
        elif key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
            self._start_tests()
        
        # View results
        elif key == ord('r'):
            if self.results:
                self.view = "results"
                self.cursor = 0
                self.scroll_offset = 0
        
        return True
    
    def _handle_results_key(self, key: int) -> bool:
        """Handle key press in results view. Returns False to quit."""
        # Quit
        if key == ord('q'):
            return False
        
        # Back to list
        elif key in (ord('b'), ord('r'), 27):  # 27 = ESC
            self.view = "list"
            self.cursor = 0
            self.scroll_offset = 0
        
        # Navigation
        elif key in (curses.KEY_UP, ord('k')):
            self.cursor = max(0, self.cursor - 1)
            self._adjust_scroll()
        
        elif key in (curses.KEY_DOWN, ord('j')):
            self.cursor = min(len(self.results) - 1, self.cursor + 1)
            self._adjust_scroll()
        
        return True
    
    def _adjust_scroll(self):
        """Adjust scroll offset to keep cursor visible."""
        visible_height = self.screen.height - 6  # Header, separator, footer
        
        if self.cursor < self.scroll_offset:
            self.scroll_offset = self.cursor
        elif self.cursor >= self.scroll_offset + visible_height:
            self.scroll_offset = self.cursor - visible_height + 1
    
    def _start_tests(self):
        """Start running selected tests."""
        if self.runner.is_running:
            self.status_message = "Tests already running..."
            return
        
        # Get selected tests
        tests_to_run = [t for t in self.tests if t.id in self.selected]
        
        if not tests_to_run:
            self.status_message = "No tests selected. Use SPACE to select."
            return
        
        self.results = []
        self.status_message = f"Running {len(tests_to_run)} tests..."
        
        def on_complete(result: TestResult):
            self.results.append(result)
        
        def on_all_complete():
            summary = self.runner.get_summary()
            self.status_message = f"Done: {summary['passed']}/{summary['total']} passed"
        
        self.runner.run_tests_async(
            tests_to_run,
            on_test_complete=on_complete,
            on_all_complete=on_all_complete
        )
    
    def _draw(self):
        """Draw the current view."""
        self.screen.clear()
        
        if self.view == "list":
            self._draw_list_view()
        elif self.view == "results":
            self._draw_results_view()
        
        self.screen.refresh()
    
    def _draw_list_view(self):
        """Draw the test list view."""
        visible_tests = self.get_visible_tests()
        category = self.categories[self.current_category]
        
        # Header
        subtitle = f"Category: {category}"
        if self.runner.is_running:
            subtitle += f"  │  Running: {self.runner.current_test}"
        self.screen.draw_header("MiniFW-AI Test Suite", subtitle)
        
        # Separator
        self.screen.draw_separator(1)
        
        # Test list
        visible_height = self.screen.height - 6
        start_row = 2
        
        for i, test in enumerate(visible_tests):
            if i < self.scroll_offset:
                continue
            if i >= self.scroll_offset + visible_height:
                break
            
            row = start_row + (i - self.scroll_offset)
            self._draw_test_row(row, i, test)
        
        # Summary bar
        summary_row = self.screen.height - 3
        self.screen.draw_separator(summary_row)
        
        selected_count = len(self.selected)
        passed = sum(1 for r in self.results if r.success)
        failed = len(self.results) - passed
        
        summary = f"Selected: {selected_count}"
        if self.results:
            summary += f"  │  Results: ✅ {passed}  ❌ {failed}"
        if self.status_message:
            summary += f"  │  {self.status_message}"
        
        self.screen.draw_text(summary_row + 1, 2, summary, Colors.INFO)
        
        # Footer
        footer = "[↑↓] Nav  [SPACE] Toggle  [a/n] All/None  [c] Category  [ENTER] Run  [r] Results  [q] Quit"
        self.screen.draw_footer(footer)
    
    def _draw_test_row(self, row: int, idx: int, test: TestInfo):
        """Draw a single test row."""
        is_cursor = (idx == self.cursor)
        is_selected = (test.id in self.selected)
        
        # Checkbox
        checkbox = "[x]" if is_selected else "[ ]"
        
        # Cursor indicator
        cursor = "➤" if is_cursor else " "
        
        # Status indicator based on results
        status = " "
        result = next((r for r in self.results if r.test_id == test.id), None)
        if result:
            status = "✅" if result.success else "❌"
        elif self.runner.current_test == test.id:
            status = "⏳"
        
        # Type indicator
        type_badge = "P" if test.type == "pytest" else "S"
        
        # Root indicator
        root_badge = "🔒" if test.requires_root else "  "
        
        # Build line
        line = f" {checkbox} {cursor} {status} [{type_badge}] {root_badge} {test.name}"
        
        # Category
        cat_str = f"({test.category})"
        
        # Colors
        if is_cursor:
            color = Colors.SELECTED
        elif result and not result.success:
            color = Colors.ERROR
        elif result and result.success:
            color = Colors.SUCCESS
        else:
            color = Colors.DEFAULT
        
        self.screen.draw_text(row, 0, line, color, max_width=self.screen.width - len(cat_str) - 2)
        self.screen.draw_text(row, self.screen.width - len(cat_str) - 2, cat_str, Colors.INFO)
    
    def _draw_results_view(self):
        """Draw the results view."""
        summary = self.runner.get_summary()
        
        # Header
        subtitle = f"Passed: {summary['passed']}  Failed: {summary['failed']}  Time: {summary['duration']:.1f}s"
        self.screen.draw_header("Test Results", subtitle)
        
        # Separator
        self.screen.draw_separator(1)
        
        # Results list
        visible_height = self.screen.height - 5
        start_row = 2
        
        for i, result in enumerate(self.results):
            if i < self.scroll_offset:
                continue
            if i >= self.scroll_offset + visible_height:
                break
            
            row = start_row + (i - self.scroll_offset)
            self._draw_result_row(row, i, result)
        
        # Footer
        self.screen.draw_separator(self.screen.height - 2)
        self.screen.draw_footer("[↑↓] Navigate  [b] Back to list  [q] Quit")
    
    def _draw_result_row(self, row: int, idx: int, result: TestResult):
        """Draw a single result row."""
        is_cursor = (idx == self.cursor)
        
        # Status icon
        status = "✅" if result.success else "❌"
        
        # Duration
        duration = f"{result.duration:.2f}s"
        
        # Build line
        line = f" {status} {result.name}"
        
        # Colors
        if is_cursor:
            color = Colors.SELECTED
        elif result.success:
            color = Colors.SUCCESS
        else:
            color = Colors.ERROR
        
        self.screen.draw_text(row, 0, line, color, max_width=self.screen.width - len(duration) - 2)
        self.screen.draw_text(row, self.screen.width - len(duration) - 2, duration, Colors.INFO)
        
        # Show error preview if cursor is on failed test
        if is_cursor and not result.success and result.error:
            error_line = f"   └─ {result.error.split(chr(10))[0][:60]}"
            self.screen.draw_text(row + 1, 0, error_line, Colors.WARNING)


def main():
    """Main entry point."""
    try:
        tui = TestSuiteTUI()
        tui.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        # Make sure terminal is restored
        curses.endwin()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
