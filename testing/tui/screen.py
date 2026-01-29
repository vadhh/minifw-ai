"""
Curses Screen Wrapper for MiniFW-AI Test TUI

Provides a simplified interface to curses with proper initialization,
color support, and window management.
"""
from __future__ import annotations

import curses
from typing import Optional, Tuple


class Colors:
    """Color pair constants."""
    DEFAULT = 0
    SUCCESS = 1  # Green
    ERROR = 2    # Red
    WARNING = 3  # Yellow
    INFO = 4     # Cyan
    HEADER = 5   # Blue on white
    SELECTED = 6 # Inverted


class Screen:
    """
    Curses screen wrapper with simplified API.
    
    Usage:
        with Screen() as screen:
            screen.draw_header("Title")
            screen.draw_text(2, 0, "Hello", Colors.DEFAULT)
            screen.refresh()
            key = screen.get_key()
    """
    
    def __init__(self):
        self.stdscr: Optional[curses.window] = None
        self.height: int = 0
        self.width: int = 0
    
    def __enter__(self) -> "Screen":
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)  # Hide cursor
        self.stdscr.keypad(True)
        self.stdscr.nodelay(False)  # Blocking input
        
        # Initialize colors if supported
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            
            # Define color pairs
            curses.init_pair(Colors.SUCCESS, curses.COLOR_GREEN, -1)
            curses.init_pair(Colors.ERROR, curses.COLOR_RED, -1)
            curses.init_pair(Colors.WARNING, curses.COLOR_YELLOW, -1)
            curses.init_pair(Colors.INFO, curses.COLOR_CYAN, -1)
            curses.init_pair(Colors.HEADER, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(Colors.SELECTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
        
        self._update_size()
        return self
    
    def __exit__(self, *args):
        if self.stdscr:
            curses.curs_set(1)
            self.stdscr.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()
    
    def _update_size(self):
        """Update screen dimensions."""
        self.height, self.width = self.stdscr.getmaxyx()
    
    def clear(self):
        """Clear the screen."""
        self.stdscr.clear()
    
    def refresh(self):
        """Refresh the screen."""
        self._update_size()
        self.stdscr.refresh()
    
    def get_key(self, timeout_ms: int = -1) -> int:
        """
        Get a key press.
        
        Args:
            timeout_ms: Timeout in milliseconds (-1 for blocking)
        
        Returns:
            Key code or -1 if timeout
        """
        if timeout_ms >= 0:
            self.stdscr.timeout(timeout_ms)
        else:
            self.stdscr.nodelay(False)
        
        return self.stdscr.getch()
    
    def draw_text(
        self,
        row: int,
        col: int,
        text: str,
        color: int = Colors.DEFAULT,
        bold: bool = False,
        max_width: Optional[int] = None
    ):
        """
        Draw text at position with optional styling.
        
        Args:
            row: Row position (0-indexed)
            col: Column position (0-indexed)
            text: Text to draw
            color: Color pair constant
            bold: Whether to make text bold
            max_width: Maximum width (truncate if exceeded)
        """
        if row < 0 or row >= self.height:
            return
        if col < 0 or col >= self.width:
            return
        
        # Truncate text if needed
        available_width = self.width - col - 1
        if max_width:
            available_width = min(available_width, max_width)
        
        if len(text) > available_width:
            text = text[:available_width - 1] + "…"
        
        attrs = curses.color_pair(color)
        if bold:
            attrs |= curses.A_BOLD
        
        try:
            self.stdscr.addstr(row, col, text, attrs)
        except curses.error:
            pass  # Ignore write errors at screen edge
    
    def draw_header(self, title: str, subtitle: str = ""):
        """Draw header bar at top of screen."""
        header = f" {title}"
        if subtitle:
            header += f"  │  {subtitle}"
        header = header.ljust(self.width - 1)
        
        self.draw_text(0, 0, header, Colors.HEADER, bold=True)
        self.draw_text(0, self.width - 10, "[q] quit ", Colors.HEADER)
    
    def draw_footer(self, text: str):
        """Draw footer bar at bottom of screen."""
        footer = f" {text}".ljust(self.width - 1)
        self.draw_text(self.height - 1, 0, footer, Colors.HEADER)
    
    def draw_separator(self, row: int, char: str = "─"):
        """Draw horizontal separator line."""
        line = char * (self.width - 1)
        self.draw_text(row, 0, line, Colors.DEFAULT)
    
    def draw_box(self, row: int, col: int, height: int, width: int):
        """Draw a box outline."""
        # Top border
        self.draw_text(row, col, "╔" + "═" * (width - 2) + "╗")
        
        # Sides
        for r in range(row + 1, row + height - 1):
            self.draw_text(r, col, "║")
            self.draw_text(r, col + width - 1, "║")
        
        # Bottom border
        self.draw_text(row + height - 1, col, "╚" + "═" * (width - 2) + "╝")
    
    def draw_progress(self, row: int, current: int, total: int, width: int = 30):
        """Draw a progress bar."""
        if total == 0:
            percent = 0
        else:
            percent = current / total
        
        filled = int(width * percent)
        empty = width - filled
        
        bar = "█" * filled + "░" * empty
        text = f"[{bar}] {current}/{total}"
        
        self.draw_text(row, 0, text, Colors.INFO)


# Quick demo
if __name__ == "__main__":
    with Screen() as screen:
        screen.clear()
        screen.draw_header("MiniFW-AI Test Suite", "Demo Mode")
        screen.draw_separator(1)
        screen.draw_text(3, 2, "✅ Test passed", Colors.SUCCESS)
        screen.draw_text(4, 2, "❌ Test failed", Colors.ERROR)
        screen.draw_text(5, 2, "⚠️  Warning message", Colors.WARNING)
        screen.draw_text(6, 2, "ℹ️  Info message", Colors.INFO)
        screen.draw_progress(8, 7, 10)
        screen.draw_separator(screen.height - 2)
        screen.draw_footer("[↑/↓] Navigate  [SPACE] Toggle  [ENTER] Run  [q] Quit")
        screen.refresh()
        
        screen.draw_text(10, 2, "Press any key to exit...")
        screen.refresh()
        screen.get_key()
