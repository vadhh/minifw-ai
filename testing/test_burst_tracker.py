#!/usr/bin/env python3
"""
BurstTracker Unit Tests

Covers sliding-window query counting, LRU capacity cap, and TTL-based
stale-entry eviction introduced in HIGH-001 fix.
"""
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

from minifw_ai.burst import BurstTracker


class TestSlidingWindow:
    """Core sliding-window rate counting."""

    def test_single_ip_count(self):
        bt = BurstTracker(window_seconds=60)
        assert bt.add("1.1.1.1") == 1
        assert bt.add("1.1.1.1") == 2
        assert bt.add("1.1.1.1") == 3

    def test_different_ips_counted_independently(self):
        bt = BurstTracker(window_seconds=60)
        bt.add("1.1.1.1")
        bt.add("1.1.1.1")
        bt.add("2.2.2.2")
        assert bt.add("1.1.1.1") == 3
        assert bt.add("2.2.2.2") == 2

    def test_old_timestamps_expire(self):
        bt = BurstTracker(window_seconds=60)
        past = time.time() - 61  # outside the window

        # Manually seed two expired timestamps
        from collections import deque
        bt.q["10.0.0.1"] = deque([past, past])

        # add() should trim both old timestamps then append the new one → count = 1
        assert bt.add("10.0.0.1") == 1

    def test_mix_of_fresh_and_stale_timestamps(self):
        bt = BurstTracker(window_seconds=60)
        now = time.time()
        from collections import deque
        bt.q["10.0.0.2"] = deque([now - 61, now - 30, now - 10])

        # Only the two within-window timestamps survive + the new one = 3
        assert bt.add("10.0.0.2") == 3


class TestLRUCapacity:
    """LRU eviction when max_size is reached."""

    def test_lru_evicts_oldest_when_full(self):
        bt = BurstTracker(window_seconds=60, max_size=3)
        bt.add("a")
        bt.add("b")
        bt.add("c")
        assert bt.size() == 3

        # "a" is LRU; adding "d" should evict "a"
        bt.add("d")
        assert bt.size() == 3
        assert "a" not in bt.q
        assert "d" in bt.q

    def test_recently_used_ip_survives_eviction(self):
        bt = BurstTracker(window_seconds=60, max_size=3)
        bt.add("a")
        bt.add("b")
        bt.add("c")
        bt.add("a")  # refresh "a" — now LRU is "b"

        bt.add("d")  # should evict "b"
        assert "b" not in bt.q
        assert "a" in bt.q
        assert "d" in bt.q


class TestStaleEviction:
    """TTL-based eviction of cold IPs (_evict_stale / HIGH-001)."""

    def test_cold_ip_evicted_on_next_add(self):
        bt = BurstTracker(window_seconds=60, max_size=20000)
        now = time.time()
        from collections import deque

        # Seed a cold IP whose only timestamp is outside the window
        bt.q["cold.ip"] = deque([now - 120])

        # Calling add() for any IP triggers _evict_stale
        bt.add("new.ip")
        assert "cold.ip" not in bt.q

    def test_active_ip_not_evicted(self):
        bt = BurstTracker(window_seconds=60, max_size=20000)
        bt.add("active.ip")
        size_before = bt.size()

        bt.add("another.ip")
        assert "active.ip" in bt.q
        assert bt.size() == size_before + 1

    def test_multiple_cold_ips_swept(self):
        bt = BurstTracker(window_seconds=60, max_size=20000)
        now = time.time()
        from collections import deque

        for i in range(5):
            bt.q[f"cold{i}"] = deque([now - 120])

        bt.add("trigger.ip")

        for i in range(5):
            assert f"cold{i}" not in bt.q

    def test_sweep_stops_at_first_active_entry(self):
        """Active IPs must not be evicted during the stale sweep."""
        bt = BurstTracker(window_seconds=60, max_size=20000)
        now = time.time()
        from collections import deque

        # One cold IP at the front (LRU), one active IP after it
        bt.q["cold"] = deque([now - 120])
        bt.q["active"] = deque([now - 10])

        bt._evict_stale(now)

        assert "cold" not in bt.q
        assert "active" in bt.q

    def test_empty_deque_treated_as_stale(self):
        bt = BurstTracker(window_seconds=60, max_size=20000)
        from collections import deque
        bt.q["ghost"] = deque()  # empty — no recent queries

        bt._evict_stale(time.time())
        assert "ghost" not in bt.q

    def test_max_evict_bounds_work_per_call(self):
        """_evict_stale must not scan more than max_evict entries per call."""
        bt = BurstTracker(window_seconds=60, max_size=20000)
        now = time.time()
        from collections import deque

        # 30 cold IPs — more than the default max_evict=20
        for i in range(30):
            bt.q[f"cold{i}"] = deque([now - 120])

        bt._evict_stale(now, max_evict=20)

        # Exactly 20 should have been evicted
        assert bt.size() == 10


class TestSizeHelper:
    def test_size_reflects_tracked_ips(self):
        bt = BurstTracker(window_seconds=60)
        assert bt.size() == 0
        bt.add("x")
        assert bt.size() == 1
        bt.add("y")
        assert bt.size() == 2
