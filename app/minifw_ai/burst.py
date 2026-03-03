from __future__ import annotations
from collections import deque, OrderedDict
import time

class BurstTracker:
    def __init__(self, window_seconds: int = 60, max_size: int = 20000):
        self.window = window_seconds
        self.max_size = max_size
        self.q: OrderedDict[str, deque] = OrderedDict()

    def _evict_stale(self, now: float, max_evict: int = 20) -> None:
        """Remove cold IPs from the LRU front of the queue.

        IPs are kept in LRU order (move_to_end on every add), so the front
        always holds the least-recently-seen entries. If the front IP's most
        recent timestamp is older than the window it is cold and evicted.
        Stops at the first active entry or after max_evict evictions so that
        worst-case cost per add() call is bounded.
        """
        evicted = 0
        while self.q and evicted < max_evict:
            ip, dq = next(iter(self.q.items()))
            # dq[-1] is the newest timestamp for this IP (appended last).
            # Empty deque means all prior timestamps already expired.
            if dq and (now - dq[-1]) <= self.window:
                break  # front is still active; everything after is newer
            del self.q[ip]
            evicted += 1

    def add(self, ip: str) -> int:
        now = time.time()

        # Evict cold IPs before checking capacity so freed slots are visible.
        self._evict_stale(now)

        # LRU: move existing entry to end; evict LRU tail if still at capacity.
        if ip in self.q:
            self.q.move_to_end(ip)
        elif len(self.q) >= self.max_size:
            self.q.popitem(last=False)

        if ip not in self.q:
            self.q[ip] = deque()
        dq = self.q[ip]

        dq.append(now)

        # Trim timestamps outside the sliding window for this IP.
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

        return len(dq)

    def size(self) -> int:
        """Number of tracked IPs (active + not yet evicted)."""
        return len(self.q)

