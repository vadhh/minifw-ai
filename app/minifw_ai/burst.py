from __future__ import annotations
from collections import deque, defaultdict
import time

class BurstTracker:
    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self.q = defaultdict(deque)

    def add(self, ip: str) -> int:
        now = time.time()
        dq = self.q[ip]
        dq.append(now)
        while dq and (now - dq[0]) > self.window:
            dq.popleft()
        return len(dq)
