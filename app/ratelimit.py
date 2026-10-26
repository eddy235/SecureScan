"""Single-process bounded scan limiter; intended for private loopback mode."""
from collections import deque
from threading import Lock
from time import monotonic


class ScanRateLimiter:
    def __init__(self, limit=10, window_seconds=60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.events = deque()
        self.lock = Lock()

    def allow(self, now=None):
        if now is None:
            now = monotonic()
        with self.lock:
            while self.events and now - self.events[0] >= self.window_seconds:
                self.events.popleft()
            if len(self.events) >= self.limit:
                return False
            self.events.append(now)
            return True


scan_limiter = ScanRateLimiter()
