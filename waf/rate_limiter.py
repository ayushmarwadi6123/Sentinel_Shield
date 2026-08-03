"""
rate_limiter.py
----------------
Behavior monitoring / rate limiting component of SentinelShield.

Implements a simple sliding-window request counter per source IP.
If an IP exceeds `MAX_REQUESTS` within `WINDOW_SECONDS`, it is flagged
as abusive and temporarily blocked for `BLOCK_SECONDS`.

This demonstrates the "traffic monitoring -> threshold -> flagging"
concept from the practical documentation without needing an external
datastore (Redis, etc.) — everything is kept in memory, which is fine
for a single-process teaching deployment.
"""

import time
import threading
from collections import defaultdict, deque

MAX_REQUESTS = 20        # allowed requests
WINDOW_SECONDS = 10       # ...within this many seconds
BLOCK_SECONDS = 60        # how long an abusive IP stays blocked


class RateLimiter:
    def __init__(self, max_requests=MAX_REQUESTS, window_seconds=WINDOW_SECONDS,
                 block_seconds=BLOCK_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._requests = defaultdict(deque)   # ip -> deque[timestamps]
        self._blocked_until = {}              # ip -> unix timestamp
        self._lock = threading.Lock()

    def _prune(self, ip: str, now: float):
        dq = self._requests[ip]
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def check(self, ip: str):
        """
        Register a request from `ip` and decide whether it should be
        allowed. Returns a dict describing the decision.
        """
        now = time.time()
        with self._lock:
            # Already blocked?
            blocked_until = self._blocked_until.get(ip)
            if blocked_until and now < blocked_until:
                return {
                    "allowed": False,
                    "reason": "IP_TEMPORARILY_BLOCKED",
                    "retry_after": round(blocked_until - now, 1),
                    "request_count": len(self._requests[ip]),
                }

            self._prune(ip, now)
            self._requests[ip].append(now)
            count = len(self._requests[ip])

            if count > self.max_requests:
                self._blocked_until[ip] = now + self.block_seconds
                return {
                    "allowed": False,
                    "reason": "RATE_LIMIT_EXCEEDED",
                    "retry_after": self.block_seconds,
                    "request_count": count,
                }

            return {"allowed": True, "reason": "OK", "retry_after": 0, "request_count": count}

    def snapshot(self):
        """Return current per-IP counters for dashboard display."""
        now = time.time()
        with self._lock:
            data = {}
            for ip, dq in self._requests.items():
                self._prune(ip, now)
                data[ip] = {
                    "requests_in_window": len(dq),
                    "blocked": ip in self._blocked_until and now < self._blocked_until[ip],
                }
            return data


# Single shared instance used by the whole app
rate_limiter = RateLimiter()
