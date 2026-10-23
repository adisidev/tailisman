"""Failed-password limits: a sliding window per client IP and one across all IPs. In memory; a restart forgets them."""

from __future__ import annotations

import collections
import threading

from .config import RateLimits


class RateLimiter:
    def __init__(self, limits: RateLimits) -> None:
        self.limits = limits
        self._lock = threading.Lock()
        self._per_ip: dict[str, collections.deque[float]] = {}
        self._total: collections.deque[float] = collections.deque()

    def retry_after(self, ip: str, now: float) -> int | None:
        """Seconds until this IP may try again, or None when it may try now."""
        with self._lock:
            self._expire(now)
            waits = [
                window[0] + self.limits.window_seconds - now
                for window, limit in ((self._per_ip.get(ip), self.limits.per_ip), (self._total, self.limits.total))
                if window is not None and len(window) >= limit
            ]
            return max(1, int(max(waits)) + 1) if waits else None

    def record_failure(self, ip: str, now: float) -> None:
        with self._lock:
            self._per_ip.setdefault(ip, collections.deque()).append(now)
            self._total.append(now)

    def _expire(self, now: float) -> None:
        cutoff = now - self.limits.window_seconds
        for window in (self._total, *self._per_ip.values()):
            while window and window[0] <= cutoff:
                window.popleft()
        self._per_ip = {ip: window for ip, window in self._per_ip.items() if window}
