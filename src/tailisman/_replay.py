from __future__ import annotations

import threading
from typing import Protocol


class ReplayStore(Protocol):
    def claim(self, nonce: str, until: int, now: int) -> bool:
        """True the first time `nonce` is seen, False on every later call before `until`. Must be atomic across whatever shares the store."""
        ...


class InMemoryReplayStore:
    """Correct for one process. Each worker of a multi-process server would keep its own dict, so a token could be used once per worker."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str, until: int, now: int) -> bool:
        with self._lock:
            self._seen = {n: u for n, u in self._seen.items() if u >= now}
            if nonce in self._seen:
                return False
            self._seen[nonce] = until
            return True
