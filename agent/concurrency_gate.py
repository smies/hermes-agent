"""Small process-wide, non-queueing concurrency admission primitive."""

from __future__ import annotations

import threading
import time
from typing import Optional


class ConcurrencyLease:
    """Idempotent lease returned by :class:`NonBlockingConcurrencyGate`."""

    def __init__(self, gate: "NonBlockingConcurrencyGate") -> None:
        self._gate = gate
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._gate._release()


class NonBlockingConcurrencyGate:
    """Bound process-wide work without blocking or creating a wait queue.

    The limit is supplied at admission time so a config reload can raise or
    lower capacity without replacing a semaphore while leases are active.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active = 0
        self._rejections_since_log = 0
        self._last_rejection_log = 0.0

    def try_acquire(self, limit: int) -> Optional[ConcurrencyLease]:
        normalized_limit = max(1, int(limit))
        with self._lock:
            if self._active >= normalized_limit:
                self._rejections_since_log += 1
                return None
            self._active += 1
        return ConcurrencyLease(self)

    def rejection_log_count(self, interval_seconds: float = 30.0) -> int:
        """Return a coalesced rejection count at most once per interval."""
        now = time.monotonic()
        with self._lock:
            if not self._rejections_since_log:
                return 0
            if self._last_rejection_log and now - self._last_rejection_log < interval_seconds:
                return 0
            count = self._rejections_since_log
            self._rejections_since_log = 0
            self._last_rejection_log = now
            return count

    def _release(self) -> None:
        with self._lock:
            if self._active > 0:
                self._active -= 1

