"""Small process-wide concurrency admission primitives."""

from __future__ import annotations

import threading
import time
from collections import deque
from math import isfinite
from typing import Callable, Optional


class ConcurrencyWaitCancelled(Exception):
    """Raised when a queued admission is cooperatively cancelled."""


class ConcurrencyLease:
    """Idempotent lease returned by a concurrency gate."""

    def __init__(self, gate: "NonBlockingConcurrencyGate | FairConcurrencyGate") -> None:
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


class FairConcurrencyGate:
    """Bound process-wide work with FIFO, timeout-bounded admission.

    The limit is supplied at admission time for the same reason as
    :class:`NonBlockingConcurrencyGate`: config changes do not replace a
    semaphore while leases are active. A waiter may only acquire when it is at
    the head of the queue, so later callers cannot barge ahead.
    """

    _CANCEL_POLL_SECONDS = 0.05

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0
        self._waiters: deque[object] = deque()

    def acquire(
        self,
        limit: int,
        timeout_seconds: float,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Optional[ConcurrencyLease]:
        """Wait fairly for capacity, returning ``None`` on timeout.

        Queue bookkeeping is removed in ``finally`` so interruption while
        waiting cannot strand the head ticket. ``cancel_check`` is an internal
        cooperative hook; cancellation is distinct from expiry so callers do
        not misreport an interrupt as a queue timeout.
        """
        normalized_limit = max(1, int(limit))
        normalized_timeout = float(timeout_seconds)
        if not isfinite(normalized_timeout):
            raise ValueError("timeout_seconds must be finite")
        normalized_timeout = max(0.0, normalized_timeout)
        deadline = time.monotonic() + normalized_timeout
        ticket = object()
        admitted = False
        has_waited = False

        with self._condition:
            self._waiters.append(ticket)
            try:
                while True:
                    if cancel_check is not None and cancel_check():
                        raise ConcurrencyWaitCancelled

                    # Capacity available on entry is admitted immediately.
                    # Once a caller has waited, the deadline wins any race
                    # with a release so the queue ceiling remains strict.
                    if has_waited and time.monotonic() >= deadline:
                        return None

                    if self._waiters[0] is ticket and self._active < normalized_limit:
                        self._waiters.popleft()
                        self._active += 1
                        admitted = True
                        # More than one slot may be free. Wake the new head so
                        # it can claim the next one without waiting for a
                        # release from this lease.
                        self._condition.notify_all()
                        return ConcurrencyLease(self)

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    if cancel_check is not None:
                        remaining = min(remaining, self._CANCEL_POLL_SECONDS)
                    self._condition.wait(remaining)
                    has_waited = True
            finally:
                if not admitted:
                    try:
                        self._waiters.remove(ticket)
                    except ValueError:
                        pass
                    self._condition.notify_all()

    def _release(self) -> None:
        with self._condition:
            if self._active > 0:
                self._active -= 1
            self._condition.notify_all()
