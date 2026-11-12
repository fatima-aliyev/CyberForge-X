"""Token-slot rate limiter and global request budget."""

from __future__ import annotations

import random
import threading
import time

from cyberforge.core.exceptions import RateLimitError, RequestBudgetExceeded


class RateLimiter:
    """Politeness limiter that spaces request starts across threads.

    The limiter is intentionally conservative: it schedules request slots in a
    single lock and sleeps outside the lock, so concurrent callers receive
    evenly spaced slots instead of a burst.
    """

    def __init__(self, requests_per_second: float = 5.0, jitter: float = 0.15) -> None:
        if requests_per_second <= 0:
            raise RateLimitError("requests_per_second must be positive")
        if jitter < 0:
            raise RateLimitError("jitter must not be negative")
        self.requests_per_second = float(requests_per_second)
        self.jitter = float(min(jitter, 2.0))
        self._interval = 1.0 / self.requests_per_second
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
            wait = slot - now
        if wait > 0:
            time.sleep(wait)
        if self.jitter:
            time.sleep(random.uniform(0.0, self.jitter))


class RequestBudget:
    """Hard cap on the number of outbound target requests."""

    def __init__(self, max_requests: int) -> None:
        if max_requests < 1:
            raise RateLimitError("max_requests must be at least 1")
        self.max_requests = int(max_requests)
        self._count = 0
        self._lock = threading.Lock()

    def consume(self, amount: int = 1) -> int:
        with self._lock:
            if self._count + amount > self.max_requests:
                raise RequestBudgetExceeded(
                    f"request budget exhausted ({self._count}/{self.max_requests})"
                )
            self._count += amount
            return self._count

    @property
    def used(self) -> int:
        with self._lock:
            return self._count

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.max_requests - self._count


SPEED_PROFILES: dict[str, dict[str, float | int]] = {
    "safe": {"rate": 2.0, "jitter": 0.35, "workers": 4},
    "normal": {"rate": 5.0, "jitter": 0.15, "workers": 8},
    "aggressive": {"rate": 15.0, "jitter": 0.05, "workers": 16},
}
