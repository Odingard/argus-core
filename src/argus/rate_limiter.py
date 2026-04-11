"""Rate Limiter + Circuit Breaker for client target protection.

Prevents ARGUS from overwhelming client AI systems during scans.
Integrates with the SandboxEnvironment to enforce per-target limits.

Rate Limiter:
- Token bucket algorithm with configurable RPM (requests per minute)
- Per-target tracking — different targets can have different limits
- Burst allowance — short bursts above RPM are allowed up to a cap

Circuit Breaker:
- Monitors consecutive failures (5xx, timeouts, connection errors)
- CLOSED → OPEN after N consecutive failures (default 5)
- OPEN → HALF_OPEN after cooldown period (default 30s)
- HALF_OPEN → CLOSED on first success, OPEN on failure
- Emits signals when state changes so the operator is notified
"""

from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RateLimiter:
    """Token bucket rate limiter for outbound requests.

    Args:
        requests_per_minute: Maximum sustained request rate.
        burst_size: Maximum burst size above the sustained rate.
    """

    def __init__(self, requests_per_minute: int = 60, burst_size: int = 10) -> None:
        self.rpm = requests_per_minute
        self.burst_size = burst_size
        self._tokens = float(burst_size)
        self._max_tokens = float(burst_size)
        self._refill_rate = requests_per_minute / 60.0  # tokens per second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._total_throttled = 0

    async def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a rate limit token. Blocks until available or timeout.

        Returns True if acquired, False if timed out.
        """
        deadline = time.monotonic() + timeout

        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_requests += 1
                    return True

            # Not enough tokens — wait and retry
            if time.monotonic() >= deadline:
                self._total_throttled += 1
                logger.warning(
                    "Rate limiter: request throttled (RPM=%d, total_throttled=%d)",
                    self.rpm,
                    self._total_throttled,
                )
                return False

            # Sleep until next token is available
            async with self._lock:
                wait_time = (1.0 - self._tokens) / self._refill_rate if self._refill_rate > 0 else 1.0
            await asyncio.sleep(min(wait_time, 0.5))

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "rpm": self.rpm,
            "burst_size": self.burst_size,
            "total_requests": self._total_requests,
            "total_throttled": self._total_throttled,
            "available_tokens": round(self._tokens, 2),
        }


class CircuitBreaker:
    """Circuit breaker to protect client systems from continued hammering.

    Monitors consecutive failures and opens the circuit when the threshold
    is reached. The circuit auto-recovers after a cooldown period.

    Args:
        failure_threshold: Consecutive failures before opening circuit.
        recovery_timeout: Seconds to wait before trying half-open.
        success_threshold: Successes in half-open before closing circuit.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._lock = asyncio.Lock()
        self._total_trips = 0
        self._state_change_callbacks: list = []

    @property
    def state(self) -> CircuitState:
        return self._state

    async def check_allowed(self) -> bool:
        """Check if a request is allowed through the circuit.

        Returns True if allowed, False if circuit is open.
        """
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                # Check if cooldown has elapsed
                if self._last_failure_time and (time.monotonic() - self._last_failure_time) >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    logger.info("Circuit breaker: OPEN → HALF_OPEN (testing recovery)")
                    return True
                return False

            if self._state == CircuitState.HALF_OPEN:
                return True

            return False

    async def record_success(self) -> None:
        """Record a successful request."""
        async with self._lock:
            self._failure_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    logger.info("Circuit breaker: HALF_OPEN → CLOSED (recovered)")

    async def record_failure(self) -> None:
        """Record a failed request (5xx, timeout, connection error)."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning("Circuit breaker: HALF_OPEN → OPEN (recovery failed)")
                self._total_trips += 1
                return

            if self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._total_trips += 1
                logger.warning(
                    "Circuit breaker: CLOSED → OPEN after %d consecutive failures (cooldown=%.0fs)",
                    self._failure_count,
                    self.recovery_timeout,
                )

    async def reset(self) -> None:
        """Force reset the circuit to CLOSED state."""
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "total_trips": self._total_trips,
        }


class TargetProtection:
    """Combined rate limiter + circuit breaker for a target.

    Provides a single interface for the scan engine to check before
    sending each request to a client's AI system.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: int = 10,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        self.rate_limiter = RateLimiter(
            requests_per_minute=requests_per_minute,
            burst_size=burst_size,
        )
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

    async def acquire(self, timeout: float = 30.0) -> bool:
        """Check circuit breaker and acquire rate limit token.

        Returns True if the request should proceed, False otherwise.
        """
        # Check circuit breaker first — fast path rejection
        if not await self.circuit_breaker.check_allowed():
            logger.debug("Request blocked: circuit breaker is OPEN")
            return False

        # Then rate limit
        if not await self.rate_limiter.acquire(timeout=timeout):
            logger.debug("Request blocked: rate limit exceeded")
            return False

        return True

    async def record_success(self) -> None:
        await self.circuit_breaker.record_success()

    async def record_failure(self) -> None:
        await self.circuit_breaker.record_failure()

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "rate_limiter": self.rate_limiter.stats,
            "circuit_breaker": self.circuit_breaker.stats,
        }
