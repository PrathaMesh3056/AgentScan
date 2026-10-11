# agentscan/core/circuit_breaker.py
#
# Production Async Circuit Breaker (Resilience4j State Machine Pattern).
# States:
#   - CLOSED: Normal operation. All requests pass through.
#   - OPEN: Tripped. Requests fail fast with CircuitBreakerOpenError without hitting the network.
#   - HALF_OPEN: Trial period. A limited number of trial requests are permitted to test recovery.

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Any, TypeVar

from loguru import logger

T = TypeVar("T")


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""

    def __init__(self, name: str, reset_timeout: float):
        super().__init__(
            f"Circuit breaker '{name}' is OPEN. Target is unresponsive or failing. "
            f"Fast-failing requests for {reset_timeout:.1f}s."
        )
        self.name = name
        self.reset_timeout = reset_timeout


class AsyncCircuitBreaker:
    """
    Thread-safe & asyncio-compatible circuit breaker.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_trials: int = 3,
        monitored_exceptions: tuple[type[Exception], ...] = (Exception,),
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_trials = half_open_max_trials
        self.monitored_exceptions = monitored_exceptions

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._consecutive_successes = 0
        self._trial_count = 0
        self._last_state_change = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute async function guarded by this circuit breaker."""
        trial = False
        async with self._lock:
            now = time.monotonic()

            if self._state == CircuitState.OPEN:
                if now - self._last_state_change >= self.recovery_timeout:
                    logger.info(
                        f"CircuitBreaker [{self.name}]: Transitioning OPEN -> HALF_OPEN (probing recovery)"
                    )
                    self._state = CircuitState.HALF_OPEN
                    self._last_state_change = now
                    self._trial_count = 0
                    self._consecutive_successes = 0
                else:
                    raise CircuitBreakerOpenError(
                        self.name, self.recovery_timeout - (now - self._last_state_change)
                    )

            if self._state == CircuitState.HALF_OPEN:
                if self._trial_count >= self.half_open_max_trials:
                    raise CircuitBreakerOpenError(self.name, self.recovery_timeout)
                self._trial_count += 1
                trial = True

        # Execute operation outside the lock so other requests aren't held
        try:
            result = func(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError:
            async with self._lock:
                if trial and self._state == CircuitState.HALF_OPEN:
                    self._trial_count = max(0, self._trial_count - 1)
            raise
        except self.monitored_exceptions as exc:
            await self._on_failure(exc)
            raise
        except BaseException:
            async with self._lock:
                if trial and self._state == CircuitState.HALF_OPEN:
                    self._trial_count = max(0, self._trial_count - 1)
            raise
        else:
            await self._on_success()
            return result

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._consecutive_successes += 1
                if self._consecutive_successes >= self.half_open_max_trials:
                    logger.info(
                        f"CircuitBreaker [{self.name}]: Recovery confirmed. HALF_OPEN -> CLOSED"
                    )
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._consecutive_successes = 0
                    self._last_state_change = time.monotonic()
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    async def _on_failure(self, exc: Exception) -> None:
        async with self._lock:
            self._failure_count += 1
            now = time.monotonic()
            logger.warning(
                f"CircuitBreaker [{self.name}]: Failure {self._failure_count}/{self.failure_threshold} "
                f"({exc.__class__.__name__}: {exc})"
            )

            if (
                self._state == CircuitState.HALF_OPEN
                or self._failure_count >= self.failure_threshold
            ):
                logger.error(
                    f"CircuitBreaker [{self.name}]: Threshold reached. Transitioning to OPEN"
                )
                self._state = CircuitState.OPEN
                self._last_state_change = now
