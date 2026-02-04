"""
Circuit breaker for metrics recording.

Prevents cascading failures when metrics collection fails.
"""

import logging
import time

logger = logging.getLogger(__name__)


class MetricsCircuitBreaker:
    """Simple circuit breaker for metrics recording."""

    def __init__(self, max_failures: int = 5):
        self.failures = 0
        self.max_failures = max_failures
        self.is_open = False
        self.last_failure_time = 0

    def execute(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.is_open:
            # Try to close after 60 seconds
            if time.time() - self.last_failure_time > 60:
                self.is_open = False
                self.failures = 0
            else:
                return

        try:
            func(*args, **kwargs)
            self.failures = 0  # Reset on success
        except Exception as e:
            logger.debug(f"Metrics recording failed: {e}")
            self.failures += 1
            self.last_failure_time = time.time()

            if self.failures >= self.max_failures:
                self.is_open = True
                logger.warning(f"Metrics circuit breaker opened after {self.failures} failures")
