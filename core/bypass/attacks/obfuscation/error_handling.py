"""
Error handling utilities for protocol mimicry attacks.

Provides unified exception handling for all protocol mimicry attack classes.
"""

import asyncio
import time
from core.bypass.attacks.base import AttackResult, AttackStatus


def handle_attack_execution_error(
    exception: Exception, start_time: float, technique_used: str
) -> AttackResult:
    """
    Handle exceptions during attack execution with appropriate error categorization.

    Args:
        exception: The caught exception
        start_time: Attack start time (from time.time())
        technique_used: Name of the technique being executed

    Returns:
        AttackResult with appropriate error status and message
    """
    latency_ms = (time.time() - start_time) * 1000

    # Note: asyncio.CancelledError is BaseException on py3.12 and should normally propagate.
    if isinstance(exception, asyncio.TimeoutError):
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=f"Timeout or cancellation: {str(exception)}",
            latency_ms=latency_ms,
            technique_used=technique_used,
        )
    elif isinstance(exception, (ValueError, TypeError, KeyError)):
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=f"Invalid parameter or data: {str(exception)}",
            latency_ms=latency_ms,
            technique_used=technique_used,
        )
    else:
        # Catch-all for unexpected errors
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=f"Unexpected error: {str(exception)}",
            latency_ms=latency_ms,
            technique_used=technique_used,
        )
