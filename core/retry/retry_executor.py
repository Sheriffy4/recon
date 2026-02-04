from __future__ import annotations

# File: core/retry/retry_executor.py
"""
Retry execution utilities with exponential backoff.

This module provides focused functions for executing operations with intelligent
retry mechanisms, extracted from UnifiedBypassEngine to reduce method complexity.
"""

import time
import logging
from typing import Callable, Tuple, Any, Optional

LOG = logging.getLogger("retry_executor")


def calculate_retry_delay(
    attempt: int,
    retry_delay_base: float,
    retry_backoff_multiplier: float,
) -> float:
    """
    Calculate delay for retry attempt using exponential backoff.

    Args:
        attempt: Current attempt number (0-indexed, where 0 is first retry)
        retry_delay_base: Base delay in seconds
        retry_backoff_multiplier: Multiplier for exponential backoff

    Returns:
        Delay in seconds for this retry attempt
    """
    return retry_delay_base * (retry_backoff_multiplier**attempt)


def execute_with_retry(
    operation: Callable[[], Tuple[bool, str]],
    max_retries: int,
    retry_delay_base: float,
    retry_backoff_multiplier: float,
    is_retryable_error: Callable[[str], bool],
    logger,
    operation_name: str = "operation",
) -> Tuple[bool, str]:
    """
    Execute an operation with intelligent retry mechanism.

    This is a generic retry executor that handles:
    - Exponential backoff between retries
    - Retryable vs non-retryable error detection
    - Logging of retry attempts
    - Exception handling

    Args:
        operation: Callable that returns (success: bool, reason: str)
        max_retries: Maximum number of retry attempts
        retry_delay_base: Base delay between retries in seconds
        retry_backoff_multiplier: Multiplier for exponential backoff
        is_retryable_error: Function to determine if error is retryable
        logger: Logger instance for logging retry attempts
        operation_name: Name of operation for logging

    Returns:
        Tuple[bool, str]: (success, reason)
    """
    logger = logger or LOG
    last_error = None

    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            # Apply delay for retry attempts (not for initial attempt)
            if attempt > 0:
                delay = calculate_retry_delay(
                    attempt - 1, retry_delay_base, retry_backoff_multiplier
                )
                logger.info(
                    f"🔄 {operation_name} retry attempt {attempt}/{max_retries} "
                    f"after {delay:.1f}s delay"
                )
                time.sleep(delay)

            # Execute the operation
            success, reason = operation()

            if success:
                if attempt > 0:
                    logger.info(f"✅ {operation_name} succeeded on retry attempt {attempt}")
                return True, reason
            else:
                # Check if this is a retryable error
                if is_retryable_error(reason):
                    last_error = reason
                    if attempt < max_retries:
                        logger.warning(f"⚠️ Retryable error on attempt {attempt + 1}: {reason}")
                        continue
                    else:
                        logger.warning(f"❌ Max retries reached, last error: {reason}")
                        return False, f"Max retries reached: {reason}"
                else:
                    # Non-retryable error, fail immediately
                    logger.warning(f"❌ Non-retryable error: {reason}")
                    return False, reason

        except Exception as e:
            last_error = f"{operation_name} error: {e}"
            if attempt < max_retries:
                logger.warning(
                    f"⚠️ {operation_name} error on attempt {attempt + 1}: {e}, retrying..."
                )
                continue
            else:
                return False, last_error

    return False, last_error or f"{operation_name} failed after all retries"


def execute_subprocess_with_retry(
    build_command: Callable[[], list],
    max_retries: int,
    retry_delay_base: float,
    retry_backoff_multiplier: float,
    timeout: float,
    analyze_response: Callable[[str, str, int], Tuple[bool, str]],
    is_retryable_error: Callable[[str, str], bool],
    logger,
    operation_name: str = "subprocess",
) -> Tuple[bool, str]:
    """
    Execute subprocess command with intelligent retry mechanism.

    Specialized retry executor for subprocess operations (like curl) that handles:
    - Command building
    - Subprocess execution with timeout
    - Response analysis
    - Timeout and FileNotFoundError handling
    - Exponential backoff

    Args:
        build_command: Callable that returns command list
        max_retries: Maximum number of retry attempts
        retry_delay_base: Base delay between retries in seconds
        retry_backoff_multiplier: Multiplier for exponential backoff
        timeout: Timeout for subprocess execution
        analyze_response: Function to analyze subprocess output
        is_retryable_error: Function to determine if error is retryable
        logger: Logger instance
        operation_name: Name of operation for logging

    Returns:
        Tuple[bool, str]: (success, reason)
    """
    import subprocess

    last_error = None

    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            # Apply delay for retry attempts
            if attempt > 0:
                delay = calculate_retry_delay(
                    attempt - 1, retry_delay_base, retry_backoff_multiplier
                )
                logger.info(
                    f"🔄 {operation_name} retry attempt {attempt}/{max_retries} "
                    f"after {delay:.1f}s delay"
                )
                time.sleep(delay)

            cmd = build_command()
            logger.debug(
                "🌐 Executing %s (attempt %s): %s",
                operation_name,
                attempt + 1,
                " ".join(map(str, cmd)),
            )

            # Execute subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)

            # Analyze response
            is_accessible, reason = analyze_response(
                result.stdout or "", result.stderr or "", int(getattr(result, "returncode", -1))
            )

            if is_accessible:
                if attempt > 0:
                    logger.info(f"✅ {operation_name} succeeded on retry attempt {attempt}")
                return True, reason
            else:
                # Check if this is a retryable error
                if is_retryable_error(result.stderr or "", reason):
                    last_error = reason
                    if attempt < max_retries:
                        logger.warning(f"⚠️ Retryable error on attempt {attempt + 1}: {reason}")
                        continue
                    else:
                        logger.warning(f"❌ Max retries reached, last error: {reason}")
                        return False, f"Max retries reached: {reason}"
                else:
                    # Non-retryable error, fail immediately
                    logger.warning(f"❌ Non-retryable error: {reason}")
                    return False, reason

        except FileNotFoundError:
            return False, f"{operation_name} executable not found"
        except subprocess.TimeoutExpired:
            last_error = f"{operation_name} timeout after {timeout}s"
            if attempt < max_retries:
                logger.warning(f"⚠️ {operation_name} timeout on attempt {attempt + 1}, retrying...")
                continue
            else:
                return False, last_error
        except Exception as e:
            last_error = f"{operation_name} execution error: {e}"
            if attempt < max_retries:
                logger.warning(
                    f"⚠️ {operation_name} error on attempt {attempt + 1}: {e}, retrying..."
                )
                continue
            else:
                return False, last_error

    return False, last_error or f"{operation_name} failed after all retries"


# ============================================================================
# Retry Predicates (Error Classification)
# ============================================================================


def is_retryable_tcp_error(reason: str) -> bool:
    """
    Determine if a TCP connectivity error is retryable.

    TCP timeouts are typically retryable (transient network issues),
    while connection refused errors are not (service not running).

    Args:
        reason: Error reason from TCP test

    Returns:
        bool: True if error should be retried

    Examples:
        >>> is_retryable_tcp_error("Connection timeout")
        True

        >>> is_retryable_tcp_error("Connection refused")
        False

        >>> is_retryable_tcp_error("Network unreachable")
        True
    """
    if not reason:
        return False

    reason_lower = reason.lower()

    # Retryable patterns for TCP errors
    retryable_patterns = [
        "timeout",
        "timed out",
        "temporary failure",
        "network unreachable",
        "host unreachable",
        "no route to host",
    ]

    # Non-retryable patterns
    non_retryable_patterns = [
        "connection refused",
        "connection reset",
        "port unreachable",
    ]

    # Check non-retryable first (more specific)
    for pattern in non_retryable_patterns:
        if pattern in reason_lower:
            return False

    # Check retryable
    for pattern in retryable_patterns:
        if pattern in reason_lower:
            return True

    return False


def is_retryable_requests_error(reason: str) -> bool:
    """
    Determine if a requests library error is retryable.

    Timeout and temporary network errors are retryable,
    while DNS failures and connection refused are not.

    Args:
        reason: Error reason from requests test

    Returns:
        bool: True if error should be retried

    Examples:
        >>> is_retryable_requests_error("Read timeout")
        True

        >>> is_retryable_requests_error("Connection refused")
        False

        >>> is_retryable_requests_error("DNS resolution failed")
        False
    """
    if not reason:
        return False

    reason_lower = reason.lower()

    # Retryable patterns for requests errors
    retryable_patterns = [
        "timeout",
        "connection timeout",
        "read timeout",
        "temporary failure",
        "network unreachable",
        "recv failure",
    ]

    # Non-retryable patterns
    non_retryable_patterns = [
        "connection refused",
        "name resolution failed",
        "dns",
        "requests library not available",
        "connection error",
    ]

    # Check non-retryable first
    for pattern in non_retryable_patterns:
        if pattern in reason_lower:
            return False

    # Check retryable
    for pattern in retryable_patterns:
        if pattern in reason_lower:
            return True

    return False


def is_retryable_curl_error(stderr: str, reason: str) -> bool:
    """
    Determine if a curl error is retryable.

    Analyzes both stderr output and reason string to determine
    if the error is transient (retryable) or permanent.

    Args:
        stderr: Curl stderr output
        reason: Error reason string

    Returns:
        bool: True if error should be retried

    Examples:
        >>> is_retryable_curl_error("Operation timed out", "timeout")
        True

        >>> is_retryable_curl_error("Connection refused", "refused")
        False

        >>> is_retryable_curl_error("SSL certificate problem", "ssl error")
        False
    """
    if not stderr and not reason:
        return False

    stderr_lower = (stderr or "").lower()
    reason_lower = (reason or "").lower()

    # Retryable patterns
    retryable_patterns = [
        "timeout",
        "timed out",
        "operation timeout",
        "temporary failure",
        "network unreachable",
        "recv failure",
        "send failure",
        "partial file",
    ]

    # Non-retryable patterns
    non_retryable_patterns = [
        "connection refused",
        "could not resolve host",
        "ssl",
        "certificate",
        "authentication",
        "forbidden",
        "not found",
        "curl not found",
    ]

    # Check non-retryable first
    for pattern in non_retryable_patterns:
        if pattern in stderr_lower or pattern in reason_lower:
            return False

    # Check retryable
    for pattern in retryable_patterns:
        if pattern in stderr_lower or pattern in reason_lower:
            return True

    return False


def is_retryable_http_error(http_code: int, reason: str) -> bool:
    """
    Determine if an HTTP error is retryable based on status code.

    5xx errors (server errors) are typically retryable,
    while 4xx errors (client errors) are not.

    Args:
        http_code: HTTP status code
        reason: Error reason string

    Returns:
        bool: True if error should be retried

    Examples:
        >>> is_retryable_http_error(503, "Service Unavailable")
        True

        >>> is_retryable_http_error(404, "Not Found")
        False

        >>> is_retryable_http_error(500, "Internal Server Error")
        True
    """
    # 5xx errors are typically retryable (server-side issues)
    if 500 <= http_code < 600:
        # Except for some specific codes
        non_retryable_5xx = [
            501,
            505,
            511,
        ]  # Not Implemented, Version Not Supported, Network Auth Required
        if http_code in non_retryable_5xx:
            return False
        return True

    # 429 Too Many Requests is retryable (rate limiting)
    if http_code == 429:
        return True

    # 408 Request Timeout is retryable
    if http_code == 408:
        return True

    # 4xx errors are generally not retryable (client errors)
    if 400 <= http_code < 500:
        return False

    # Check reason for timeout patterns
    if reason:
        reason_lower = reason.lower()
        if "timeout" in reason_lower or "temporary" in reason_lower:
            return True

    return False
