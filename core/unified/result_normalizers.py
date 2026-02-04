# Файл: core/unified/result_normalizers.py
"""
Result normalization utilities for unified bypass engine.

This module provides functions to standardize result dictionaries from different
testing paths (curl, tls-client, aiohttp, etc.) into a consistent format.
"""

import time
from typing import Dict, Any, Tuple


def standardize_timing_fields(result: Dict[str, Any], start_mono: float) -> None:
    """
    Ensure common timing keys exist across different testing paths.

    This function adds standardized timing fields to result dictionaries,
    calculating elapsed time from a monotonic start timestamp. It is additive
    only and never removes legacy fields.

    Args:
        result: Result dictionary to modify in-place
        start_mono: Monotonic timestamp from time.monotonic() when test started

    Side Effects:
        Modifies result dict in-place, adding:
        - execution_time_ms: Total execution time in milliseconds
        - response_time_ms: Response time (alias for execution_time_ms)
        - latency_ms: Latency (alias for execution_time_ms)

    Examples:
        >>> import time
        >>> result = {}
        >>> start = time.monotonic()
        >>> time.sleep(0.1)
        >>> standardize_timing_fields(result, start)
        >>> result['execution_time_ms'] > 100
        True

    Note:
        Uses setdefault() to avoid overwriting existing timing fields.
        If timing calculation fails, defaults to 0.0 ms.
    """
    try:
        elapsed_ms = (time.monotonic() - float(start_mono)) * 1000.0
    except (ValueError, TypeError, OverflowError) as e:
        # Log error if logger available, otherwise silent fallback
        elapsed_ms = 0.0

    result.setdefault("execution_time_ms", elapsed_ms)
    result.setdefault("response_time_ms", elapsed_ms)
    result.setdefault("latency_ms", elapsed_ms)


def standardize_http_fields(
    result: Dict[str, Any],
    *,
    http_code_raw: Any,
    http_code: int,
) -> None:
    """
    Ensure common HTTP keys exist across different testing paths.

    This function adds standardized HTTP response fields to result dictionaries.
    It is additive only and never removes legacy fields.

    Args:
        result: Result dictionary to modify in-place
        http_code_raw: Raw HTTP code from source (any type)
        http_code: Parsed HTTP code as integer

    Side Effects:
        Modifies result dict in-place, adding:
        - http_code_raw: String representation of raw HTTP code
        - http_code: Integer HTTP code
        - http_success: Boolean indicating valid HTTP response (100-599)

    Examples:
        >>> result = {}
        >>> standardize_http_fields(result, http_code_raw="200", http_code=200)
        >>> result['http_success']
        True
        >>> result['http_code']
        200

        >>> result2 = {}
        >>> standardize_http_fields(result2, http_code_raw=None, http_code=0)
        >>> result2['http_success']
        False

    Note:
        Uses setdefault() to avoid overwriting existing HTTP fields.
        HTTP success is defined as code in range [100, 600).
    """
    result.setdefault("http_code_raw", str(http_code_raw) if http_code_raw is not None else "")
    result.setdefault("http_code", int(http_code) if http_code else 0)
    result.setdefault("http_success", bool(100 <= int(result["http_code"]) < 600))


def coerce_http_code(http_code_raw: Any) -> Tuple[int, str]:
    """
    Convert raw HTTP code from different sources into (code_int, code_str).

    This function handles HTTP codes from various sources (curl, tls-client, etc.)
    and normalizes them to a consistent format. It is defensive and never raises
    exceptions.

    Args:
        http_code_raw: Raw HTTP code (can be int, str, None, or any type)

    Returns:
        Tuple[int, str]: (code_int, code_str)
        - code_int: Integer HTTP code (0 if invalid/None)
        - code_str: String representation (empty string if None)

    Examples:
        >>> coerce_http_code(200)
        (200, '200')

        >>> coerce_http_code("404")
        (404, '404')

        >>> coerce_http_code(None)
        (0, '')

        >>> coerce_http_code("invalid")
        (0, 'invalid')

        >>> coerce_http_code("200 OK")
        (0, '200 OK')

    Note:
        Only pure numeric strings are converted to integers.
        Any non-numeric content results in code_int=0.
    """
    if http_code_raw is None:
        return 0, ""

    s = str(http_code_raw).strip()
    if s.isdigit():
        try:
            return int(s), s
        except (ValueError, OverflowError):
            # Should never happen for isdigit() strings, but be defensive
            return 0, s

    return 0, s


def normalize_result_dict(
    result: Dict[str, Any],
    *,
    start_mono: float,
    http_code_raw: Any = None,
    http_code: int = 0,
    add_timing: bool = True,
    add_http: bool = True,
) -> Dict[str, Any]:
    """
    Comprehensive result normalization combining timing and HTTP fields.

    This is a convenience function that applies both timing and HTTP
    standardization in one call. It modifies the result dict in-place
    and also returns it for chaining.

    Args:
        result: Result dictionary to normalize
        start_mono: Monotonic timestamp when test started
        http_code_raw: Raw HTTP code (optional)
        http_code: Parsed HTTP code (optional)
        add_timing: Whether to add timing fields (default: True)
        add_http: Whether to add HTTP fields (default: True)

    Returns:
        Dict[str, Any]: The same result dict (modified in-place)

    Examples:
        >>> import time
        >>> result = {"status": "ok"}
        >>> start = time.monotonic()
        >>> normalized = normalize_result_dict(
        ...     result,
        ...     start_mono=start,
        ...     http_code_raw="200",
        ...     http_code=200
        ... )
        >>> normalized['http_success']
        True
        >>> 'execution_time_ms' in normalized
        True

    Note:
        This function is useful when you want to apply all normalizations
        at once. For more control, use individual functions.
    """
    if add_timing:
        standardize_timing_fields(result, start_mono)

    if add_http:
        standardize_http_fields(result, http_code_raw=http_code_raw, http_code=http_code)

    return result


def extract_http_code_from_curl_output(stdout: str) -> Tuple[int, str]:
    """
    Extract HTTP code from curl output with -w "%{http_code}" format.

    Curl with -w "%{http_code}" appends the HTTP code to stdout.
    This function extracts it safely.

    Args:
        stdout: Curl stdout output

    Returns:
        Tuple[int, str]: (code_int, code_str)

    Examples:
        >>> extract_http_code_from_curl_output("200")
        (200, '200')

        >>> extract_http_code_from_curl_output("<!DOCTYPE html>...200")
        (200, '200')

        >>> extract_http_code_from_curl_output("")
        (0, '')

    Note:
        Assumes the HTTP code is the last line or last numeric token.
        This matches curl's -w "%{http_code}" behavior.
    """
    if not stdout:
        return 0, ""

    # Try to extract last line (curl appends code at the end)
    lines = stdout.strip().split("\n")
    last_line = lines[-1].strip() if lines else ""

    return coerce_http_code(last_line)
