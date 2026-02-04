from __future__ import annotations

# Файл: core/validation/curl_validators.py
"""
Curl command validation utilities.

This module provides reusable validation functions for curl commands
to ensure consistency and reduce code duplication.
"""

from typing import List, Tuple


def validate_timeout_parameter(curl_cmd: List[str], start_index: int = 0) -> Tuple[bool, str]:
    """
    Validate that curl command contains a valid timeout parameter (-m).

    Args:
        curl_cmd: List of curl command arguments
        start_index: Index to start searching from (default: 0)

    Returns:
        Tuple[bool, str]: (is_valid, reason)

    Examples:
        >>> validate_timeout_parameter(["curl", "-m", "10", "https://example.com"])
        (True, "Valid timeout: 10 seconds")

        >>> validate_timeout_parameter(["curl", "https://example.com"])
        (False, "Missing or invalid timeout parameter (-m)")
    """
    timeout_found = False
    timeout_value = None

    for i in range(start_index, len(curl_cmd)):
        arg = curl_cmd[i]
        if arg == "-m" and i + 1 < len(curl_cmd):
            try:
                timeout_val = int(curl_cmd[i + 1])
                if timeout_val > 0:
                    timeout_found = True
                    timeout_value = timeout_val
                    break
            except ValueError:
                pass

    if not timeout_found:
        return False, "Missing or invalid timeout parameter (-m)"

    return True, f"Valid timeout: {timeout_value} seconds"


def validate_resolve_parameter(curl_cmd: List[str], start_index: int = 0) -> Tuple[bool, str]:
    """
    Validate that curl command contains a valid --resolve parameter for IP binding.

    Args:
        curl_cmd: List of curl command arguments
        start_index: Index to start searching from (default: 0)

    Returns:
        Tuple[bool, str]: (is_valid, reason)

    Examples:
        >>> validate_resolve_parameter(["curl", "--resolve", "example.com:443:1.2.3.4", "https://example.com"])
        (True, "Valid resolve parameter")
    """
    resolve_found = False

    for i in range(start_index, len(curl_cmd)):
        arg = curl_cmd[i]
        if arg == "--resolve" and i + 1 < len(curl_cmd):
            resolve_param = curl_cmd[i + 1]
            if ":" in resolve_param and resolve_param.count(":") >= 2:
                resolve_found = True
                break

    if not resolve_found:
        return False, "Missing or invalid --resolve parameter for IP binding"

    return True, "Valid resolve parameter"


def validate_http2_flag(curl_cmd: List[str]) -> Tuple[bool, str]:
    """
    Validate that curl command contains --http2 flag.

    Args:
        curl_cmd: List of curl command arguments

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    if "--http2" not in curl_cmd:
        return False, "Missing --http2 flag for proper ClientHello generation"

    return True, "HTTP/2 flag present"


def validate_url_parameter(curl_cmd: List[str]) -> Tuple[bool, str]:
    """
    Validate that curl command has a valid URL as the last parameter.

    Args:
        curl_cmd: List of curl command arguments

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    if not curl_cmd:
        return False, "Empty curl command"

    last_arg = str(curl_cmd[-1])
    if not last_arg.lower().startswith("http"):
        return False, f"Invalid or missing URL: {last_arg}"

    return True, "Valid URL parameter"


def validate_curl_executable(curl_cmd: List[str]) -> Tuple[bool, str]:
    """
    Validate that the first argument is a valid curl executable.

    Args:
        curl_cmd: List of curl command arguments

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    if not curl_cmd:
        return False, "Empty curl command"

    if not curl_cmd[0] or "curl" not in str(curl_cmd[0]).lower():
        return False, f"Invalid curl executable: {curl_cmd[0]}"

    return True, "Valid curl executable"
