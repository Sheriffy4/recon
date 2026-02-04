# Файл: core/unified/validators.py
"""
Unified validator predicates.

This module provides reusable predicate functions for common validation patterns
across different components, reducing code duplication and improving consistency.
"""

from typing import Any, Optional


def predicate_is_pcap_analysis_available(obj: Any, attr_name: str = "_pcap_analyzer") -> bool:
    """
    Check if PCAP analysis capabilities are available.

    This is a common pattern used to check if an object has PCAP analysis
    capabilities by checking if a specific attribute is not None.

    Args:
        obj: Object to check
        attr_name: Name of the attribute to check (default: '_pcap_analyzer')

    Returns:
        bool: True if PCAP analysis is available, False otherwise

    Examples:
        >>> class Analyzer:
        ...     def __init__(self):
        ...         self._pcap_analyzer = SomePcapAnalyzer()
        >>> analyzer = Analyzer()
        >>> predicate_is_pcap_analysis_available(analyzer)
        True

        >>> class NoAnalyzer:
        ...     def __init__(self):
        ...         self._pcap_analyzer = None
        >>> no_analyzer = NoAnalyzer()
        >>> predicate_is_pcap_analysis_available(no_analyzer)
        False
    """
    return hasattr(obj, attr_name) and getattr(obj, attr_name) is not None


def predicate_is_discovery_mode_active(
    engine: Any, method_name: str = "is_discovery_mode_active", fallback: bool = False
) -> bool:
    """
    Check if discovery mode is active in an engine.

    This predicate delegates to the underlying engine's discovery mode check,
    with a fallback value if the method is not available.

    Args:
        engine: Engine object to check
        method_name: Name of the method to call (default: 'is_discovery_mode_active')
        fallback: Value to return if method is not available (default: False)

    Returns:
        bool: True if discovery mode is active, fallback value otherwise

    Examples:
        >>> class Engine:
        ...     def is_discovery_mode_active(self):
        ...         return True
        >>> engine = Engine()
        >>> predicate_is_discovery_mode_active(engine)
        True

        >>> class NoDiscoveryEngine:
        ...     pass
        >>> no_discovery = NoDiscoveryEngine()
        >>> predicate_is_discovery_mode_active(no_discovery, fallback=False)
        False
    """
    if hasattr(engine, method_name):
        method = getattr(engine, method_name)
        if callable(method):
            return method()
    return fallback


def predicate_is_stop_requested(obj: Any, flag_attr: str = "_running", invert: bool = True) -> bool:
    """
    Check if a stop has been requested (or if object is running).

    This predicate checks a boolean flag attribute to determine if an object
    is running or if a stop has been requested.

    Args:
        obj: Object to check
        flag_attr: Name of the flag attribute (default: '_running')
        invert: If True, return NOT flag_value (for stop_requested semantics)
                If False, return flag_value (for is_running semantics)

    Returns:
        bool: True if stop requested (or running, depending on invert)

    Examples:
        >>> class Service:
        ...     def __init__(self):
        ...         self._running = True
        >>> service = Service()
        >>> predicate_is_stop_requested(service, invert=False)  # is_running
        True
        >>> predicate_is_stop_requested(service, invert=True)   # is_stop_requested
        False

        >>> service._running = False
        >>> predicate_is_stop_requested(service, invert=False)  # is_running
        False
        >>> predicate_is_stop_requested(service, invert=True)   # is_stop_requested
        True
    """
    if hasattr(obj, flag_attr):
        flag_value = getattr(obj, flag_attr)
        return not flag_value if invert else flag_value
    return False if not invert else True


def predicate_is_running(obj: Any, flag_attr: str = "_running") -> bool:
    """
    Check if an object is currently running.

    Convenience wrapper for predicate_is_stop_requested with invert=False.

    Args:
        obj: Object to check
        flag_attr: Name of the flag attribute (default: '_running')

    Returns:
        bool: True if running, False otherwise

    Examples:
        >>> class Service:
        ...     def __init__(self):
        ...         self._running = True
        >>> service = Service()
        >>> predicate_is_running(service)
        True
    """
    return predicate_is_stop_requested(obj, flag_attr, invert=False)


def predicate_has_attribute(obj: Any, attr_name: str, check_not_none: bool = False) -> bool:
    """
    Check if an object has a specific attribute.

    Args:
        obj: Object to check
        attr_name: Name of the attribute
        check_not_none: If True, also check that attribute is not None

    Returns:
        bool: True if attribute exists (and is not None if check_not_none)

    Examples:
        >>> class MyClass:
        ...     def __init__(self):
        ...         self.value = 42
        ...         self.none_value = None
        >>> obj = MyClass()
        >>> predicate_has_attribute(obj, 'value')
        True
        >>> predicate_has_attribute(obj, 'value', check_not_none=True)
        True
        >>> predicate_has_attribute(obj, 'none_value', check_not_none=True)
        False
        >>> predicate_has_attribute(obj, 'missing')
        False
    """
    if not hasattr(obj, attr_name):
        return False

    if check_not_none:
        return getattr(obj, attr_name) is not None

    return True


def predicate_is_available(
    obj: Any, attr_name: Optional[str] = None, check_not_none: bool = True
) -> bool:
    """
    Generic availability check predicate.

    Checks if an object or its attribute is available (not None).

    Args:
        obj: Object to check
        attr_name: Optional attribute name to check. If None, checks obj itself.
        check_not_none: If True, check that value is not None

    Returns:
        bool: True if available, False otherwise

    Examples:
        >>> class Engine:
        ...     def __init__(self):
        ...         self.component = SomeComponent()
        >>> engine = Engine()
        >>> predicate_is_available(engine)  # Check engine itself
        True
        >>> predicate_is_available(engine, 'component')  # Check component
        True
        >>> predicate_is_available(None)
        False
    """
    if attr_name is None:
        # Check object itself
        return obj is not None if check_not_none else True

    # Check attribute
    return predicate_has_attribute(obj, attr_name, check_not_none)


# ============================================================================
# Curl Command Validation
# ============================================================================

import logging
from typing import List, Tuple


class CurlCommandValidator:
    """Validator for curl command construction to ensure consistency.

    This validator ensures that curl commands are properly constructed with
    required parameters for DPI bypass testing, including HTTP/2 support,
    proper IP resolution, and timeout handling.

    Requirements: 5.4
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the validator.

        Args:
            logger: Optional logger instance. If None, creates a new logger.
        """
        self.logger = logger or logging.getLogger(__name__)

    def validate_curl_command(self, curl_cmd: List[str]) -> Tuple[bool, str]:
        """
        Validate curl command construction for consistency and correctness.

        This method performs strict validation requiring all parameters needed
        for proper DPI bypass testing, including the --resolve parameter for
        IP binding.

        Args:
            curl_cmd: List of curl command arguments

        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        from core.validation.curl_validators import (
            validate_curl_executable,
            validate_http2_flag,
            validate_resolve_parameter,
            validate_timeout_parameter,
            validate_url_parameter,
        )

        # Check curl executable
        is_valid, reason = validate_curl_executable(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for required HTTP/2 flag
        is_valid, reason = validate_http2_flag(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for resolve parameter (required for IP binding)
        is_valid, reason = validate_resolve_parameter(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for timeout parameter
        is_valid, reason = validate_timeout_parameter(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for URL at the end
        is_valid, reason = validate_url_parameter(curl_cmd)
        if not is_valid:
            return False, reason

        self.logger.debug("✅ Curl command validation passed")
        return True, "Curl command is valid"

    def validate_curl_command_any(self, curl_cmd: List[str]) -> Tuple[bool, str]:
        """
        Less strict validation that does NOT require --resolve.

        This method is intended for direct URL curl calls (fallback paths)
        where IP binding via --resolve is not required.

        Args:
            curl_cmd: List of curl command arguments

        Returns:
            Tuple[bool, str]: (is_valid, reason)
        """
        from core.validation.curl_validators import (
            validate_curl_executable,
            validate_http2_flag,
            validate_timeout_parameter,
            validate_url_parameter,
        )

        # Check curl executable
        is_valid, reason = validate_curl_executable(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for HTTP/2 flag
        is_valid, reason = validate_http2_flag(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for timeout parameter
        is_valid, reason = validate_timeout_parameter(curl_cmd)
        if not is_valid:
            return False, reason

        # Check for URL at the end
        is_valid, reason = validate_url_parameter(curl_cmd)
        if not is_valid:
            return False, reason

        return True, "Curl command is valid (non-resolve)"


# ============================================================================
# Strategy Normalization
# ============================================================================

from typing import Dict, Any


def normalize_strategy_dict(strategy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize strategy dictionary to ensure consistent field names and types.

    This function handles various strategy formats and normalizes them to a
    consistent structure expected by the bypass engine. It performs field
    name mapping, type coercion, and default value injection.

    Args:
        strategy: Strategy dictionary to normalize

    Returns:
        Dict[str, Any]: Normalized strategy dictionary

    Examples:
        >>> strategy = {"type": "http", "split": "5"}
        >>> normalized = normalize_strategy_dict(strategy)
        >>> normalized["split_position"]
        5

    Note:
        This function is additive and does not remove existing fields.
        It only adds missing fields and normalizes known field names.
    """
    if not isinstance(strategy, dict):
        return strategy

    normalized = dict(strategy)

    # Normalize split_position field (common alias: split, splitPos)
    if "split" in normalized and "split_position" not in normalized:
        try:
            normalized["split_position"] = int(normalized["split"])
        except (ValueError, TypeError):
            pass

    if "splitPos" in normalized and "split_position" not in normalized:
        try:
            normalized["split_position"] = int(normalized["splitPos"])
        except (ValueError, TypeError):
            pass

    # Normalize attack type field
    if "type" in normalized and "attack_type" not in normalized:
        normalized["attack_type"] = normalized["type"]

    # Normalize boolean fields
    for bool_field in ["auto_ttl", "reverse_frag", "disorder"]:
        if bool_field in normalized:
            val = normalized[bool_field]
            if isinstance(val, str):
                normalized[bool_field] = val.lower() in ("true", "1", "yes", "on")
            elif not isinstance(val, bool):
                normalized[bool_field] = bool(val)

    # Normalize numeric fields
    for num_field in ["ttl", "fake_ttl", "window_size", "mss"]:
        if num_field in normalized and not isinstance(normalized[num_field], (int, float)):
            try:
                normalized[num_field] = int(normalized[num_field])
            except (ValueError, TypeError):
                pass

    return normalized
