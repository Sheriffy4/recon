"""
Parameter utilities for protocol mimicry attacks.

Provides helper functions for parameter parsing and coercion.
"""

from typing import Any


def coerce_bool(value: Any, default: bool = False) -> bool:
    """
    Coerce a value to boolean with flexible type handling.

    Handles None, bool, int, float, and string types.
    String values like "1", "true", "yes", "y", "on" are considered True.

    Args:
        value: Value to coerce to boolean
        default: Default value if value is None

    Returns:
        Boolean representation of the value
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        return v in ("1", "true", "yes", "y", "on")
    return bool(value)
