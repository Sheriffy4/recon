"""
Dataclass serialization utilities.

This module provides utilities for serializing dataclass objects to dictionaries
with consistent handling of nested structures and type conversions.
"""

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Callable, Optional


_PRIMITIVE_TYPES = (str, int, float, bool, type(None))


def _convert_for_json(value: Any, str_converter: Callable[[Any], str]) -> Any:
    """
    Recursively convert values so that they become JSON-serializable.
    Uses str_converter for unknown/non-serializable leaf values.
    """
    if isinstance(value, _PRIMITIVE_TYPES):
        return value

    if is_dataclass(value):
        return _convert_for_json(asdict(value), str_converter)

    if isinstance(value, dict):
        return {k: _convert_for_json(v, str_converter) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_convert_for_json(v, str_converter) for v in value]

    # Fallback: stringify unknown objects
    return str_converter(value)


def dataclass_to_dict(
    obj: Any, exclude_none: bool = False, str_converter: Optional[Callable[[Any], str]] = None
) -> Dict[str, Any]:
    """
    Convert a dataclass object to a dictionary for JSON serialization.

    Args:
        obj: Dataclass object to convert
        exclude_none: If True, exclude fields with None values
        str_converter: Optional function to convert non-serializable values to strings

    Returns:
        Dictionary representation of the dataclass

    Raises:
        TypeError: If obj is not a dataclass instance

    Note:
        This is a wrapper around dataclasses.asdict() with additional options
        for filtering and type conversion.
    """
    if not is_dataclass(obj):
        raise TypeError(f"Expected dataclass instance, got {type(obj)}")

    result = asdict(obj)

    if exclude_none:
        result = {k: v for k, v in result.items() if v is not None}

    if str_converter:
        # Previously conversion was shallow; make it recursive for robustness.
        result = _convert_for_json(result, str_converter)

    return result


def dataclass_to_dict_with_str_values(
    obj: Any, fields_to_stringify: Optional[list] = None
) -> Dict[str, Any]:
    """
    Convert a dataclass to dictionary with specific fields converted to strings.

    Args:
        obj: Dataclass object to convert
        fields_to_stringify: List of field names to convert to strings (default: all non-primitive types)

    Returns:
        Dictionary with specified fields converted to strings

    Example:
        >>> @dataclass
        ... class Example:
        ...     name: str
        ...     value: int
        ...     data: dict
        >>> obj = Example("test", 42, {"key": "value"})
        >>> dataclass_to_dict_with_str_values(obj, ["data"])
        {'name': 'test', 'value': 42, 'data': "{'key': 'value'}"}
    """
    if not is_dataclass(obj):
        raise TypeError(f"Expected dataclass instance, got {type(obj)}")

    result = asdict(obj)

    if fields_to_stringify:
        for field in fields_to_stringify:
            if field in result:
                result[field] = str(result[field])
    else:
        # Convert all non-primitive types to strings
        for key, value in result.items():
            if not isinstance(value, (str, int, float, bool, type(None), list, dict)):
                result[key] = str(value)

    return result
