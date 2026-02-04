"""
Field Utilities
Helper functions for working with nested data structures.
"""

from typing import Any, Dict


def get_nested_field_value(data: Dict[str, Any], field_path: str) -> Any:
    """
    Get value from nested dictionary using dot notation.

    Args:
        data: Dictionary to search in
        field_path: Field path like 'tcp_analysis.fragmentation_handling'

    Returns:
        Field value or None if not found
    """
    keys = field_path.split(".")
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None

    return current
