"""
Helper functions for report generation.

This module contains common helper functions used across report generation
to eliminate code duplication.
"""

from typing import List, Dict, Any, Callable


def group_by_category(items: List[Any], category_attr: str = "category") -> Dict[str, List[Any]]:
    """
    Group items by category attribute.

    Args:
        items: List of items to group
        category_attr: Attribute name to group by (default: "category")

    Returns:
        Dictionary mapping category values to lists of items
    """
    groups = {}
    for item in items:
        if hasattr(item, category_attr):
            category = getattr(item, category_attr)
            # Handle enum values
            if hasattr(category, "value"):
                category = category.value
        else:
            category = "unknown"

        if category not in groups:
            groups[category] = []
        groups[category].append(item)

    return groups


def add_action_if_issues(
    actions: List[str],
    items: List[Any],
    filter_func: Callable[[Any], bool],
    action_text: str,
) -> None:
    """
    Add action to list if filtered items exist.

    Args:
        actions: List to append action to
        items: Items to filter
        filter_func: Function to filter items
        action_text: Text to add if items match filter
    """
    filtered = [item for item in items if filter_func(item)]
    if filtered:
        actions.append(action_text)


def format_percentage(value: float, decimals: int = 1) -> str:
    """
    Format a float as percentage string.

    Args:
        value: Float value between 0 and 1
        decimals: Number of decimal places

    Returns:
        Formatted percentage string (e.g., "75.5%")
    """
    return f"{value * 100:.{decimals}f}%"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}min"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def truncate_list(items: List[Any], max_items: int = 5) -> List[Any]:
    """
    Truncate list to maximum number of items.

    Args:
        items: List to truncate
        max_items: Maximum number of items to keep

    Returns:
        Truncated list
    """
    return items[:max_items]


def safe_mean(values: List[float], default: float = 0.0) -> float:
    """
    Calculate mean of values, returning default if empty.

    Args:
        values: List of numeric values
        default: Default value if list is empty

    Returns:
        Mean value or default
    """
    if not values:
        return default
    return sum(values) / len(values)
