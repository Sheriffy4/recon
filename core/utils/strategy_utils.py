from __future__ import annotations

# Файл: core/utils/strategy_utils.py
"""
Strategy utility functions.

This module provides reusable utility functions for strategy processing,
including deduplication and normalization.
"""

from typing import List, TypeVar, Iterable, Callable, Optional, Hashable

T = TypeVar("T")


def deduplicate_strategies(
    strategies: Iterable[T],
    key: Optional[Callable[[T], Hashable]] = None,
    preserve_order: bool = True,
) -> List[T]:
    """
    Remove duplicate strategies while optionally preserving order.

    This is a common pattern used throughout the codebase for deduplicating
    lists of strategies, attacks, recommendations, etc.

    Args:
        strategies: Iterable of items to deduplicate
        key: Optional function to extract comparison key from each item.
             If None, items are compared directly.
        preserve_order: If True, preserve the order of first occurrence.
                       If False, order is not guaranteed (faster for large lists).

    Returns:
        List of unique items

    Examples:
        >>> # Simple deduplication
        >>> deduplicate_strategies(['fake', 'split', 'fake', 'disorder'])
        ['fake', 'split', 'disorder']

        >>> # Deduplication with custom key
        >>> strategies = [{'type': 'fake'}, {'type': 'split'}, {'type': 'fake'}]
        >>> deduplicate_strategies(strategies, key=lambda s: s['type'])
        [{'type': 'fake'}, {'type': 'split'}]

        >>> # Deduplication without order preservation (faster)
        >>> deduplicate_strategies(['a', 'b', 'a', 'c'], preserve_order=False)
        ['a', 'b', 'c']  # Order may vary
    """
    if preserve_order:
        # Preserve order of first occurrence
        seen = set()
        unique = []

        for item in strategies:
            # Extract comparison key
            comparison_key = key(item) if key else item

            # Check if we've seen this key before
            if comparison_key not in seen:
                seen.add(comparison_key)
                unique.append(item)

        return unique
    else:
        # Faster but doesn't preserve order
        if key:
            # Use dict to deduplicate while keeping original items.
            # If key is unhashable, fall back to equality-based tracking.
            seen_dict = {}
            seen_keys = []
            unique = []
            for item in strategies:
                comparison_key = key(item)
                try:
                    if comparison_key not in seen_dict:
                        seen_dict[comparison_key] = item
                except TypeError:
                    # Unhashable key (e.g. dict/list) -> fallback to O(n^2) equality check
                    if any(comparison_key == k for k in seen_keys):
                        continue
                    seen_keys.append(comparison_key)
                    unique.append(item)
            return list(seen_dict.values()) if seen_dict else unique
        else:
            # Simple set conversion; fallback for unhashable items
            try:
                return list(set(strategies))
            except TypeError:
                unique = []
                for item in strategies:
                    if item not in unique:
                        unique.append(item)
                return unique


def deduplicate_preserve_order(items: Iterable[T]) -> List[T]:
    """
    Remove duplicates while preserving order (convenience function).

    This is an alias for deduplicate_strategies with preserve_order=True.
    Commonly used pattern in the codebase.

    Args:
        items: Iterable of items to deduplicate

    Returns:
        List of unique items in original order

    Examples:
        >>> deduplicate_preserve_order(['a', 'b', 'a', 'c'])
        ['a', 'b', 'c']
    """
    return deduplicate_strategies(items, preserve_order=True)


def deduplicate_by_key(items: Iterable[T], key: Callable[[T], Hashable]) -> List[T]:
    """
    Remove duplicates based on a key function while preserving order.

    This is useful when items are complex objects and you want to deduplicate
    based on a specific attribute or computed value.

    Args:
        items: Iterable of items to deduplicate
        key: Function to extract comparison key from each item

    Returns:
        List of unique items based on key

    Examples:
        >>> strategies = [
        ...     {'type': 'fake', 'ttl': 5},
        ...     {'type': 'split', 'pos': 2},
        ...     {'type': 'fake', 'ttl': 10}
        ... ]
        >>> deduplicate_by_key(strategies, key=lambda s: s['type'])
        [{'type': 'fake', 'ttl': 5}, {'type': 'split', 'pos': 2}]
    """
    return deduplicate_strategies(items, key=key, preserve_order=True)


def deduplicate_attacks(attacks: Iterable[str]) -> List[str]:
    """
    Remove duplicate attack names while preserving order.

    Convenience function specifically for attack name deduplication.

    Args:
        attacks: Iterable of attack names

    Returns:
        List of unique attack names

    Examples:
        >>> deduplicate_attacks(['fake', 'split', 'fake', 'disorder'])
        ['fake', 'split', 'disorder']
    """
    return deduplicate_preserve_order(attacks)


def deduplicate_recommendations(recommendations: Iterable[str]) -> List[str]:
    """
    Remove duplicate recommendations while preserving order.

    Convenience function specifically for recommendation deduplication.

    Args:
        recommendations: Iterable of recommendation strings

    Returns:
        List of unique recommendations

    Examples:
        >>> deduplicate_recommendations(['use_fake', 'use_split', 'use_fake'])
        ['use_fake', 'use_split']
    """
    return deduplicate_preserve_order(recommendations)


def deduplicate_with_limit(
    items: Iterable[T], limit: int, key: Optional[Callable[[T], Hashable]] = None
) -> List[T]:
    """
    Remove duplicates and limit the result to a maximum number of items.

    This is useful when you want to deduplicate and then take only the first N items.

    Args:
        items: Iterable of items to deduplicate
        limit: Maximum number of items to return
        key: Optional function to extract comparison key

    Returns:
        List of unique items, limited to 'limit' items

    Examples:
        >>> deduplicate_with_limit(['a', 'b', 'a', 'c', 'd'], limit=3)
        ['a', 'b', 'c']
    """
    unique = deduplicate_strategies(items, key=key, preserve_order=True)
    return unique[:limit]
