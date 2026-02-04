#!/usr/bin/env python3
"""
Generic threshold-based level classification utility.

This module provides a reusable pattern for classifying numeric scores
into discrete levels based on threshold ranges.
"""

from typing import List, Tuple, TypeVar, Generic
from enum import Enum

T = TypeVar("T", bound=Enum)


def classify_by_thresholds(
    score: float,
    thresholds: List[Tuple[float, T]],
    default: T,
    descending: bool = True,
) -> T:
    """
    Classify a numeric score into a level based on threshold ranges.

    Args:
        score: The numeric score to classify
        thresholds: List of (threshold, level) tuples, sorted by threshold
        default: Default level if score doesn't match any threshold
        descending: If True, check thresholds from highest to lowest (default)
                   If False, check from lowest to highest

    Returns:
        The level corresponding to the score

    Example:
        >>> from enum import Enum
        >>> class Level(Enum):
        ...     HIGH = "high"
        ...     MEDIUM = "medium"
        ...     LOW = "low"
        >>> thresholds = [(0.8, Level.HIGH), (0.5, Level.MEDIUM)]
        >>> classify_by_thresholds(0.9, thresholds, Level.LOW)
        <Level.HIGH: 'high'>
        >>> classify_by_thresholds(0.6, thresholds, Level.LOW)
        <Level.MEDIUM: 'medium'>
        >>> classify_by_thresholds(0.3, thresholds, Level.LOW)
        <Level.LOW: 'low'>
    """
    if descending:
        # Check from highest to lowest threshold
        for threshold, level in sorted(thresholds, key=lambda x: x[0], reverse=True):
            if score >= threshold:
                return level
    else:
        # Check from lowest to highest threshold
        for threshold, level in sorted(thresholds, key=lambda x: x[0]):
            if score <= threshold:
                return level

    return default


def create_threshold_classifier(
    thresholds: List[Tuple[float, T]], default: T, descending: bool = True
):
    """
    Create a reusable classifier function with predefined thresholds.

    Args:
        thresholds: List of (threshold, level) tuples
        default: Default level if score doesn't match any threshold
        descending: If True, check thresholds from highest to lowest

    Returns:
        A function that takes a score and returns a level

    Example:
        >>> from enum import Enum
        >>> class Priority(Enum):
        ...     CRITICAL = "critical"
        ...     HIGH = "high"
        ...     NORMAL = "normal"
        >>> classifier = create_threshold_classifier(
        ...     [(0.9, Priority.CRITICAL), (0.7, Priority.HIGH)],
        ...     Priority.NORMAL
        ... )
        >>> classifier(0.95)
        <Priority.CRITICAL: 'critical'>
    """

    def classifier(score: float) -> T:
        return classify_by_thresholds(score, thresholds, default, descending)

    return classifier
