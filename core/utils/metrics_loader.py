"""
Shared metrics loader utility.

Provides safe import of metrics collector with fallback handling.
"""

from __future__ import annotations


def get_metrics_availability():
    """
    Check if metrics collection is available.

    Returns:
        tuple: (METRICS_AVAILABLE: bool, get_metrics_collector: callable or None)
    """
    try:
        from ..metrics.attack_parity_metrics import get_metrics_collector

        return True, get_metrics_collector
    except ImportError:
        return False, None


# Module-level exports for backward compatibility
METRICS_AVAILABLE, _get_metrics_collector = get_metrics_availability()


def get_metrics_collector():
    """Get metrics collector if available, otherwise raise ImportError."""
    if _get_metrics_collector is None:
        raise ImportError("Metrics collector not available")
    return _get_metrics_collector()
