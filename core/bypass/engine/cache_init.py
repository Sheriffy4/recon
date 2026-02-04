"""
Cache and Lock Initialization Utilities

This module provides utilities for initializing caches, locks, and other
synchronization primitives used by the bypass engine.

Extracted from base_engine.py to reduce god class complexity and improve testability.
"""

import threading
from typing import Dict, Any


def initialize_caches_and_locks(
    max_injections: int = 12,
    flow_ttl_sec: float = 3.0,
    flow_timeout: float = 15.0,
    autottl_cache_ttl: float = 300.0,
) -> Dict[str, Any]:
    """
    Initialize caches, locks, and synchronization primitives.

    This function creates all the caches, locks, semaphores, and other
    synchronization primitives needed by the bypass engine.

    Args:
        max_injections: Maximum concurrent packet injections (default: 12)
        flow_ttl_sec: Flow time-to-live in seconds (default: 3.0)
        flow_timeout: Flow timeout in seconds (default: 15.0)
        autottl_cache_ttl: Auto-TTL cache TTL in seconds (default: 300.0)

    Returns:
        Dictionary containing all initialized components:
        - lock: Main threading lock
        - tlock: Telemetry lock
        - inject_sema: Injection semaphore
        - flow_table: Flow tracking table
        - active_flows: Set of active flows
        - inbound_events: Inbound event dictionary
        - inbound_results: Inbound results dictionary
        - processed_flows: Processed flows dictionary
        - autottl_cache: Auto-TTL cache
        - split_pos_cache: Split position cache
        - flow_ttl_sec: Flow TTL value
        - flow_timeout: Flow timeout value
        - autottl_cache_ttl: Auto-TTL cache TTL value

    Examples:
        >>> caches = initialize_caches_and_locks()
        >>> print(f"Lock: {caches['lock']}")
        >>> print(f"Active flows: {len(caches['active_flows'])}")
    """
    return {
        # Threading primitives
        "lock": threading.Lock(),
        "tlock": threading.Lock(),
        "inject_sema": threading.Semaphore(max_injections),
        # Flow tracking
        "flow_table": {},
        "active_flows": set(),
        "inbound_events": {},
        "inbound_results": {},
        "processed_flows": {},
        # Caches
        "autottl_cache": {},
        "split_pos_cache": {},
        # Configuration values
        "flow_ttl_sec": flow_ttl_sec,
        "flow_timeout": flow_timeout,
        "autottl_cache_ttl": autottl_cache_ttl,
    }
