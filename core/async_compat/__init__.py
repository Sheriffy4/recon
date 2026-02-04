"""
Async/Sync Compatibility Layer for UnifiedBypassEngine Refactoring

This module provides comprehensive async/sync compatibility for all operations,
ensuring consistent behavior between synchronous and asynchronous calling contexts.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

from .async_sync_wrapper import (
    AsyncSyncWrapper,
    AsyncCompatibilityMixin,
    run_in_thread_pool,
    handle_nested_event_loop,
    is_async_context,
    async_sync_method,
    ensure_consistent_behavior,
)
from .subprocess_async import (
    AsyncSubprocessManager,
    SubprocessConfig,
    run_subprocess_async,
    run_subprocess_sync,
)
from .event_loop_handler import (
    EventLoopHandler,
    get_or_create_event_loop,
    ensure_event_loop,
    handle_event_loop_policy,
    run_async_from_sync,
)

__all__ = [
    "AsyncSyncWrapper",
    "AsyncCompatibilityMixin",
    "run_in_thread_pool",
    "handle_nested_event_loop",
    "is_async_context",
    "async_sync_method",
    "ensure_consistent_behavior",
    "AsyncSubprocessManager",
    "SubprocessConfig",
    "run_subprocess_async",
    "run_subprocess_sync",
    "EventLoopHandler",
    "get_or_create_event_loop",
    "ensure_event_loop",
    "handle_event_loop_policy",
    "run_async_from_sync",
]
