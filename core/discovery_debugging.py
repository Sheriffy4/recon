"""
Discovery debugging utilities for the DPI bypass system.

This module provides debugging capabilities for the discovery system,
including debug levels, debugging context, and debug output management.
"""

import logging
import time
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime


class DebugLevel(Enum):
    """Debug levels for discovery system."""

    NONE = "none"
    BASIC = "basic"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"
    TRACE = "trace"


@dataclass
class DebugContext:
    """Debug context for tracking discovery operations."""

    session_id: str
    domain: str
    operation: str
    start_time: float = field(default_factory=time.time)
    debug_data: Dict[str, Any] = field(default_factory=dict)

    def add_debug_info(self, key: str, value: Any) -> None:
        """Add debug information to the context."""
        self.debug_data[key] = value

    def get_elapsed_time(self) -> float:
        """Get elapsed time since context creation."""
        return time.time() - self.start_time


class DiscoveryDebugger:
    """
    Debugger for the discovery system.

    Provides debugging capabilities including debug output, context tracking,
    and performance monitoring for discovery operations.
    """

    def __init__(self, debug_level: DebugLevel = DebugLevel.INFO):
        """Initialize the discovery debugger."""
        self.debug_level = debug_level
        self.logger = logging.getLogger(__name__)
        self.contexts: Dict[str, DebugContext] = {}
        self.debug_handlers: List[Callable[[str, DebugLevel, Dict[str, Any]], None]] = []

    def set_debug_level(self, level: DebugLevel) -> None:
        """Set the debug level."""
        self.debug_level = level

    def add_debug_handler(self, handler: Callable[[str, DebugLevel, Dict[str, Any]], None]) -> None:
        """Add a debug message handler."""
        self.debug_handlers.append(handler)

    def create_context(self, session_id: str, domain: str, operation: str) -> DebugContext:
        """Create a new debug context."""
        context = DebugContext(session_id, domain, operation)
        self.contexts[session_id] = context

        self._debug_message(
            f"Created debug context for {operation} on {domain}",
            DebugLevel.DEBUG,
            {"session_id": session_id, "domain": domain, "operation": operation},
        )

        return context

    def get_context(self, session_id: str) -> Optional[DebugContext]:
        """Get debug context by session ID."""
        return self.contexts.get(session_id)

    def remove_context(self, session_id: str) -> None:
        """Remove debug context."""
        if session_id in self.contexts:
            context = self.contexts[session_id]
            self._debug_message(
                f"Removing debug context for {context.operation} on {context.domain} "
                f"(elapsed: {context.get_elapsed_time():.2f}s)",
                DebugLevel.DEBUG,
                {"session_id": session_id, "elapsed_time": context.get_elapsed_time()},
            )
            del self.contexts[session_id]

    def debug(
        self,
        message: str,
        level: DebugLevel = DebugLevel.DEBUG,
        context_id: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Log a debug message."""
        debug_data = kwargs.copy()

        if context_id and context_id in self.contexts:
            context = self.contexts[context_id]
            debug_data.update(
                {
                    "session_id": context_id,
                    "domain": context.domain,
                    "operation": context.operation,
                    "elapsed_time": context.get_elapsed_time(),
                }
            )

        self._debug_message(message, level, debug_data)

    def debug_strategy_test(
        self, session_id: str, strategy_name: str, result: bool, execution_time: float, **kwargs
    ) -> None:
        """Debug a strategy test result."""
        self.debug(
            f"Strategy test: {strategy_name} -> {'SUCCESS' if result else 'FAILED'} "
            f"({execution_time:.2f}s)",
            DebugLevel.INFO,
            session_id,
            strategy_name=strategy_name,
            result=result,
            execution_time=execution_time,
            **kwargs,
        )

    def debug_fingerprint_update(
        self, session_id: str, domain: str, fingerprint_data: Dict[str, Any]
    ) -> None:
        """Debug fingerprint update."""
        self.debug(
            f"Fingerprint updated for {domain}",
            DebugLevel.INFO,
            session_id,
            fingerprint_data=fingerprint_data,
        )

    def debug_cache_operation(self, operation: str, key: str, hit: bool) -> None:
        """Debug cache operation."""
        self.debug(
            f"Cache {operation}: {key} -> {'HIT' if hit else 'MISS'}",
            DebugLevel.DEBUG,
            cache_operation=operation,
            cache_key=key,
            cache_hit=hit,
        )

    def get_debug_summary(self) -> Dict[str, Any]:
        """Get debug summary for all active contexts."""
        summary = {
            "active_contexts": len(self.contexts),
            "debug_level": self.debug_level.value,
            "contexts": {},
        }

        for session_id, context in self.contexts.items():
            summary["contexts"][session_id] = {
                "domain": context.domain,
                "operation": context.operation,
                "elapsed_time": context.get_elapsed_time(),
                "debug_data_keys": list(context.debug_data.keys()),
            }

        return summary

    def _debug_message(self, message: str, level: DebugLevel, debug_data: Dict[str, Any]) -> None:
        """Internal method to handle debug messages."""
        # Check if we should output this debug level
        level_priority = {
            DebugLevel.NONE: 0,
            DebugLevel.BASIC: 1,
            DebugLevel.ERROR: 2,
            DebugLevel.WARNING: 3,
            DebugLevel.INFO: 4,
            DebugLevel.DEBUG: 5,
            DebugLevel.TRACE: 6,
        }

        if level_priority[level] > level_priority[self.debug_level]:
            return

        # Log to standard logger
        log_level = {
            DebugLevel.BASIC: logging.INFO,
            DebugLevel.ERROR: logging.ERROR,
            DebugLevel.WARNING: logging.WARNING,
            DebugLevel.INFO: logging.INFO,
            DebugLevel.DEBUG: logging.DEBUG,
            DebugLevel.TRACE: logging.DEBUG,
        }.get(level, logging.DEBUG)

        self.logger.log(log_level, f"[DISCOVERY] {message}")

        # Call debug handlers
        for handler in self.debug_handlers:
            try:
                handler(message, level, debug_data)
            except Exception as e:
                self.logger.error(f"Debug handler error: {e}")

    def capture_debug_snapshot(
        self, session_id: str, target_domain: str, operation: str = "snapshot", **kwargs
    ) -> Dict[str, Any]:
        """
        Capture a debug snapshot of the current state.

        Args:
            session_id: Session identifier
            target_domain: Target domain being processed
            operation: Operation being performed
            **kwargs: Additional debug data

        Returns:
            Dictionary containing debug snapshot data
        """
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
            "target_domain": target_domain,
            "operation": operation,
            "debug_level": self.debug_level.value,
            "active_contexts": len(self.contexts),
            **kwargs,
        }

        # Add context data if available
        if session_id in self.contexts:
            context = self.contexts[session_id]
            snapshot.update(
                {
                    "context_domain": context.domain,
                    "context_operation": context.operation,
                    "elapsed_time": context.get_elapsed_time(),
                    "debug_data": context.debug_data.copy(),
                }
            )

        self.debug(
            f"Debug snapshot captured for {operation} on {target_domain}",
            DebugLevel.DEBUG,
            session_id,
            snapshot_keys=list(snapshot.keys()),
        )

        return snapshot

    def record_error(
        self,
        session_id: str,
        target_domain: str,
        error_type: str,
        error_message: str,
        component: str,
        exception: Optional[Exception] = None,
    ) -> None:
        """
        Record an error for debugging purposes.

        Args:
            session_id: Session identifier
            target_domain: Target domain being processed
            error_type: Type of error (e.g., "session_start_error")
            error_message: Error message
            component: Component where error occurred
            exception: Optional exception object
        """
        error_data = {
            "session_id": session_id,
            "target_domain": target_domain,
            "error_type": error_type,
            "error_message": error_message,
            "component": component,
            "timestamp": datetime.now().isoformat(),
        }

        if exception:
            error_data.update(
                {"exception_type": type(exception).__name__, "exception_str": str(exception)}
            )

        # Add to context if available
        if session_id in self.contexts:
            context = self.contexts[session_id]
            context.add_debug_info(f"error_{error_type}", error_data)

        self.debug(
            f"Error recorded: {error_type} in {component} - {error_message}",
            DebugLevel.ERROR,
            session_id,
            **error_data,
        )

        # Log as error to standard logger
        self.logger.error(f"[DISCOVERY ERROR] {component}: {error_message}")
        if exception:
            self.logger.error(f"[DISCOVERY ERROR] Exception: {exception}")


# Global debugger instance
_global_debugger: Optional[DiscoveryDebugger] = None


def get_discovery_debugger() -> DiscoveryDebugger:
    """Get the global discovery debugger instance."""
    global _global_debugger
    if _global_debugger is None:
        _global_debugger = DiscoveryDebugger()
    return _global_debugger


def set_discovery_debug_level(level: DebugLevel) -> None:
    """Set the global discovery debug level."""
    debugger = get_discovery_debugger()
    debugger.set_debug_level(level)


def debug_discovery(message: str, level: DebugLevel = DebugLevel.DEBUG, **kwargs) -> None:
    """Convenience function for discovery debugging."""
    debugger = get_discovery_debugger()
    debugger.debug(message, level, **kwargs)
