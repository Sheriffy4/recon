"""
Session metrics tracking for engine sessions.

This module provides session metrics functionality
extracted from EngineSessionManager to maintain single responsibility.

Feature: unified-engine-refactoring
Requirements: 4.1
"""

import time
from typing import Dict, Any, Set
from dataclasses import dataclass


@dataclass
class SessionMetrics:
    """
    Metrics for engine session management.

    Requirement 4.1: Proper engine lifecycle management.
    """

    session_id: str
    created_at: float
    resources_created: int = 0
    resources_cleaned: int = 0
    cleanup_failures: int = 0
    concurrent_operations: int = 0
    max_concurrent_operations: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "resources_created": self.resources_created,
            "resources_cleaned": self.resources_cleaned,
            "cleanup_failures": self.cleanup_failures,
            "concurrent_operations": self.concurrent_operations,
            "max_concurrent_operations": self.max_concurrent_operations,
            "uptime_seconds": time.time() - self.created_at,
        }


class OperationTracker:
    """
    Tracks concurrent operations for session management.

    This class provides operation tracking functionality to prevent
    resource conflicts and race conditions.
    """

    def __init__(self, session_id: str):
        """
        Initialize operation tracker.

        Args:
            session_id: Session identifier
        """
        self.session_id = session_id
        self._active_operations: Set[str] = set()
        self._metrics = SessionMetrics(session_id=session_id, created_at=time.time())

    def start_operation(self, operation_id: str) -> None:
        """
        Mark start of concurrent operation.

        Args:
            operation_id: Unique operation identifier
        """
        self._active_operations.add(operation_id)
        self._metrics.concurrent_operations = len(self._active_operations)

        if self._metrics.concurrent_operations > self._metrics.max_concurrent_operations:
            self._metrics.max_concurrent_operations = self._metrics.concurrent_operations

    def end_operation(self, operation_id: str) -> None:
        """
        Mark end of concurrent operation.

        Args:
            operation_id: Operation identifier
        """
        self._active_operations.discard(operation_id)
        self._metrics.concurrent_operations = len(self._active_operations)

    def get_active_operations(self) -> Set[str]:
        """Get set of active operation IDs."""
        return self._active_operations.copy()

    def has_active_operations(self) -> bool:
        """Check if there are any active operations."""
        return len(self._active_operations) > 0

    def wait_for_operations_to_complete(self, timeout: float = 30.0) -> bool:
        """
        Wait for all active operations to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if all operations completed within timeout
        """
        start_time = time.time()

        while self.has_active_operations():
            if timeout and (time.time() - start_time) > timeout:
                return False
            time.sleep(0.1)

        return True

    def update_resource_metrics(
        self, created: int = 0, cleaned: int = 0, failures: int = 0
    ) -> None:
        """
        Update resource-related metrics.

        Args:
            created: Number of resources created
            cleaned: Number of resources cleaned
            failures: Number of cleanup failures
        """
        self._metrics.resources_created += created
        self._metrics.resources_cleaned += cleaned
        self._metrics.cleanup_failures += failures

    def get_metrics(self) -> SessionMetrics:
        """Get current session metrics."""
        return self._metrics

    def get_status(self) -> Dict[str, Any]:
        """Get operation tracker status."""
        return {
            "session_id": self.session_id,
            "active_operations": len(self._active_operations),
            "operation_ids": list(self._active_operations),
            "metrics": self._metrics.to_dict(),
        }
