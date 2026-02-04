"""
EngineSessionManager for proper engine lifecycle management.

This module provides guaranteed resource cleanup with context managers,
thread joining, WinDivert handle management, exception-safe resource cleanup,
and concurrent operation safety.

Feature: unified-engine-refactoring
Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

import threading
import time
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional, List, Callable
from concurrent.futures import ThreadPoolExecutor, Future
import atexit

from core.unified_engine_models import ResourceError
from .resource_handle import ResourceManager
from .session_metrics import OperationTracker, SessionMetrics
from .thread_manager import ThreadManager


class EngineSessionManager:
    """
    Manages engine lifecycle with guaranteed resource cleanup.

    This refactored version uses specialized components to maintain
    single responsibility and stay under 500 lines.

    Requirements:
    - 4.1: Proper engine lifecycle management with guaranteed cleanup
    - 4.2: All threads properly joined and resources released
    - 4.3: Prevent resource conflicts and race conditions
    - 4.4: Exception-safe resource cleanup
    - 4.5: Proper WinDivert handle and thread termination
    """

    _global_sessions: Dict[str, "EngineSessionManager"] = {}
    _global_lock = threading.RLock()
    _cleanup_registered = False

    def __init__(self, session_id: Optional[str] = None):
        """
        Initialize engine session manager.

        Args:
            session_id: Unique session identifier (auto-generated if None)
        """
        # Session identification
        self.session_id = session_id or f"session_{int(time.time() * 1000000)}"

        # Thread-safe management (Requirement 4.3)
        self._lock = threading.RLock()

        # State management
        self._is_active = True
        self._cleanup_started = False
        self._cleanup_completed = False

        # Specialized components for modular architecture
        self.logger = logging.getLogger(f"{__name__}.{self.session_id}")
        self._resource_manager = ResourceManager(self.logger)
        self._operation_tracker = OperationTracker(self.session_id)
        self._thread_manager = ThreadManager(self.session_id, self.logger)

        # WinDivert handle tracking (Requirement 4.5)
        self._windivert_handles: Dict[str, Any] = {}

        # Cleanup callbacks
        self._cleanup_callbacks: List[Callable[[], None]] = []

        # Register global session and cleanup
        self._register_global_session()
        self._register_cleanup()

        self.logger.debug(f"EngineSessionManager initialized: {self.session_id}")

    @classmethod
    def _register_cleanup(cls):
        """Register global cleanup handler."""
        if not cls._cleanup_registered:
            atexit.register(cls._cleanup_all_sessions)
            cls._cleanup_registered = True

    def _register_global_session(self):
        """Register this session globally for cleanup."""
        with self._global_lock:
            self._global_sessions[self.session_id] = self

    def _unregister_global_session(self):
        """Unregister this session from global tracking."""
        with self._global_lock:
            self._global_sessions.pop(self.session_id, None)

    @classmethod
    def _cleanup_all_sessions(cls):
        """Clean up all active sessions (called at exit)."""
        with cls._global_lock:
            sessions = list(cls._global_sessions.values())

        for session in sessions:
            try:
                session.cleanup()
            except Exception as e:
                logging.getLogger(__name__).error(
                    f"Failed to cleanup session {session.session_id}: {e}"
                )

    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        with self._lock:
            return self._is_active and not self._cleanup_completed

    @property
    def resource_count(self) -> int:
        """Get number of active resources."""
        return self._resource_manager.get_resource_count()

    @property
    def metrics(self) -> SessionMetrics:
        """Get session metrics."""
        return self._operation_tracker.get_metrics()

    @property
    def _threads(self) -> Dict[str, Any]:
        """Get threads dictionary for backward compatibility with tests."""
        return self._thread_manager._threads

    @property
    def _active_operations(self) -> set:
        """Get active operations set for backward compatibility with tests."""
        return self._operation_tracker.get_active_operations()

    def register_resource(
        self,
        resource: Any,
        resource_type: str,
        resource_id: Optional[str] = None,
        cleanup_func: Optional[Callable[[], None]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Register a resource for managed cleanup.

        Requirement 4.1: Proper engine lifecycle management with guaranteed cleanup.
        """
        with self._lock:
            if not self._is_active:
                raise ResourceError("Cannot register resource: session is not active")

            # Use resource manager for registration
            resource_id = self._resource_manager.register_resource(
                resource=resource,
                resource_type=resource_type,
                resource_id=resource_id,
                cleanup_func=cleanup_func,
                metadata=metadata,
            )

            # Update metrics
            self._operation_tracker.update_resource_metrics(created=1)

            # Special handling for specific resource types
            if resource_type == "windivert":
                self._windivert_handles[resource_id] = resource
            # Note: threads are handled separately via register_thread method

            return resource_id

    def register_windivert_handle(self, handle: Any, handle_id: Optional[str] = None) -> str:
        """
        Register WinDivert handle for managed cleanup.

        Requirement 4.5: Proper WinDivert handle termination.

        Args:
            handle: WinDivert handle
            handle_id: Unique identifier

        Returns:
            Handle ID for tracking
        """
        return self.register_resource(
            resource=handle,
            resource_type="windivert",
            resource_id=handle_id,
            cleanup_func=lambda: self._cleanup_windivert_handle(handle),
            metadata={"handle_type": "windivert"},
        )

    def register_thread(self, thread: threading.Thread, thread_id: Optional[str] = None) -> str:
        """
        Register thread for managed cleanup.

        Requirement 4.2: All threads properly joined and resources released.
        """
        # Register with thread manager
        thread_id = self._thread_manager.register_thread(thread, thread_id)

        # Also register as a resource for counting and cleanup
        self.register_resource(
            resource=thread,
            resource_type="thread",
            resource_id=thread_id,
            cleanup_func=lambda: self._thread_manager.cleanup_thread(thread),
        )

        return thread_id

    def start_operation(self, operation_id: str) -> None:
        """
        Mark start of concurrent operation.

        Requirement 4.3: Prevent resource conflicts and race conditions.
        """
        self._operation_tracker.start_operation(operation_id)

    def end_operation(self, operation_id: str) -> None:
        """Mark end of concurrent operation."""
        self._operation_tracker.end_operation(operation_id)

    @contextmanager
    def operation_context(self, operation_id: str):
        """
        Context manager for tracking operations.

        Requirement 4.3: Prevent resource conflicts and race conditions.
        """
        self.start_operation(operation_id)
        try:
            yield
        finally:
            self.end_operation(operation_id)

    def get_thread_pool(self, max_workers: int = 4) -> ThreadPoolExecutor:
        """
        Get managed thread pool executor.

        Requirement 4.2: All threads properly joined and resources released.
        """
        return self._thread_manager.get_thread_pool(max_workers)

    def submit_task(self, func: Callable, *args, **kwargs) -> Future:
        """
        Submit task to managed thread pool.
        """
        return self._thread_manager.submit_task(func, *args, **kwargs)

    def wait_for_operations(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for all active operations to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if all operations completed within timeout
        """
        return self._operation_tracker.wait_for_operations_to_complete(timeout or 30.0)

    def cleanup_resource(self, resource_id: str) -> bool:
        """
        Clean up specific resource.

        Args:
            resource_id: Resource identifier

        Returns:
            True if cleanup was successful
        """
        success = self._resource_manager.cleanup_resource(resource_id)

        # Update metrics and special tracking
        if success:
            self._operation_tracker.update_resource_metrics(cleaned=1)
            # Remove from special tracking
            if resource_id in self._windivert_handles:
                del self._windivert_handles[resource_id]
        else:
            self._operation_tracker.update_resource_metrics(failures=1)

        return success

    def cleanup(self, timeout: float = 30.0) -> bool:
        """
        Clean up all resources and shut down session.

        Requirements:
        - 4.1: Proper engine lifecycle management with guaranteed cleanup
        - 4.2: All threads properly joined and resources released
        - 4.4: Exception-safe resource cleanup
        - 4.5: Proper WinDivert handle and thread termination

        Args:
            timeout: Maximum time to wait for cleanup

        Returns:
            True if all resources were cleaned up successfully
        """
        with self._lock:
            if self._cleanup_started:
                return self._cleanup_completed

            self._cleanup_started = True
            self._is_active = False

        self.logger.info(f"Starting cleanup for session {self.session_id}")
        start_time = time.time()
        success = True

        try:
            # Wait for active operations to complete
            self.logger.debug("Waiting for active operations to complete...")
            operations_completed = self.wait_for_operations(timeout=min(timeout / 4, 10.0))
            if not operations_completed:
                self.logger.warning("Some operations did not complete before cleanup timeout")

            # Run custom cleanup callbacks first
            self.logger.debug("Running custom cleanup callbacks...")
            for callback in self._cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Cleanup callback failed: {e}")
                    success = False

            # Clean up threads using thread manager
            self.logger.debug("Cleaning up threads...")
            self._thread_manager.cleanup_all_threads()

            # Clean up resources using resource manager
            self.logger.debug("Cleaning up managed resources...")
            cleaned_count = self._resource_manager.cleanup_all_resources()
            total_resources = self._resource_manager.get_resource_count()

            if cleaned_count < total_resources:
                success = False
                self.logger.warning(
                    f"Only {cleaned_count}/{total_resources} resources cleaned successfully"
                )

            # Clear special tracking dictionaries after resource cleanup
            self._windivert_handles.clear()

            # Final verification
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time > 0:
                self._verify_cleanup(remaining_time)

        except Exception as e:
            self.logger.error(f"Exception during cleanup: {e}", exc_info=True)
            success = False

        finally:
            with self._lock:
                self._cleanup_completed = True

            # Unregister from global sessions
            self._unregister_global_session()

            elapsed = time.time() - start_time
            self.logger.info(f"Cleanup completed in {elapsed:.2f}s, success: {success}")

        return success

    def add_cleanup_callback(self, callback: Callable[[], None]) -> None:
        """
        Add custom cleanup callback.

        Args:
            callback: Function to call during cleanup
        """
        with self._lock:
            self._cleanup_callbacks.append(callback)

    def _cleanup_windivert_handle(self, handle: Any) -> None:
        """
        Clean up WinDivert handle.

        Requirement 4.5: Proper WinDivert handle termination.
        """
        try:
            if hasattr(handle, "close"):
                handle.close()
            elif hasattr(handle, "stop"):
                handle.stop()

            self.logger.debug("WinDivert handle cleaned up successfully")

        except Exception as e:
            self.logger.error(f"Failed to cleanup WinDivert handle: {e}")
            raise

    def _verify_cleanup(self, timeout: float) -> None:
        """
        Verify that cleanup was successful.

        Args:
            timeout: Time to spend on verification
        """
        start_time = time.time()

        # Check for remaining active resources using resource manager
        active_resources = self._resource_manager.get_active_resources()
        if active_resources:
            self.logger.warning(f"Found {len(active_resources)} active resources after cleanup")
            for resource_id, resource_info in active_resources.items():
                self.logger.warning(f"  - {resource_info.get('type', 'unknown')}: {resource_id}")

        # Check for remaining threads using thread manager
        remaining_threads = self._thread_manager.get_active_threads()
        if remaining_threads:
            self.logger.warning(f"Found {len(remaining_threads)} alive threads after cleanup")
            for thread_id, thread in remaining_threads.items():
                self.logger.warning(f"  - Thread: {thread_id}")

    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive session status.

        Returns:
            Dictionary with session status information
        """
        with self._lock:
            # Get status from specialized components
            resource_status = self._resource_manager.get_resource_status()
            operation_status = self._operation_tracker.get_status()
            thread_status = self._thread_manager.get_thread_status()

            return {
                "session_id": self.session_id,
                "is_active": self._is_active,
                "cleanup_started": self._cleanup_started,
                "cleanup_completed": self._cleanup_completed,
                "windivert_handles": len(self._windivert_handles),
                "resource_status": resource_status,
                "operation_status": operation_status,
                "thread_status": thread_status,
            }

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit with guaranteed cleanup.

        Requirement 4.4: Exception-safe resource cleanup.
        """
        try:
            self.cleanup()
        except Exception as e:
            self.logger.error(f"Exception during context manager cleanup: {e}")
            # Don't suppress the original exception
            return False

    def __del__(self):
        """Destructor with cleanup."""
        try:
            if self.is_active:
                self.cleanup()
        except Exception:
            pass  # Avoid exceptions in destructor

    def __str__(self) -> str:
        """String representation."""
        return f"EngineSessionManager(session_id={self.session_id}, active={self.is_active})"

    def __repr__(self) -> str:
        """Detailed representation."""
        try:
            operation_count = len(self._operation_tracker.get_active_operations())
        except:
            operation_count = 0
        return (
            f"EngineSessionManager(session_id={self.session_id}, "
            f"active={self.is_active}, "
            f"resources={self.resource_count}, "
            f"operations={operation_count})"
        )


# Convenience functions for common usage patterns


@contextmanager
def managed_engine_session(session_id: Optional[str] = None):
    """
    Context manager for engine session with guaranteed cleanup.

    Requirements:
    - 4.1: Proper engine lifecycle management with guaranteed cleanup
    - 4.4: Exception-safe resource cleanup

    Args:
        session_id: Optional session identifier

    Yields:
        EngineSessionManager instance
    """
    session = EngineSessionManager(session_id)
    try:
        yield session
    finally:
        session.cleanup()


def create_session_manager(session_id: Optional[str] = None) -> EngineSessionManager:
    """
    Factory function for creating session managers.

    Args:
        session_id: Optional session identifier

    Returns:
        EngineSessionManager instance
    """
    return EngineSessionManager(session_id)
