"""
Thread management for engine sessions.

This module provides thread management functionality
extracted from EngineSessionManager to maintain single responsibility.

Feature: unified-engine-refactoring
Requirements: 4.2
"""

import threading
import time
import logging
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, Future


class ThreadManager:
    """
    Manages threads and thread pools for engine sessions.

    This class handles thread lifecycle management to ensure
    all threads are properly joined and resources released.

    Requirement 4.2: All threads properly joined and resources released.
    """

    def __init__(self, session_id: str, logger: Optional[logging.Logger] = None):
        """
        Initialize thread manager.

        Args:
            session_id: Session identifier
            logger: Optional logger instance
        """
        self.session_id = session_id
        self.logger = logger or logging.getLogger(__name__)

        # Thread tracking
        self._threads: Dict[str, threading.Thread] = {}
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._futures: List[Future] = []

    def register_thread(self, thread: threading.Thread, thread_id: Optional[str] = None) -> str:
        """
        Register thread for managed cleanup.

        Args:
            thread: Thread to manage
            thread_id: Unique identifier

        Returns:
            Thread ID for tracking
        """
        if thread_id is None:
            thread_id = f"thread_{len(self._threads)}_{int(time.time() * 1000000)}"

        self._threads[thread_id] = thread
        self.logger.debug(f"Registered thread: {thread_id} ({thread.name})")
        return thread_id

    def get_thread_pool(self, max_workers: int = 4) -> ThreadPoolExecutor:
        """
        Get managed thread pool executor.

        Args:
            max_workers: Maximum number of worker threads

        Returns:
            ThreadPoolExecutor instance
        """
        if self._thread_pool is None:
            self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)
            self.logger.debug(f"Created thread pool with {max_workers} workers")

        return self._thread_pool

    def submit_task(self, func, *args, **kwargs) -> Future:
        """
        Submit task to managed thread pool.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Future object
        """
        pool = self.get_thread_pool()
        future = pool.submit(func, *args, **kwargs)
        self._futures.append(future)
        return future

    def cleanup_thread(self, thread: threading.Thread) -> bool:
        """
        Clean up thread with proper joining.

        Args:
            thread: Thread to clean up

        Returns:
            True if cleanup was successful
        """
        try:
            if thread.is_alive():
                # Try to stop thread gracefully if it has a stop method
                if hasattr(thread, "stop"):
                    thread.stop()

                # Join with timeout
                thread.join(timeout=5.0)

                if thread.is_alive():
                    self.logger.warning(f"Thread {thread.name} did not stop gracefully")
                    return False
                else:
                    self.logger.debug(f"Thread {thread.name} joined successfully")
                    return True

            return True  # Thread was already stopped

        except Exception as e:
            self.logger.error(f"Failed to cleanup thread {thread.name}: {e}")
            return False

    def cleanup_thread_pool(self) -> bool:
        """
        Clean up thread pool executor.

        Returns:
            True if cleanup was successful
        """
        if self._thread_pool:
            try:
                # Try with timeout parameter first (Python 3.9+)
                try:
                    self._thread_pool.shutdown(wait=True, timeout=10.0)
                except TypeError:
                    # Fallback for older Python versions
                    self._thread_pool.shutdown(wait=True)

                self.logger.debug("Thread pool shut down successfully")
                self._thread_pool = None
                return True

            except Exception as e:
                self.logger.error(f"Failed to shutdown thread pool: {e}")
                return False

        return True

    def cleanup_futures(self, timeout: float = 5.0) -> bool:
        """
        Clean up pending futures.

        Args:
            timeout: Maximum time to wait for futures

        Returns:
            True if cleanup was successful
        """
        if not self._futures:
            return True

        try:
            # Cancel pending futures
            for future in self._futures:
                if not future.done():
                    future.cancel()

            # Wait for completion with timeout
            start_time = time.time()
            for future in self._futures:
                remaining_time = timeout - (time.time() - start_time)
                if remaining_time <= 0:
                    break

                try:
                    future.result(timeout=remaining_time)
                except Exception:
                    pass  # Ignore exceptions from cancelled futures

            self._futures.clear()
            self.logger.debug("Futures cleaned up successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to cleanup futures: {e}")
            return False

    def cleanup_all_threads(self) -> int:
        """
        Clean up all managed threads.

        Returns:
            Number of threads successfully cleaned up
        """
        success_count = 0

        # Clean up individual threads
        for thread_id, thread in self._threads.items():
            try:
                if self.cleanup_thread(thread):
                    success_count += 1
            except Exception as e:
                self.logger.error(f"Failed to cleanup thread {thread_id}: {e}")

        # Clean up futures
        self.cleanup_futures()

        # Clean up thread pool
        self.cleanup_thread_pool()

        return success_count

    def get_active_threads(self) -> Dict[str, threading.Thread]:
        """Get all active threads."""
        return {
            thread_id: thread for thread_id, thread in self._threads.items() if thread.is_alive()
        }

    def get_thread_status(self) -> Dict[str, Any]:
        """
        Get thread management status.

        Returns:
            Dictionary with thread status information
        """
        alive_threads = [t for t in self._threads.values() if t.is_alive()]

        return {
            "session_id": self.session_id,
            "total_threads": len(self._threads),
            "alive_threads": len(alive_threads),
            "thread_pool_active": self._thread_pool is not None,
            "pending_futures": len(self._futures),
            "thread_names": [t.name for t in alive_threads],
        }
