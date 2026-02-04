"""
Event Loop Handler for managing async event loops in various contexts.

This module provides utilities for handling event loops correctly in different
scenarios, including nested event loops and cross-platform compatibility.

Requirements: 5.4 - Handle nested event loop scenarios correctly
"""

import asyncio
import logging
import threading
import sys
from typing import Optional, Any, Callable, TypeVar
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

T = TypeVar("T")

logger = logging.getLogger(__name__)


class EventLoopHandler:
    """
    Handler for managing event loops in various contexts.

    This class provides utilities for creating, managing, and handling
    event loops correctly across different scenarios.

    Requirement 5.4: Handle nested event loop scenarios correctly
    """

    def __init__(self):
        """Initialize EventLoopHandler."""
        self._thread_local = threading.local()
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()

    def get_current_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        """
        Get the current event loop if one is running.

        Returns:
            Current event loop or None if no loop is running
        """
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            return None

    def is_loop_running(self) -> bool:
        """
        Check if an event loop is currently running.

        Returns:
            True if event loop is running, False otherwise
        """
        return self.get_current_loop() is not None

    def get_or_create_loop(self) -> asyncio.AbstractEventLoop:
        """
        Get existing event loop or create a new one.

        Returns:
            Event loop instance

        Requirement 5.4: Handle nested event loop scenarios correctly
        """
        try:
            # Try to get running loop first
            loop = asyncio.get_running_loop()
            return loop
        except RuntimeError:
            # No running loop, try to get event loop for current thread
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    # Loop is closed, create new one
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                return loop
            except RuntimeError:
                # No event loop, create new one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop

    def ensure_event_loop(self) -> asyncio.AbstractEventLoop:
        """
        Ensure an event loop exists for the current thread.

        Returns:
            Event loop instance
        """
        if not hasattr(self._thread_local, "loop"):
            self._thread_local.loop = self.get_or_create_loop()

        if self._thread_local.loop.is_closed():
            self._thread_local.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._thread_local.loop)

        return self._thread_local.loop

    def run_in_new_loop(self, coro) -> Any:
        """
        Run coroutine in a new event loop.

        This method creates a new event loop and runs the coroutine in it,
        which is useful for avoiding nested event loop issues.

        Args:
            coro: Coroutine to run

        Returns:
            Result of coroutine execution

        Requirement 5.4: Handle nested event loop scenarios correctly
        """
        # Create new event loop in current thread
        old_loop = None
        try:
            old_loop = asyncio.get_event_loop()
        except RuntimeError:
            pass

        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)

        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()
            if old_loop and not old_loop.is_closed():
                asyncio.set_event_loop(old_loop)
            else:
                # Clear event loop if old one was closed
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass

    def run_in_thread(self, coro, timeout: Optional[float] = None) -> Any:
        """
        Run coroutine in a separate thread with its own event loop.

        This is the safest way to run async code from sync context
        when there might be an existing event loop.

        Args:
            coro: Coroutine to run
            timeout: Optional timeout in seconds

        Returns:
            Result of coroutine execution

        Requirement 5.4: Handle nested event loop scenarios correctly
        """

        def run_coro():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run_coro)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(f"Operation timed out after {timeout} seconds")

    def handle_nested_loop_scenario(self, coro, timeout: Optional[float] = None) -> Any:
        """
        Handle nested event loop scenarios intelligently.

        This method detects the current context and chooses the appropriate
        method for running the coroutine.

        Args:
            coro: Coroutine to run
            timeout: Optional timeout in seconds

        Returns:
            Result of coroutine execution

        Requirement 5.4: Handle nested event loop scenarios correctly
        """
        if not self.is_loop_running():
            # No loop running, can use asyncio.run or run_until_complete
            try:
                return asyncio.run(coro)
            except Exception:
                # Fallback to manual loop management
                return self.run_in_new_loop(coro)
        else:
            # Loop is running, need to run in thread
            logger.debug("Detected nested event loop scenario, running in thread")
            return self.run_in_thread(coro, timeout)

    def start_background_loop(self) -> asyncio.AbstractEventLoop:
        """
        Start a background event loop in a separate thread.

        This is useful for running async operations from sync contexts
        without blocking the main thread.

        Returns:
            Event loop running in background thread
        """
        if self._main_loop and not self._main_loop.is_closed():
            return self._main_loop

        self._shutdown_event.clear()

        def run_loop():
            self._main_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._main_loop)

            try:
                # Run until shutdown is requested
                while not self._shutdown_event.is_set():
                    try:
                        self._main_loop.run_until_complete(asyncio.sleep(0.1))
                    except Exception as e:
                        if not self._shutdown_event.is_set():
                            logger.error(f"Error in background event loop: {e}")
            finally:
                self._main_loop.close()

        self._loop_thread = threading.Thread(target=run_loop, daemon=True)
        self._loop_thread.start()

        # Wait for loop to be ready
        import time

        max_wait = 5.0
        start_time = time.time()
        while (self._main_loop is None or self._main_loop.is_closed()) and (
            time.time() - start_time
        ) < max_wait:
            time.sleep(0.01)

        if self._main_loop is None or self._main_loop.is_closed():
            raise RuntimeError("Failed to start background event loop")

        return self._main_loop

    def stop_background_loop(self, timeout: float = 5.0):
        """
        Stop the background event loop.

        Args:
            timeout: Timeout for stopping the loop
        """
        if self._main_loop and not self._main_loop.is_closed():
            self._shutdown_event.set()

            if self._loop_thread and self._loop_thread.is_alive():
                self._loop_thread.join(timeout=timeout)

            self._main_loop = None
            self._loop_thread = None

    def run_coroutine_threadsafe(
        self,
        coro,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """
        Run coroutine in a specific event loop from another thread.

        Args:
            coro: Coroutine to run
            loop: Target event loop (uses background loop if None)
            timeout: Optional timeout in seconds

        Returns:
            Result of coroutine execution
        """
        if loop is None:
            loop = self.start_background_loop()

        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise TimeoutError(f"Operation timed out after {timeout} seconds")

    def handle_event_loop_policy(self):
        """
        Handle event loop policy for cross-platform compatibility.

        This method sets appropriate event loop policies for different
        platforms to ensure consistent behavior.
        """
        if sys.platform == "win32":
            # On Windows, use ProactorEventLoop for subprocess support
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                logger.debug("Set Windows ProactorEventLoop policy")
            except AttributeError:
                # Fallback for older Python versions
                logger.warning("ProactorEventLoop not available, using default policy")
        else:
            # On Unix-like systems, use default policy
            try:
                asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
                logger.debug("Set default event loop policy")
            except Exception as e:
                logger.warning(f"Failed to set event loop policy: {e}")


# Global event loop handler instance
_global_event_loop_handler: Optional[EventLoopHandler] = None


def get_event_loop_handler() -> EventLoopHandler:
    """
    Get global event loop handler instance.

    Returns:
        Global EventLoopHandler instance
    """
    global _global_event_loop_handler
    if _global_event_loop_handler is None:
        _global_event_loop_handler = EventLoopHandler()
    return _global_event_loop_handler


def get_or_create_event_loop() -> asyncio.AbstractEventLoop:
    """
    Get existing event loop or create a new one.

    Returns:
        Event loop instance
    """
    handler = get_event_loop_handler()
    return handler.get_or_create_loop()


def ensure_event_loop() -> asyncio.AbstractEventLoop:
    """
    Ensure an event loop exists for the current thread.

    Returns:
        Event loop instance
    """
    handler = get_event_loop_handler()
    return handler.ensure_event_loop()


def handle_event_loop_policy():
    """
    Handle event loop policy for cross-platform compatibility.
    """
    handler = get_event_loop_handler()
    handler.handle_event_loop_policy()


def run_async_from_sync(coro, timeout: Optional[float] = None) -> Any:
    """
    Run async coroutine from sync context, handling nested loops correctly.

    Args:
        coro: Coroutine to run
        timeout: Optional timeout in seconds

    Returns:
        Result of coroutine execution

    Requirement 5.4: Handle nested event loop scenarios correctly
    """
    handler = get_event_loop_handler()
    return handler.handle_nested_loop_scenario(coro, timeout)


def cleanup_event_loop_handler():
    """Clean up global event loop handler."""
    global _global_event_loop_handler
    if _global_event_loop_handler:
        _global_event_loop_handler.stop_background_loop()
        _global_event_loop_handler = None
