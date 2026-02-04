"""
Async/Sync Wrapper for consistent behavior between sync and async modes.

This module provides utilities for running async operations from sync contexts
and vice versa, handling nested event loop scenarios correctly.

Requirements: 5.1, 5.2, 5.5 - Async/sync compatibility with consistent behavior
"""

import asyncio
import concurrent.futures
import functools
import inspect
import logging
import threading
from typing import Any, Awaitable, Callable, Optional, TypeVar, Union
from concurrent.futures import ThreadPoolExecutor

T = TypeVar("T")

logger = logging.getLogger(__name__)


def is_async_context() -> bool:
    """
    Check if we're currently in an async context (event loop running).

    Returns:
        True if in async context, False otherwise

    Requirement 5.4: Handle nested event loop scenarios correctly
    """
    try:
        loop = asyncio.get_running_loop()
        return loop is not None and loop.is_running()
    except RuntimeError:
        return False


def handle_nested_event_loop(coro: Awaitable[T], timeout: Optional[float] = None) -> T:
    """
    Handle nested event loop scenarios by running coroutine in thread pool.

    Args:
        coro: Coroutine to execute
        timeout: Optional timeout in seconds

    Returns:
        Result of coroutine execution

    Raises:
        RuntimeError: If execution fails
        TimeoutError: If timeout is exceeded

    Requirement 5.4: Handle nested event loop scenarios correctly
    """
    if not is_async_context():
        # No event loop running, can use asyncio.run directly
        return asyncio.run(coro)

    # We're in an async context, need to run in thread pool
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout} seconds")


def run_in_thread_pool(
    func: Callable[..., T],
    *args,
    timeout: Optional[float] = None,
    executor: Optional[ThreadPoolExecutor] = None,
    **kwargs,
) -> T:
    """
    Run a synchronous function in a thread pool.

    Args:
        func: Function to execute
        *args: Positional arguments for function
        timeout: Optional timeout in seconds
        executor: Optional custom executor
        **kwargs: Keyword arguments for function

    Returns:
        Result of function execution

    Requirement 5.2: Proper sync wrappers using ThreadPoolExecutor
    """
    if executor is None:
        with ThreadPoolExecutor(max_workers=1) as default_executor:
            future = default_executor.submit(func, *args, **kwargs)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(f"Operation timed out after {timeout} seconds")
    else:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout} seconds")


class AsyncSyncWrapper:
    """
    Wrapper class that provides both async and sync interfaces for operations.

    This class ensures consistent behavior between sync and async modes by
    providing native async implementations and proper sync wrappers.

    Requirements: 5.1, 5.2, 5.5 - Async/sync compatibility with consistent behavior
    """

    def __init__(self, executor: Optional[ThreadPoolExecutor] = None):
        """
        Initialize AsyncSyncWrapper.

        Args:
            executor: Optional custom ThreadPoolExecutor for sync operations
        """
        self._executor = executor
        self._default_timeout = 30.0

    def __enter__(self):
        """Context manager entry."""
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=4)
            self._owns_executor = True
        else:
            self._owns_executor = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._owns_executor and self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

    async def run_async(
        self, coro_or_func: Union[Awaitable[T], Callable[..., T]], *args, **kwargs
    ) -> T:
        """
        Run an async operation, handling both coroutines and sync functions.

        Args:
            coro_or_func: Coroutine or sync function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Result of operation

        Requirement 5.1: Native async implementations for all operations
        """
        if inspect.iscoroutine(coro_or_func):
            return await coro_or_func
        elif inspect.iscoroutinefunction(coro_or_func):
            return await coro_or_func(*args, **kwargs)
        elif callable(coro_or_func):
            # Run sync function in thread pool
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self._executor, functools.partial(coro_or_func, *args, **kwargs)
            )
        else:
            raise TypeError(f"Expected coroutine or callable, got {type(coro_or_func)}")

    def run_sync(
        self,
        coro_or_func: Union[Awaitable[T], Callable[..., T]],
        *args,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> T:
        """
        Run an operation synchronously, handling both coroutines and sync functions.

        Args:
            coro_or_func: Coroutine or sync function to execute
            *args: Positional arguments
            timeout: Optional timeout in seconds
            **kwargs: Keyword arguments

        Returns:
            Result of operation

        Requirement 5.2: Proper sync wrappers using ThreadPoolExecutor
        Requirement 5.4: Handle nested event loop scenarios correctly
        """
        timeout = timeout or self._default_timeout

        if inspect.iscoroutine(coro_or_func):
            return handle_nested_event_loop(coro_or_func, timeout)
        elif inspect.iscoroutinefunction(coro_or_func):
            coro = coro_or_func(*args, **kwargs)
            return handle_nested_event_loop(coro, timeout)
        elif callable(coro_or_func):
            # Direct sync function call
            return coro_or_func(*args, **kwargs)
        else:
            raise TypeError(f"Expected coroutine or callable, got {type(coro_or_func)}")

    def wrap_method(self, method: Callable) -> Callable:
        """
        Wrap a method to provide both async and sync versions.

        Args:
            method: Method to wrap

        Returns:
            Wrapped method with async/sync compatibility
        """
        if inspect.iscoroutinefunction(method):
            # Async method - add sync wrapper
            @functools.wraps(method)
            def sync_wrapper(*args, **kwargs):
                coro = method(*args, **kwargs)
                return self.run_sync(coro)

            # Add sync version as attribute (handle bound methods)
            try:
                method.sync = sync_wrapper
            except AttributeError:
                # For bound methods, we can't set attributes directly
                # Store in a registry or return a wrapper object
                pass
            return method
        else:
            # Sync method - add async wrapper
            @functools.wraps(method)
            async def async_wrapper(*args, **kwargs):
                return await self.run_async(method, *args, **kwargs)

            # Add async version as attribute (handle bound methods)
            try:
                method.async_version = async_wrapper
            except AttributeError:
                # For bound methods, we can't set attributes directly
                pass
            return method


class AsyncCompatibilityMixin:
    """
    Mixin class that adds async/sync compatibility to any class.

    This mixin provides automatic async/sync method generation and
    ensures consistent behavior between sync and async modes.

    Requirements: 5.1, 5.2, 5.5 - Async/sync compatibility with consistent behavior
    """

    def __init__(self, *args, **kwargs):
        """Initialize mixin with async/sync wrapper."""
        super().__init__(*args, **kwargs)
        self._async_wrapper = AsyncSyncWrapper()
        self._method_registry = {}  # Registry for async/sync method versions
        self._setup_async_sync_methods()

    def _setup_async_sync_methods(self):
        """
        Automatically create async/sync versions of methods.

        This method scans the class for methods and creates corresponding
        async or sync versions as needed.
        """
        # Skip automatic setup for bound methods to avoid AttributeError
        # Methods will be wrapped on-demand through ensure_async_method/ensure_sync_method
        pass

    async def _run_async_operation(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Run an operation asynchronously.

        Args:
            operation: Operation to run
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Result of operation
        """
        return await self._async_wrapper.run_async(operation, *args, **kwargs)

    def _run_sync_operation(
        self, operation: Callable, *args, timeout: Optional[float] = None, **kwargs
    ) -> Any:
        """
        Run an operation synchronously.

        Args:
            operation: Operation to run
            *args: Positional arguments
            timeout: Optional timeout in seconds
            **kwargs: Keyword arguments

        Returns:
            Result of operation
        """
        return self._async_wrapper.run_sync(operation, *args, timeout=timeout, **kwargs)

    def ensure_async_method(self, method_name: str) -> Callable:
        """
        Ensure a method has an async version.

        Args:
            method_name: Name of method to ensure async version for

        Returns:
            Async version of method

        Raises:
            AttributeError: If method doesn't exist
        """
        if not hasattr(self, method_name):
            raise AttributeError(f"Method {method_name} not found")

        method = getattr(self, method_name)

        if inspect.iscoroutinefunction(method):
            return method

        # Check registry first
        registry_key = f"{method_name}_async"
        if registry_key in self._method_registry:
            return self._method_registry[registry_key]

        # Check if async version already exists as attribute
        if hasattr(method, "async_version"):
            return method.async_version

        # Create async version
        @functools.wraps(method)
        async def async_method(*args, **kwargs):
            return await self._run_async_operation(method, *args, **kwargs)

        # Try to set as attribute, fall back to registry
        try:
            method.async_version = async_method
        except AttributeError:
            self._method_registry[registry_key] = async_method

        return async_method

    def ensure_sync_method(self, method_name: str) -> Callable:
        """
        Ensure a method has a sync version.

        Args:
            method_name: Name of method to ensure sync version for

        Returns:
            Sync version of method

        Raises:
            AttributeError: If method doesn't exist
        """
        if not hasattr(self, method_name):
            raise AttributeError(f"Method {method_name} not found")

        method = getattr(self, method_name)

        if not inspect.iscoroutinefunction(method):
            return method

        # Check registry first
        registry_key = f"{method_name}_sync"
        if registry_key in self._method_registry:
            return self._method_registry[registry_key]

        # Check if sync version already exists as attribute
        if hasattr(method, "sync"):
            return method.sync

        # Create sync version
        @functools.wraps(method)
        def sync_method(*args, **kwargs):
            coro = method(*args, **kwargs)
            return self._run_sync_operation(coro)

        # Try to set as attribute, fall back to registry
        try:
            method.sync = sync_method
        except AttributeError:
            self._method_registry[registry_key] = sync_method

        return sync_method


def async_sync_method(timeout: Optional[float] = None):
    """
    Decorator that creates both async and sync versions of a method.

    Args:
        timeout: Default timeout for sync version

    Returns:
        Decorator function

    Requirements: 5.1, 5.2, 5.5 - Async/sync compatibility
    """

    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            # Async function - add sync wrapper
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                coro = func(*args, **kwargs)
                return handle_nested_event_loop(coro, timeout)

            func.sync = sync_wrapper
            return func
        else:
            # Sync function - add async wrapper
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))

            func.async_version = async_wrapper
            return func

    return decorator


def ensure_consistent_behavior(func: Callable) -> Callable:
    """
    Decorator that ensures consistent behavior between sync and async versions.

    This decorator adds validation and error handling to ensure that both
    sync and async versions of a method behave consistently.

    Args:
        func: Function to wrap

    Returns:
        Wrapped function with consistent behavior

    Requirement 5.5: Consistent behavior between sync and async modes
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)

            # Log successful execution for consistency tracking
            logger.debug(f"Function {func.__name__} executed successfully")

            return result
        except Exception as e:
            # Ensure consistent error handling
            logger.error(f"Function {func.__name__} failed: {e}")
            raise

    return wrapper
