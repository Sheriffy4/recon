#!/usr/bin/env python3
"""
Async Operations Optimizer
Optimizes blocking operations in async contexts and provides async utilities.
"""

import asyncio
import threading
import time
import logging
import concurrent.futures
from typing import Any, Callable, Optional, Dict, List, Awaitable, Union
from functools import wraps, partial
import inspect
from contextlib import asynccontextmanager

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

class AsyncOptimizer:
    """
    Optimizes blocking operations for async contexts.
    Provides utilities for converting blocking operations to async.
    """
    
    def __init__(self, max_workers: int = 4, connection_pool_size: int = 20):
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers
        self.connection_pool_size = connection_pool_size
        
        # Thread pool for blocking operations
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="AsyncOptimizer"
        )
        
        # HTTP session for async requests
        self.http_session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # Operation tracking
        self.active_operations: Dict[str, int] = {}
        self.operation_stats: Dict[str, Dict[str, Any]] = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_http_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
    
    async def _ensure_http_session(self):
        """Ensure HTTP session is created."""
        if not AIOHTTP_AVAILABLE:
            return
        
        async with self._session_lock:
            if self.http_session is None or self.http_session.closed:
                connector = aiohttp.TCPConnector(
                    limit=self.connection_pool_size,
                    limit_per_host=10,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True
                )
                
                timeout = aiohttp.ClientTimeout(
                    total=30,
                    connect=10,
                    sock_read=30
                )
                
                self.http_session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={
                        'User-Agent': 'recon-async-optimizer/1.0'
                    }
                )
                
                self.logger.debug("HTTP session created")
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.http_session and not self.http_session.closed:
            await self.http_session.close()
            self.logger.debug("HTTP session closed")
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=False)
    
    async def run_in_thread(self, func: Callable, *args, **kwargs) -> Any:
        """
        Run a blocking function in a thread pool.
        
        Args:
            func: Blocking function to run
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
        """
        operation_name = f"{func.__module__}.{func.__name__}"
        
        # Track operation
        self.active_operations[operation_name] = self.active_operations.get(operation_name, 0) + 1
        
        start_time = time.time()
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.thread_pool,
                partial(func, *args, **kwargs)
            )
            
            # Update stats
            duration = time.time() - start_time
            self._update_operation_stats(operation_name, duration, True)
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self._update_operation_stats(operation_name, duration, False, str(e))
            raise
        finally:
            self.active_operations[operation_name] -= 1
            if self.active_operations[operation_name] <= 0:
                del self.active_operations[operation_name]
    
    def _update_operation_stats(self, operation_name: str, duration: float, success: bool, error: Optional[str] = None):
        """Update operation statistics."""
        if operation_name not in self.operation_stats:
            self.operation_stats[operation_name] = {
                "total_calls": 0,
                "successful_calls": 0,
                "failed_calls": 0,
                "total_duration": 0.0,
                "avg_duration": 0.0,
                "max_duration": 0.0,
                "min_duration": float('inf'),
                "last_error": None
            }
        
        stats = self.operation_stats[operation_name]
        stats["total_calls"] += 1
        stats["total_duration"] += duration
        stats["avg_duration"] = stats["total_duration"] / stats["total_calls"]
        stats["max_duration"] = max(stats["max_duration"], duration)
        stats["min_duration"] = min(stats["min_duration"], duration)
        
        if success:
            stats["successful_calls"] += 1
        else:
            stats["failed_calls"] += 1
            stats["last_error"] = error
    
    async def http_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make an async HTTP request.
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response data
        """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available for async HTTP requests")
        
        await self._ensure_http_session()
        
        operation_name = f"http_request.{method.upper()}"
        self.active_operations[operation_name] = self.active_operations.get(operation_name, 0) + 1
        
        start_time = time.time()
        try:
            async with self.http_session.request(method, url, **kwargs) as response:
                result = {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "url": str(response.url),
                    "content_type": response.content_type
                }
                
                # Read response body based on content type
                if response.content_type.startswith('application/json'):
                    try:
                        result["data"] = await response.json()
                    except:
                        result["data"] = await response.text()
                else:
                    result["data"] = await response.text()
                
                duration = time.time() - start_time
                self._update_operation_stats(operation_name, duration, response.status < 400)
                
                return result
                
        except Exception as e:
            duration = time.time() - start_time
            self._update_operation_stats(operation_name, duration, False, str(e))
            raise
        finally:
            self.active_operations[operation_name] -= 1
            if self.active_operations[operation_name] <= 0:
                del self.active_operations[operation_name]
    
    async def batch_operations(self, operations: List[Callable], max_concurrent: int = 10) -> List[Any]:
        """
        Execute multiple operations concurrently with concurrency limit.
        
        Args:
            operations: List of async operations to execute
            max_concurrent: Maximum concurrent operations
            
        Returns:
            List of results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_operation(op):
            async with semaphore:
                return await op()
        
        tasks = [limited_operation(op) for op in operations]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_operation_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get operation statistics."""
        return self.operation_stats.copy()
    
    def get_active_operations(self) -> Dict[str, int]:
        """Get currently active operations."""
        return self.active_operations.copy()

def async_optimize(func: Optional[Callable] = None, *, use_thread_pool: bool = True):
    """
    Decorator to optimize blocking functions for async contexts.
    
    Args:
        func: Function to optimize
        use_thread_pool: Whether to use thread pool for blocking operations
    """
    def decorator(f):
        if inspect.iscoroutinefunction(f):
            # Already async, just return as-is
            return f
        
        @wraps(f)
        async def async_wrapper(*args, **kwargs):
            if use_thread_pool:
                optimizer = get_global_optimizer()
                return await optimizer.run_in_thread(f, *args, **kwargs)
            else:
                # Run directly (for CPU-bound operations that release GIL)
                return f(*args, **kwargs)
        
        return async_wrapper
    
    if func is None:
        return decorator
    else:
        return decorator(func)

def make_async(func: Callable, use_thread_pool: bool = True) -> Callable:
    """
    Convert a blocking function to async.
    
    Args:
        func: Blocking function to convert
        use_thread_pool: Whether to use thread pool
        
    Returns:
        Async version of the function
    """
    return async_optimize(func, use_thread_pool=use_thread_pool)

@asynccontextmanager
async def async_timeout(seconds: float):
    """
    Async context manager for timeouts.
    
    Args:
        seconds: Timeout in seconds
    """
    try:
        async with asyncio.timeout(seconds):
            yield
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"Operation timed out after {seconds} seconds")

class AsyncBatch:
    """Utility for batching async operations."""
    
    def __init__(self, max_concurrent: int = 10, timeout_seconds: float = 30.0):
        self.max_concurrent = max_concurrent
        self.timeout_seconds = timeout_seconds
        self.operations: List[Callable] = []
    
    def add(self, operation: Callable):
        """Add an async operation to the batch."""
        self.operations.append(operation)
    
    async def execute(self) -> List[Any]:
        """Execute all operations in the batch."""
        if not self.operations:
            return []
        
        optimizer = get_global_optimizer()
        
        async with async_timeout(self.timeout_seconds):
            return await optimizer.batch_operations(
                self.operations, 
                max_concurrent=self.max_concurrent
            )
    
    def clear(self):
        """Clear all operations from the batch."""
        self.operations.clear()

class AsyncQueue:
    """Async queue with rate limiting and backpressure."""
    
    def __init__(self, max_size: int = 1000, max_rate_per_second: float = 10.0):
        self.queue = asyncio.Queue(maxsize=max_size)
        self.max_rate_per_second = max_rate_per_second
        self.last_get_time = 0.0
        self.rate_limiter_lock = asyncio.Lock()
    
    async def put(self, item: Any):
        """Put an item in the queue."""
        await self.queue.put(item)
    
    async def get(self) -> Any:
        """Get an item from the queue with rate limiting."""
        async with self.rate_limiter_lock:
            # Rate limiting
            if self.max_rate_per_second > 0:
                min_interval = 1.0 / self.max_rate_per_second
                elapsed = time.time() - self.last_get_time
                
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
                
                self.last_get_time = time.time()
        
        return await self.queue.get()
    
    def qsize(self) -> int:
        """Get queue size."""
        return self.queue.qsize()
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        return self.queue.empty()
    
    def full(self) -> bool:
        """Check if queue is full."""
        return self.queue.full()

# Async utilities for common blocking operations
class AsyncUtils:
    """Collection of async utilities for common operations."""
    
    @staticmethod
    async def sleep_with_jitter(base_seconds: float, jitter_factor: float = 0.1):
        """Sleep with random jitter to avoid thundering herd."""
        import random
        jitter = random.uniform(-jitter_factor, jitter_factor) * base_seconds
        sleep_time = max(0, base_seconds + jitter)
        await asyncio.sleep(sleep_time)
    
    @staticmethod
    async def retry_with_backoff(
        operation: Callable,
        max_retries: int = 3,
        base_delay: float = 1.0,
        backoff_factor: float = 2.0,
        max_delay: float = 60.0
    ) -> Any:
        """Retry an async operation with exponential backoff."""
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return await operation()
            except Exception as e:
                last_exception = e
                
                if attempt == max_retries:
                    break
                
                delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                await AsyncUtils.sleep_with_jitter(delay)
        
        raise last_exception
    
    @staticmethod
    async def gather_with_limit(
        *operations: Awaitable,
        limit: int = 10,
        return_exceptions: bool = True
    ) -> List[Any]:
        """Gather operations with concurrency limit."""
        semaphore = asyncio.Semaphore(limit)
        
        async def limited_operation(op):
            async with semaphore:
                return await op
        
        limited_ops = [limited_operation(op) for op in operations]
        return await asyncio.gather(*limited_ops, return_exceptions=return_exceptions)

# Global optimizer instance
_global_optimizer: Optional[AsyncOptimizer] = None

def get_global_optimizer() -> AsyncOptimizer:
    """Get or create global async optimizer."""
    global _global_optimizer
    if _global_optimizer is None:
        _global_optimizer = AsyncOptimizer()
    return _global_optimizer

async def cleanup_global_optimizer():
    """Cleanup global optimizer resources."""
    global _global_optimizer
    if _global_optimizer is not None:
        await _global_optimizer.cleanup()
        _global_optimizer = None