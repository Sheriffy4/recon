#!/usr/bin/env python3
"""
HTTP Client Pool for Performance Optimization

Provides connection pooling, request caching, and async batch processing
for HTTP clients used throughout the DPI bypass system.
"""

import asyncio
import aiohttp
import time
import logging
import hashlib
import json
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import weakref

LOG = logging.getLogger("HTTPClientPool")


@dataclass
class CacheEntry:
    """Cached HTTP response entry."""

    data: Any
    timestamp: datetime
    ttl_seconds: int
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: int = 200

    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return datetime.now() > self.timestamp + timedelta(seconds=self.ttl_seconds)


@dataclass
class RequestStats:
    """Statistics for HTTP requests."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        return (
            self.successful_requests / self.total_requests
            if self.total_requests > 0
            else 0.0
        )

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_cache_requests = self.cache_hits + self.cache_misses
        return (
            self.cache_hits / total_cache_requests if total_cache_requests > 0 else 0.0
        )

    @property
    def average_latency_ms(self) -> float:
        """Calculate average latency."""
        return (
            self.total_latency_ms / self.total_requests
            if self.total_requests > 0
            else 0.0
        )


class OptimizedHTTPClientPool:
    """
    High-performance HTTP client pool with connection pooling, caching, and batch processing.
    """

    def __init__(
        self,
        max_connections: int = 100,
        max_connections_per_host: int = 30,
        connection_timeout: float = 5.0,
        request_timeout: float = 10.0,
        cache_ttl_seconds: int = 300,  # 5 minutes default
        max_cache_size: int = 1000,
    ):
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.connection_timeout = connection_timeout
        self.request_timeout = request_timeout
        self.cache_ttl_seconds = cache_ttl_seconds
        self.max_cache_size = max_cache_size

        # Connection pool
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()

        # Response cache
        self._cache: Dict[str, CacheEntry] = {}
        self._cache_lock = asyncio.Lock()

        # Statistics
        self.stats = RequestStats()

        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]
        self._ua_index = 0

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

        # Weak references to track instances for cleanup
        self._instances = weakref.WeakSet()
        self._instances.add(self)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create optimized aiohttp session with connection pooling."""
        async with self._session_lock:
            if self._session is None or self._session.closed:
                # Create optimized connector
                connector = aiohttp.TCPConnector(
                    limit=self.max_connections,
                    limit_per_host=self.max_connections_per_host,
                    ttl_dns_cache=600,  # <--- ИЗМЕНЕНИЕ: с 300 на 600 секунд (10 минут)
                    use_dns_cache=True,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True,
                    ssl=False,
                )

                # Create timeout configuration
                timeout = aiohttp.ClientTimeout(
                    total=self.request_timeout,
                    connect=self.connection_timeout,
                    sock_read=self.request_timeout,
                )

                # Rotate user agent
                headers = {
                    "User-Agent": self.user_agents[self._ua_index],
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                }
                self._ua_index = (self._ua_index + 1) % len(self.user_agents)

                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=headers,
                    cookie_jar=aiohttp.CookieJar(),
                )

                # Start cleanup task if not running
                if self._cleanup_task is None or self._cleanup_task.done():
                    self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

                LOG.debug(
                    f"Created new HTTP session with {self.max_connections} max connections"
                )

        return self._session

    def _generate_cache_key(self, method: str, url: str, **kwargs) -> str:
        """Generate cache key for request."""
        # Include relevant parameters in cache key
        cache_data = {
            "method": method.upper(),
            "url": url,
            "headers": kwargs.get("headers", {}),
            "params": kwargs.get("params", {}),
        }

        # Don't cache POST requests with data
        if method.upper() == "POST" and ("data" in kwargs or "json" in kwargs):
            return None

        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_str.encode()).hexdigest()

    async def _get_from_cache(self, cache_key: str) -> Optional[CacheEntry]:
        """Get response from cache if available and not expired."""
        if not cache_key:
            return None

        async with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry and not entry.is_expired:
                self.stats.cache_hits += 1
                LOG.debug(f"Cache hit for key: {cache_key[:8]}...")
                return entry
            elif entry:
                # Remove expired entry
                del self._cache[cache_key]
                LOG.debug(f"Removed expired cache entry: {cache_key[:8]}...")

        self.stats.cache_misses += 1
        return None

    async def _store_in_cache(
        self,
        cache_key: str,
        response_data: Any,
        headers: Dict[str, str],
        status_code: int,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store response in cache."""
        if not cache_key:
            return

        ttl = ttl_seconds or self.cache_ttl_seconds
        entry = CacheEntry(
            data=response_data,
            timestamp=datetime.now(),
            ttl_seconds=ttl,
            headers=headers,
            status_code=status_code,
        )

        async with self._cache_lock:
            # Implement LRU eviction if cache is full
            if len(self._cache) >= self.max_cache_size:
                # Remove oldest entry
                oldest_key = min(
                    self._cache.keys(), key=lambda k: self._cache[k].timestamp
                )
                del self._cache[oldest_key]
                LOG.debug(f"Evicted cache entry: {oldest_key[:8]}...")

            self._cache[cache_key] = entry
            LOG.debug(f"Cached response for key: {cache_key[:8]}...")

    async def request(
        self,
        method: str,
        url: str,
        use_cache: bool = True,
        cache_ttl: Optional[int] = None,
        **kwargs,
    ) -> Tuple[Any, Dict[str, str], int]:
        """
        Make HTTP request with caching and connection pooling.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            use_cache: Whether to use response caching
            cache_ttl: Custom cache TTL in seconds
            **kwargs: Additional arguments for aiohttp request

        Returns:
            Tuple of (response_data, headers, status_code)
        """
        start_time = time.time()
        cache_key = (
            self._generate_cache_key(method, url, **kwargs) if use_cache else None
        )

        # Check cache first
        if use_cache and cache_key:
            cached_entry = await self._get_from_cache(cache_key)
            if cached_entry:
                return cached_entry.data, cached_entry.headers, cached_entry.status_code

        # Make actual request
        session = await self._get_session()

        try:
            async with session.request(method, url, **kwargs) as response:
                response_data = await response.read()
                headers = dict(response.headers)
                status_code = response.status

                # Update statistics
                self.stats.total_requests += 1
                latency_ms = (time.time() - start_time) * 1000
                self.stats.total_latency_ms += latency_ms

                if 200 <= status_code < 400:
                    self.stats.successful_requests += 1
                else:
                    self.stats.failed_requests += 1

                # Cache successful responses
                if use_cache and cache_key and 200 <= status_code < 400:
                    await self._store_in_cache(
                        cache_key, response_data, headers, status_code, cache_ttl
                    )

                LOG.debug(f"{method} {url} -> {status_code} ({latency_ms:.1f}ms)")
                return response_data, headers, status_code

        except Exception as e:
            self.stats.total_requests += 1
            self.stats.failed_requests += 1
            latency_ms = (time.time() - start_time) * 1000
            self.stats.total_latency_ms += latency_ms

            LOG.error(f"{method} {url} failed: {e} ({latency_ms:.1f}ms)")
            raise

    async def get(self, url: str, **kwargs) -> Tuple[Any, Dict[str, str], int]:
        """Make GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Tuple[Any, Dict[str, str], int]:
        """Make POST request."""
        return await self.request("POST", url, use_cache=False, **kwargs)

    async def batch_get(
        self, urls: List[str], max_concurrent: int = 10, **kwargs
    ) -> List[Tuple[str, Any, Dict[str, str], int, Optional[Exception]]]:
        """
        Make multiple GET requests concurrently.

        Args:
            urls: List of URLs to request
            max_concurrent: Maximum concurrent requests
            **kwargs: Additional arguments for each request

        Returns:
            List of (url, response_data, headers, status_code, error) tuples
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_one(
            url: str,
        ) -> Tuple[str, Any, Dict[str, str], int, Optional[Exception]]:
            async with semaphore:
                try:
                    data, headers, status = await self.get(url, **kwargs)
                    return url, data, headers, status, None
                except Exception as e:
                    return url, None, {}, 0, e

        tasks = [fetch_one(url) for url in urls]
        results = await asyncio.gather(*tasks)

        LOG.info(
            f"Batch GET completed: {len(urls)} URLs, "
            f"{sum(1 for r in results if r[4] is None)} successful"
        )

        return results

    async def _periodic_cleanup(self):
        """Periodic cleanup of expired cache entries."""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute

                async with self._cache_lock:
                    expired_keys = [
                        key for key, entry in self._cache.items() if entry.is_expired
                    ]

                    for key in expired_keys:
                        del self._cache[key]

                    if expired_keys:
                        LOG.debug(
                            f"Cleaned up {len(expired_keys)} expired cache entries"
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                LOG.error(f"Cache cleanup error: {e}")

    async def clear_cache(self):
        """Clear all cached responses."""
        async with self._cache_lock:
            cache_size = len(self._cache)
            self._cache.clear()
            LOG.info(f"Cleared {cache_size} cache entries")

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        return {
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "success_rate": self.stats.success_rate,
            "cache_hits": self.stats.cache_hits,
            "cache_misses": self.stats.cache_misses,
            "cache_hit_rate": self.stats.cache_hit_rate,
            "cache_size": len(self._cache),
            "average_latency_ms": self.stats.average_latency_ms,
            "session_active": self._session is not None and not self._session.closed,
        }

    async def close(self):
        """Close HTTP session and cleanup resources."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        if self._session and not self._session.closed:
            await self._session.close()
            LOG.debug("HTTP session closed")

        await self.clear_cache()


# Global HTTP client pool instance
_global_pool: Optional[OptimizedHTTPClientPool] = None


def get_global_http_pool() -> OptimizedHTTPClientPool:
    """Get or create global HTTP client pool."""
    global _global_pool
    if _global_pool is None:
        _global_pool = OptimizedHTTPClientPool()
    return _global_pool


async def cleanup_global_pool():
    """Cleanup global HTTP client pool."""
    global _global_pool
    if _global_pool:
        await _global_pool.close()
        _global_pool = None
