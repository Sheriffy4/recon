"""
ConnectionPool for Network Connection Reuse

Provides connection pooling for HTTP/HTTPS requests to improve performance
and reduce connection overhead during strategy testing.

Requirements: 9.2 - Use connection pooling for test operations
"""

import asyncio
import aiohttp
import threading
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from contextlib import asynccontextmanager
import ssl
import certifi


@dataclass
class ConnectionPoolConfig:
    """Configuration for connection pool."""

    max_connections: int = 100
    max_connections_per_host: int = 10
    connection_timeout: float = 30.0
    read_timeout: float = 30.0
    keepalive_timeout: float = 30.0
    enable_cleanup_closed: bool = True
    ttl_dns_cache: int = 300  # 5 minutes
    use_dns_cache: bool = True


class ConnectionPool:
    """
    HTTP/HTTPS connection pool for network test operations.

    Provides connection reuse to improve performance during strategy testing
    as required by Requirement 9.2.
    """

    def __init__(self, config: Optional[ConnectionPoolConfig] = None):
        """
        Initialize connection pool.

        Args:
            config: Connection pool configuration
        """
        self.config = config or ConnectionPoolConfig()
        self.logger = logging.getLogger(__name__)

        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        self._closed = False

        # SSL context
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with proper certificate verification."""
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        return ssl_context

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling."""
        if self._closed:
            raise RuntimeError("Connection pool is closed")

        async with self._session_lock:
            if self._session is None or self._session.closed:
                # Create TCP connector with pooling configuration
                connector = aiohttp.TCPConnector(
                    limit=self.config.max_connections,
                    limit_per_host=self.config.max_connections_per_host,
                    ttl_dns_cache=self.config.ttl_dns_cache,
                    use_dns_cache=self.config.use_dns_cache,
                    keepalive_timeout=self.config.keepalive_timeout,
                    enable_cleanup_closed=self.config.enable_cleanup_closed,
                    ssl=self._ssl_context,
                )

                # Create timeout configuration
                timeout = aiohttp.ClientTimeout(
                    total=self.config.connection_timeout + self.config.read_timeout,
                    connect=self.config.connection_timeout,
                    sock_read=self.config.read_timeout,
                )

                # Create session
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers={"User-Agent": "UnifiedBypassEngine/1.0"},
                )

                self.logger.debug("Created new HTTP session with connection pooling")

        return self._session

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        """
        Make HTTP request using connection pool.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Optional request headers
            data: Optional request body
            params: Optional query parameters
            allow_redirects: Whether to follow redirects
            verify_ssl: Whether to verify SSL certificates

        Returns:
            Dictionary with response data
        """
        session = await self._get_session()

        # Prepare SSL context
        ssl_context = self._ssl_context if verify_ssl else False

        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
                allow_redirects=allow_redirects,
                ssl=ssl_context,
            ) as response:

                # Read response
                response_text = await response.text()
                response_data = {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "text": response_text,
                    "url": str(response.url),
                    "method": method,
                }

                self.logger.debug(
                    f"HTTP {method} {url} -> {response.status} " f"({len(response_text)} bytes)"
                )

                return response_data

        except asyncio.TimeoutError as e:
            self.logger.warning(f"Request timeout: {method} {url}")
            raise
        except aiohttp.ClientError as e:
            self.logger.warning(f"Client error: {method} {url} - {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error: {method} {url} - {e}")
            raise

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make POST request."""
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    @asynccontextmanager
    async def batch_requests(self):
        """
        Context manager for batch requests using the same session.

        Ensures efficient connection reuse for multiple requests.
        """
        session = await self._get_session()
        try:
            yield self
        finally:
            # Session cleanup is handled by the pool
            pass

    async def test_connectivity(
        self, urls: List[str], timeout_per_request: float = 15.0
    ) -> Dict[str, Dict[str, Any]]:
        """
        Test connectivity to multiple URLs concurrently.

        Args:
            urls: List of URLs to test
            timeout_per_request: Timeout per individual request

        Returns:
            Dictionary mapping URLs to response data
        """

        async def test_single_url(url: str) -> tuple[str, Dict[str, Any]]:
            try:
                # Override timeout for this specific test
                original_timeout = self.config.connection_timeout
                self.config.connection_timeout = timeout_per_request

                response = await self.get(url)
                return url, {
                    "success": True,
                    "status": response["status"],
                    "response_time": 0,  # Could be enhanced with timing
                    "error": None,
                }
            except Exception as e:
                return url, {
                    "success": False,
                    "status": 0,
                    "response_time": timeout_per_request,
                    "error": str(e),
                }
            finally:
                # Restore original timeout
                self.config.connection_timeout = original_timeout

        # Execute requests concurrently
        tasks = [test_single_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        connectivity_results = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Connectivity test error: {result}")
                continue

            url, data = result
            connectivity_results[url] = data

        return connectivity_results

    def get_pool_stats(self) -> Dict[str, Any]:
        """
        Get connection pool statistics.

        Returns:
            Dictionary with pool statistics
        """
        if self._session is None or self._session.closed:
            return {
                "active": False,
                "total_connections": 0,
                "available_connections": 0,
                "max_connections": self.config.max_connections,
                "max_per_host": self.config.max_connections_per_host,
            }

        connector = self._session.connector
        if hasattr(connector, "_conns"):
            total_connections = sum(len(conns) for conns in connector._conns.values())
            return {
                "active": True,
                "total_connections": total_connections,
                "max_connections": self.config.max_connections,
                "max_per_host": self.config.max_connections_per_host,
            }

        return {
            "active": True,
            "total_connections": 0,
            "max_connections": self.config.max_connections,
            "max_per_host": self.config.max_connections_per_host,
        }

    async def close(self) -> None:
        """Close connection pool and cleanup resources."""
        self._closed = True

        if self._session and not self._session.closed:
            await self._session.close()
            self.logger.debug("Closed HTTP session and connection pool")

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()


# Global connection pool instance
_connection_pool: Optional[ConnectionPool] = None


def get_connection_pool() -> ConnectionPool:
    """Get global connection pool instance."""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = ConnectionPool()
    return _connection_pool
