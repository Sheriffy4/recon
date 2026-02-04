"""Health checking module for monitoring system connectivity."""

import asyncio
import time
from typing import Optional, Tuple

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None


class HealthChecker:
    """Проверяет доступность сайтов."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.session = None

    async def __aenter__(self):
        if AIOHTTP_AVAILABLE:
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_http_connectivity(
        self, domain: str, port: int = 443, use_https: bool = True
    ) -> Tuple[bool, float, Optional[str]]:
        """Проверяет HTTP/HTTPS доступность."""
        if not AIOHTTP_AVAILABLE or not self.session:
            return await self.check_tcp_connectivity(domain, port)
        protocol = "https" if use_https else "http"
        url = (
            f"{protocol}://{domain}:{port}"
            if port != (443 if use_https else 80)
            else f"{protocol}://{domain}"
        )
        start_time = time.time()
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                response_time = (time.time() - start_time) * 1000
                return (response.status < 400, response_time, None)
        except asyncio.TimeoutError:
            return (False, (time.time() - start_time) * 1000, "Timeout")
        except Exception as e:
            if AIOHTTP_AVAILABLE and "aiohttp" in str(type(e)):
                return (False, (time.time() - start_time) * 1000, str(e))
            else:
                return (False, (time.time() - start_time) * 1000, f"HTTP Error: {e}")

    async def check_tcp_connectivity(
        self, domain: str, port: int
    ) -> Tuple[bool, float, Optional[str]]:
        """Проверяет TCP доступность."""
        start_time = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            response_time = (time.time() - start_time) * 1000
            return (True, response_time, None)
        except asyncio.TimeoutError:
            return (False, (time.time() - start_time) * 1000, "TCP Timeout")
        except ConnectionRefusedError:
            return (False, (time.time() - start_time) * 1000, "Connection Refused")
        except Exception as e:
            return (False, (time.time() - start_time) * 1000, f"TCP Error: {e}")
