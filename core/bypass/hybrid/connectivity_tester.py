"""Connectivity testing component for hybrid engine."""

import asyncio
import aiohttp
import ssl
import socket
import time
import random
import logging
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


class ConnectivityTester:
    """
    Handles asynchronous connectivity testing for sites.
    Tests with custom DNS resolution and retry logic.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger(self.__class__.__name__)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    async def test_sites(
        self,
        sites: List[str],
        dns_cache: Dict[str, str],
        max_concurrent: int = 10,
        retries: int = 0,
        backoff_base: float = 0.4,
        timeout_profile: str = "balanced",
        connect_timeout: Optional[float] = None,
        sock_read_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Test connectivity to multiple sites.

        Returns:
            Dict mapping site URL to (status, ip_used, latency_ms, http_status)
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        # Create custom resolver
        resolver = self._create_resolver(dns_cache)

        # Create SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Create connector
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit_per_host=5,
            resolver=resolver
        )

        # Get timeout configuration
        client_timeout = self._make_timeouts(
            timeout_profile,
            connect_timeout,
            sock_read_timeout,
            total_timeout
        )

        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [
                    self._test_with_semaphore(
                        session, site, dns_cache, semaphore,
                        client_timeout, retries, backoff_base, timeout_profile
                    )
                    for site in sites
                ]
                task_results = await asyncio.gather(*tasks)

                for site, result_tuple in task_results:
                    results[site] = result_tuple
        finally:
            try:
                await connector.close()
            except Exception:
                pass

        return results

    def _create_resolver(self, dns_cache: Dict[str, str]):
        """Create custom DNS resolver with cache."""

        class CustomResolver(aiohttp.resolver.AsyncResolver):
            def __init__(self, cache):
                super().__init__()
                self._custom_cache = cache

            async def resolve(self, host, port, family=socket.AF_INET):
                if host in self._custom_cache:
                    ip = self._custom_cache[host]
                    return [{
                        'hostname': host,
                        'host': ip,
                        'port': port,
                        'family': family,
                        'proto': 0,
                        'flags': 0
                    }]
                return await super().resolve(host, port, family)

        return CustomResolver(dns_cache)

    def _make_timeouts(
        self,
        profile: str,
        connect_timeout: Optional[float],
        sock_read_timeout: Optional[float],
        total_timeout: Optional[float]
    ) -> aiohttp.ClientTimeout:
        """Create timeout configuration."""
        presets = {
            "fast": {"connect": 5.0, "sock_read": 8.0, "total": 15.0},
            "balanced": {"connect": 8.0, "sock_read": 15.0, "total": 25.0},
            "slow": {"connect": 12.0, "sock_read": 25.0, "total": 40.0},
        }

        p = presets.get(profile, presets["balanced"]).copy()

        if connect_timeout is not None:
            p["connect"] = float(connect_timeout)
        if sock_read_timeout is not None:
            p["sock_read"] = float(sock_read_timeout)
        if total_timeout is not None:
            p["total"] = float(total_timeout)

        return aiohttp.ClientTimeout(
            total=p["total"],
            connect=p["connect"],
            sock_read=p["sock_read"]
        )

    async def _test_with_semaphore(
        self,
        session: aiohttp.ClientSession,
        site: str,
        dns_cache: Dict[str, str],
        semaphore: asyncio.Semaphore,
        client_timeout: aiohttp.ClientTimeout,
        retries: int,
        backoff_base: float,
        timeout_profile: str
    ) -> Tuple[str, Tuple[str, str, float, int]]:
        """Test single site with semaphore and retry logic."""
        async with semaphore:
            hostname = urlparse(site).hostname or site
            ip_used = dns_cache.get(hostname, 'N/A')
            attempt = 0

            while True:
                start_time = time.time()

                try:
                    # Escalate timeout profile on retries
                    if attempt > 0:
                        client_timeout = self._make_timeouts("slow", None, None, None)

                    async with session.get(
                        site,
                        headers=self.headers,
                        allow_redirects=True,
                        timeout=client_timeout
                    ) as response:
                        # Read a bit of data to ensure connection works
                        await response.content.readexactly(1)
                        latency = (time.time() - start_time) * 1000
                        return (site, ('WORKING', ip_used, latency, response.status))

                except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError) as e:
                    latency = (time.time() - start_time) * 1000

                    # Check if it's a RST
                    if self._is_rst_error(e):
                        self.logger.debug(f'Connectivity test for {site} -> RST')
                        return (site, ('RST', ip_used, latency, 0))

                    # Retry logic
                    if attempt < retries:
                        delay = backoff_base * (2 ** attempt) + random.uniform(0.0, 0.2)
                        self.logger.debug(f'Retry {attempt+1}/{retries} for {site} in {delay:.2f}s')
                        await asyncio.sleep(delay)
                        attempt += 1
                        continue

                    self.logger.debug(f'Connectivity test for {site} failed with TIMEOUT')
                    return (site, ('TIMEOUT', ip_used, latency, 0))

                except Exception as e:
                    latency = (time.time() - start_time) * 1000
                    self.logger.debug(f'Unexpected error testing {site}: {e}')
                    return (site, ('ERROR', ip_used, latency, 0))

    def _is_rst_error(self, e: BaseException) -> bool:
        """Check if error is a connection reset."""
        msg = str(e) if e else ""
        rep = repr(e)
        return (
            isinstance(e, ConnectionResetError) or
            "ECONNRESET" in rep or
            "Connection reset" in msg or
            isinstance(e, getattr(aiohttp, "ServerDisconnectedError", type(None)))
        )
