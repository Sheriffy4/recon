# recon/core/bypass/attacks/domain_tester.py
"""
Real Domain Accessibility Tester

Uses aiohttp to perform real HTTP requests to test domain accessibility
and measure actual network latency. Replaces basic socket testing.
"""

import asyncio
import aiohttp
import time
import logging
import ssl
from typing import Optional, Tuple, Dict, Any
from .base import AttackContext, AttackResult, AttackStatus

LOG = logging.getLogger("DomainTester")


class DomainTester:
    """
    Tests real domain accessibility using HTTP requests.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.logger = LOG
        self.session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None or self.session.closed:
            # Create SSL context that doesn't verify certificates (for testing)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=10,
                limit_per_host=5,
                ttl_dns_cache=300,
                use_dns_cache=True,
            )

            timeout = aiohttp.ClientTimeout(total=self.timeout)

            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                },
            )

        return self.session

    async def test_domain_accessibility(
        self, domain: str, use_https: bool = True
    ) -> Tuple[bool, float, Optional[str], Optional[Dict]]:
        """
        Test domain accessibility using HTTP request.

        Args:
            domain: Domain name to test
            use_https: Whether to use HTTPS (default) or HTTP

        Returns:
            Tuple of (success, latency_ms, error_message, response_info)
        """
        start_time = time.time()

        try:
            session = await self._get_session()

            # Construct URL
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{domain}/"

            # Make request
            async with session.get(url) as response:
                # Read some response data to ensure full connection
                content = await response.read()

                latency_ms = (time.time() - start_time) * 1000

                response_info = {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "content_length": len(content),
                    "url": str(response.url),
                    "content_preview": (
                        content[:200].decode("utf-8", errors="ignore")
                        if content
                        else ""
                    ),
                }

                # Check if response indicates blocking
                success = self._analyze_response_for_blocking(response, content)

                return success, latency_ms, None, response_info

        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, "Request timeout", None

        except aiohttp.ClientError as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, f"HTTP client error: {e}", None

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, f"Unexpected error: {e}", None

    def _analyze_response_for_blocking(
        self, response: aiohttp.ClientResponse, content: bytes
    ) -> bool:
        """
        Analyze HTTP response to detect DPI blocking.

        Args:
            response: aiohttp response object
            content: Response content bytes

        Returns:
            True if domain appears accessible, False if blocked
        """
        # Check status code
        if response.status in [200, 301, 302, 303, 307, 308]:
            # These are generally good status codes
            pass
        elif response.status in [403, 451, 444]:
            # These often indicate blocking
            return False
        elif response.status >= 500:
            # Server errors might indicate blocking or server issues
            return False

        # Check content for blocking indicators
        if content:
            content_str = content.decode("utf-8", errors="ignore").lower()

            # Common blocking indicators
            blocking_indicators = [
                "blocked",
                "forbidden",
                "access denied",
                "dpi",
                "censored",
                "restricted",
                "not available",
                "blocked by",
                "access restricted",
                "this site is blocked",
                "site blocked",
                "content blocked",
            ]

            for indicator in blocking_indicators:
                if indicator in content_str:
                    return False

            # Check for very short responses that might indicate blocking
            if len(content) < 100 and response.status != 204:
                return False

        # Check headers for blocking indicators
        server_header = response.headers.get("Server", "").lower()
        if any(
            block_server in server_header
            for block_server in ["block", "filter", "proxy"]
        ):
            return False

        return True

    async def test_domain_with_bypass(
        self, context: AttackContext
    ) -> Tuple[bool, float, Optional[str], Optional[Dict]]:
        """
        Test domain accessibility with bypass strategy applied.

        This is a placeholder for now - in a real implementation, this would
        apply the actual bypass strategy during the HTTP request.

        Args:
            context: Attack context with domain and strategy info

        Returns:
            Tuple of (success, latency_ms, error_message, response_info)
        """
        # For now, just test the domain normally
        # In a real implementation, this would apply the bypass strategy
        use_https = context.dst_port == 443 or (
            context.domain and "https" in context.domain
        )

        return await self.test_domain_accessibility(context.domain, use_https)

    async def compare_blocked_vs_unblocked(self, domain: str) -> Dict[str, Any]:
        """
        Compare domain accessibility with and without bypass.

        Args:
            domain: Domain to test

        Returns:
            Dictionary with comparison results
        """
        # Test without bypass (baseline)
        baseline_success, baseline_latency, baseline_error, baseline_info = (
            await self.test_domain_accessibility(domain)
        )

        # Test with bypass (for now, same as baseline - would be different in real implementation)
        bypass_success, bypass_latency, bypass_error, bypass_info = (
            await self.test_domain_accessibility(domain)
        )

        return {
            "domain": domain,
            "baseline": {
                "success": baseline_success,
                "latency_ms": baseline_latency,
                "error": baseline_error,
                "info": baseline_info,
            },
            "bypass": {
                "success": bypass_success,
                "latency_ms": bypass_latency,
                "error": bypass_error,
                "info": bypass_info,
            },
            "bypass_effective": bypass_success and not baseline_success,
            "improvement": (
                bypass_latency - baseline_latency
                if baseline_success and bypass_success
                else 0
            ),
        }

    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()

    def __del__(self):
        """Cleanup on deletion."""
        if self.session and not self.session.closed:
            # Schedule cleanup
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.session.close())
            except:
                pass


async def test_domain_accessibility_async(
    domain: str, timeout: float = 10.0
) -> Tuple[bool, float, Optional[str]]:
    """
    Async function to test domain accessibility.

    Args:
        domain: Domain to test
        timeout: Request timeout in seconds

    Returns:
        Tuple of (success, latency_ms, error_message)
    """
    tester = DomainTester(timeout=timeout)
    try:
        success, latency, error, _ = await tester.test_domain_accessibility(domain)
        return success, latency, error
    finally:
        await tester.close()


def test_domain_accessibility_sync(
    domain: str, timeout: float = 10.0
) -> Tuple[bool, float, Optional[str]]:
    """
    Synchronous wrapper for domain accessibility testing.

    Args:
        domain: Domain to test
        timeout: Request timeout in seconds

    Returns:
        Tuple of (success, latency_ms, error_message)
    """
    try:
        # Try to get existing event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, we need to use a different approach
            # This is a limitation when called from sync code in an async context
            import concurrent.futures
            import threading

            def run_in_thread():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    return new_loop.run_until_complete(
                        test_domain_accessibility_async(domain, timeout)
                    )
                finally:
                    new_loop.close()

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(run_in_thread)
                return future.result(timeout=timeout + 5)
        else:
            # No loop running, we can use it directly
            return loop.run_until_complete(
                test_domain_accessibility_async(domain, timeout)
            )
    except:
        # Fallback: create new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                test_domain_accessibility_async(domain, timeout)
            )
        finally:
            loop.close()
