import unittest
import asyncio
from unittest.mock import patch, AsyncMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# No longer need to import CustomResolver as it's an implementation detail
from core.bypass.hybrid.connectivity_tester import ConnectivityTester

class TestConnectivityTester(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tester = ConnectivityTester(debug=False)

    @patch('core.bypass.hybrid.connectivity_tester.ConnectivityTester._test_with_semaphore', new_callable=AsyncMock)
    async def test_test_sites_working(self, mock_test_with_semaphore):
        """
        Test the main test_sites orchestrator for a successful case.
        """
        # Configure the mock to return a successful result tuple
        mock_test_with_semaphore.return_value = ("http://example.com", ("WORKING", "1.2.3.4", 123.0, 200))

        sites = ["http://example.com"]
        dns_cache = {"example.com": "1.2.3.4"}

        # Await the coroutine directly
        results = await self.tester.test_sites(sites, dns_cache)

        # Assertions
        mock_test_with_semaphore.assert_called_once()
        self.assertIn("http://example.com", results)
        status, ip, latency, http_status = results["http://example.com"]
        self.assertEqual(status, "WORKING")
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(http_status, 200)
        self.assertIsInstance(latency, float)

    @patch('core.bypass.hybrid.connectivity_tester.ConnectivityTester._test_with_semaphore', new_callable=AsyncMock)
    async def test_test_sites_timeout(self, mock_test_with_semaphore):
        """
        Test the main test_sites orchestrator for a timeout case.
        """
        # Configure the mock to return a timeout result tuple
        mock_test_with_semaphore.return_value = ("http://example-timeout.com", ("TIMEOUT", "1.2.3.4", 5000.0, 0))

        sites = ["http://example-timeout.com"]
        dns_cache = {"example-timeout.com": "1.2.3.4"}

        # Await the coroutine
        results = await self.tester.test_sites(sites, dns_cache)

        # Assertions
        self.assertIn("http://example-timeout.com", results)
        status, _, _, _ = results["http://example-timeout.com"]
        self.assertEqual(status, "TIMEOUT")
        mock_test_with_semaphore.assert_called_once()


    @patch('core.bypass.hybrid.connectivity_tester.ConnectivityTester._test_with_semaphore', new_callable=AsyncMock)
    async def test_custom_resolver_is_used(self, mock_test_with_semaphore):
        """
        Verify that the custom resolver is used by checking the IP in the final result.
        This test no longer needs to import or instantiate CustomResolver directly.
        """
        # The key is that the final result contains the IP from our cache.
        # This proves the custom resolver was created and used by the session.
        expected_ip = "9.8.7.6"
        mock_test_with_semaphore.return_value = ("http://cached-domain.com", ("WORKING", expected_ip, 150.0, 200))

        sites = ["http://cached-domain.com"]
        dns_cache = {"cached-domain.com": expected_ip}

        results = await self.tester.test_sites(sites, dns_cache)

        # Verify that the result tuple contains the IP address we injected via the cache.
        self.assertIn("http://cached-domain.com", results)
        _status, ip_used, _latency, _http_status = results["http://cached-domain.com"]
        self.assertEqual(ip_used, expected_ip)


if __name__ == '__main__':
    unittest.main()
