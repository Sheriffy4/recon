import json
import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add project root to path to allow imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
    from web.monitoring_server import MonitoringWebServer, AIOHTTP_AVAILABLE
except ImportError:
    AIOHTTP_AVAILABLE = False

# Skip tests if aiohttp is not available
@unittest.skipIf(not AIOHTTP_AVAILABLE, "aiohttp not installed")
class TestMonitoringServerAPI(AioHTTPTestCase):

    async def get_application(self):
        """
        This is the required method for AioHTTPTestCase.
        It should return an aiohttp.web.Application instance.
        """
        # Mock the monitoring system dependency, it's not used by the /api/quic endpoint
        mock_monitoring_system = MagicMock()
        server = MonitoringWebServer(monitoring_system=mock_monitoring_system)

        # We need to patch the CdnAsnKnowledgeBase where it's imported from
        self.mock_kb_patch = patch('core.knowledge.cdn_asn_db.CdnAsnKnowledgeBase')
        self.MockKnowledgeBase = self.mock_kb_patch.start()

        # Configure the mock instance that will be created inside the handler
        self.mock_kb_instance = self.MockKnowledgeBase.return_value
        # Use a new MagicMock for the attribute to avoid issues with it being a class member
        self.mock_kb_instance.domain_quic_scores = MagicMock()

        # Important: stop the patch during cleanup
        self.addCleanup(self.mock_kb_patch.stop)

        # The app must be created after patching
        app = server.create_app()
        return app

    @unittest_run_loop
    async def test_api_quic_success(self):
        """Test the /api/quic endpoint for successful data retrieval."""
        # Set the return value for this specific test
        self.mock_kb_instance.domain_quic_scores = {'example.com': 0.75, 'test.com': 0.5}

        resp = await self.client.get("/api/quic")
        self.assertEqual(resp.status, 200)
        data = await resp.json()

        self.assertIn("domain_quic_scores", data)
        self.assertEqual(data["domain_quic_scores"], {'example.com': 0.75, 'test.com': 0.5})
        self.assertEqual(data["note"], "PCAP-derived ServerHello/ClientHello ratio")

    @unittest_run_loop
    async def test_api_quic_kb_error(self):
        """Test the /api/quic endpoint when the knowledge base raises an error on instantiation."""
        # Configure the mock to raise an exception when instantiated
        self.MockKnowledgeBase.side_effect = Exception("Failed to load KB")

        resp = await self.client.get("/api/quic")
        self.assertEqual(resp.status, 200) # The handler catches the exception and returns 200
        data = await resp.json()

        self.assertIn("error", data)
        self.assertEqual(data["error"], "Failed to load KB")
        self.assertEqual(data["domain_quic_scores"], {})

if __name__ == '__main__':
    # This allows running the test file directly
    if AIOHTTP_AVAILABLE:
        unittest.main()
    else:
        print("Skipping tests: aiohttp is not installed.")
