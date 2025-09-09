import unittest
from unittest.mock import MagicMock, patch
import asyncio

from core.hybrid_engine import HybridEngine

class TestHybridEngine(unittest.TestCase):

    def setUp(self):
        self.engine = HybridEngine(debug=True)

    def test_ensure_engine_task_desync_alias(self):
        """Test that 'desync' strategy is correctly aliased to 'fakeddisorder'."""
        strategy_str = "desync(split_pos=10, overlap_size=20)"
        task = self.engine._ensure_engine_task(strategy_str)
        self.assertIsNotNone(task)
        self.assertEqual(task['type'], 'fakeddisorder')
        self.assertEqual(task['params']['split_pos'], 10)

    def test_ensure_engine_task_quic_fragmentation_zapret(self):
        """Test translation of zapret-style --quic-frag flag."""
        strategy_str = "--quic-frag=100"
        task = self.engine._ensure_engine_task(strategy_str)
        self.assertIsNotNone(task)
        self.assertEqual(task['type'], 'quic_fragmentation')
        self.assertEqual(task['params']['fragment_size'], 100)

    def test_ensure_engine_task_quic_fragmentation_dsl(self):
        """Test translation of DSL-style quic_fragmentation."""
        strategy_dict = {'type': 'quic_fragmentation', 'params': {'fragment_size': 88}}
        task = self.engine._ensure_engine_task(strategy_dict)
        self.assertIsNotNone(task)
        self.assertEqual(task['type'], 'quic_fragmentation')
        self.assertEqual(task['params']['fragment_size'], 88)

    @patch('core.hybrid_engine.CdnAsnKnowledgeBase')
    def test_update_quic_metrics_called(self, MockKnowledgeBase):
        """Test that knowledge_base.update_quic_metrics is called after pcap analysis."""

        # Setup mocks
        mock_kb_instance = MockKnowledgeBase.return_value
        self.engine.knowledge_base = mock_kb_instance
        self.engine.enhanced_tracking = True

        mock_capturer = MagicMock()
        mock_capturer.pcap_file = "test.pcap"
        # Simulate pcap analysis result
        pcap_metrics = {
            'strategy1': {'tls_clienthellos': 10, 'tls_serverhellos': 8}
        }
        mock_capturer.analyze_pcap_file.return_value = pcap_metrics

        dns_cache = {'example.com': '1.2.3.4'}
        domain = 'example.com'

        # Run the method under test (simplified async call)
        async def run_test():
            await self.engine.test_strategies_hybrid(
                strategies=["--dpi-desync=fake"],
                test_sites=["https://example.com"],
                ips={"1.2.3.4"},
                dns_cache=dns_cache,
                port=443,
                domain=domain,
                capturer=mock_capturer
            )

        # Mock the actual test execution to isolate the metrics part
        with patch.object(self.engine, 'execute_strategy_real_world', return_value=('ALL_SITES_WORKING', 1, 1, 10.0, {}, {})):
            asyncio.run(run_test())

        # Assertions
        mock_capturer.analyze_pcap_file.assert_called_with("test.pcap")
        mock_kb_instance.update_quic_metrics.assert_called_once()

        # Check arguments of the call
        args, kwargs = mock_kb_instance.update_quic_metrics.call_args
        self.assertEqual(args[0], 'example.com')
        self.assertEqual(args[1], '1.2.3.4')
        self.assertAlmostEqual(args[2], 0.8) # 8 SH / 10 CH

        mock_kb_instance.save.assert_called_once()

    @patch('core.hybrid_engine.ECHDetector')
    def test_prepend_quic_strategies_on_signal(self, MockECHDetector):
        """Test that QUIC strategies are prepended when QUIC/ECH signals are detected."""

        # Mock ECHDetector to return positive signals
        mock_ech_detector_instance = MockECHDetector.return_value

        async def detect_ech_dns(domain):
            return {"ech_present": True}
        mock_ech_detector_instance.detect_ech_dns = detect_ech_dns

        async def probe_quic(domain, port, timeout):
            return {"success": True}
        mock_ech_detector_instance.probe_quic = probe_quic

        async def probe_http3(domain, port, timeout):
            return True
        mock_ech_detector_instance.probe_http3 = probe_http3

        base_strategies = ["--dpi-desync=fake"]

        async def run_test():
            with patch.object(self.engine, 'execute_strategy_real_world', return_value=('ALL_SITES_WORKING', 1, 1, 10.0, {}, {})) as mock_execute:
                await self.engine.test_strategies_hybrid(
                    strategies=base_strategies.copy(),
                    test_sites=["https://example.com"],
                    ips={"1.2.3.4"},
                    dns_cache={'example.com': '1.2.3.4'},
                    port=443,
                    domain="example.com"
                )

                self.assertTrue(mock_execute.called)

                called_strategies = [call[0][0] for call in mock_execute.call_args_list]

                expected_quic_strat1 = {'type': 'quic_fragmentation', 'params': {'fragment_size': 300, 'add_version_negotiation': True}}
                expected_quic_strat2 = {'type': 'quic_fragmentation', 'params': {'fragment_size': 200}}

                # Check that the first two strategies are the prepended QUIC ones
                self.assertEqual(called_strategies[0], expected_quic_strat1)
                self.assertEqual(called_strategies[1], expected_quic_strat2)
                # Check that the original strategy is still there
                self.assertIn("--dpi-desync=fake", called_strategies)

        asyncio.run(run_test())

if __name__ == '__main__':
    unittest.main()
