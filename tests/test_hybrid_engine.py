import unittest
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio

# Pytest is not used for execution, so mark can be removed.
# import pytest

from core.hybrid_engine import HybridEngine

class TestHybridEngine(unittest.TestCase):

    def setUp(self):
        # We need to mock the modern bypass engine components to avoid import errors if they aren't installed
        with patch('core.hybrid_engine.MODERN_BYPASS_ENGINE_AVAILABLE', False):
             self.engine = HybridEngine(debug=True, enable_modern_bypass=False)

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
        # This test remains largely the same but ensures async calls are handled correctly.
        mock_kb_instance = MockKnowledgeBase.return_value
        self.engine.knowledge_base = mock_kb_instance
        self.engine.enhanced_tracking = True

        mock_capturer = MagicMock()
        mock_capturer.pcap_file = "test.pcap"
        pcap_metrics = {'strategy1': {'tls_clienthellos': 10, 'tls_serverhellos': 8}}
        mock_capturer.analyze_pcap_file.return_value = pcap_metrics

        dns_cache = {'example.com': '1.2.3.4'}
        domain = 'example.com'

        async def run_test():
            # Mock the real-world execution to isolate the metrics logic
            with patch.object(self.engine, 'execute_strategy_real_world', AsyncMock(return_value=('ALL_SITES_WORKING', 1, 1, 10.0, {}, {}))):
                await self.engine.test_strategies_hybrid(
                    strategies=["--dpi-desync=fake"],
                    test_sites=["https://example.com"],
                    ips={"1.2.3.4"},
                    dns_cache=dns_cache,
                    port=443,
                    domain=domain,
                    capturer=mock_capturer
                )

        asyncio.run(run_test())

        mock_capturer.analyze_pcap_file.assert_called_with("test.pcap")
        mock_kb_instance.update_quic_metrics.assert_called_once()
        args, kwargs = mock_kb_instance.update_quic_metrics.call_args
        self.assertEqual(args[0], 'example.com')
        self.assertEqual(args[1], '1.2.3.4')
        self.assertAlmostEqual(args[2], 0.8)
        mock_kb_instance.save.assert_called_once()

    @patch('core.hybrid_engine.ECHDetector')
    def test_prepend_quic_strategies_on_signal(self, MockECHDetector):
        """Test that QUIC strategies are prepended when QUIC/ECH signals are detected."""

        # Mock ECHDetector to return positive signals
        mock_detector = MockECHDetector.return_value
        mock_detector.detect_ech_dns = AsyncMock(return_value={"ech_present": True})
        mock_detector.probe_quic = AsyncMock(return_value={"success": True})
        mock_detector.probe_http3 = AsyncMock(return_value=True)

        # Mock knowledge base to avoid side effects
        self.engine.knowledge_base.get_recommendations = MagicMock(return_value={})

        base_strategies = ["--dpi-desync=fake"]

        # This list will capture the strategies as they are passed to the mock
        called_strategies_list = []

        async def fake_execute_strategy(strategy, *args, **kwargs):
            """A side effect function to capture the strategy argument."""
            called_strategies_list.append(strategy)
            # Return a standard success tuple
            return ('ALL_SITES_WORKING', 1, 1, 10.0, {}, {})

        async def run_test():
            # Use the side effect to capture arguments instead of inspecting call_args_list
            with patch.object(self.engine, 'execute_strategy_real_world', side_effect=fake_execute_strategy):
                await self.engine.test_strategies_hybrid(
                    strategies=base_strategies.copy(),
                    test_sites=["https://example.com"],
                    ips={"1.2.3.4"},
                    dns_cache={'example.com': '1.2.3.4'},
                    port=443,
                    domain="example.com"
                )

        asyncio.run(run_test())

        # Assertions
        expected_quic_strat1 = {'type': 'quic_fragmentation', 'params': {'fragment_size': 300, 'add_version_negotiation': True}}
        expected_quic_strat2 = {'type': 'quic_fragmentation', 'params': {'fragment_size': 200}}

        # Check that the strategies are present in the list of called strategies
        self.assertIn(expected_quic_strat1, called_strategies_list)
        self.assertIn(expected_quic_strat2, called_strategies_list)
        self.assertIn("--dpi-desync=fake", called_strategies_list)

        # Check the relative order
        quic1_idx = called_strategies_list.index(expected_quic_strat1)
        base_idx = called_strategies_list.index("--dpi-desync=fake")
        self.assertLess(quic1_idx, base_idx, "QUIC strategy should be tested before the base strategy")


if __name__ == '__main__':
    unittest.main()
