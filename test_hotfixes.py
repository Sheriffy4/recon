import sys
import unittest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock

# Mock pydivert at the module level for initial imports
sys.modules['pydivert'] = MagicMock()
sys.modules['pydivert.windivert'] = MagicMock()

# Now, we can safely import our modules
from core.hybrid_engine import HybridEngine
from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
from core.bypass.techniques.primitives import BypassTechniques
from core.fingerprint.unified_fingerprinter import FingerprintingConfig

class TestFakesniInjection(unittest.TestCase):

    def setUp(self):
        self.hybrid_engine = HybridEngine(debug=True)

    def test_fakesni_auto_injection_on_fakeddisorder(self):
        strategy_str = "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badsum"
        engine_task = self.hybrid_engine._ensure_engine_task(strategy_str)
        self.assertIsNotNone(engine_task)
        fooling_params = engine_task.get('params', {}).get('fooling', [])
        self.assertIn('fakesni', fooling_params)
        self.assertIn('badsum', fooling_params)

    def test_fakesni_generation_in_primitives(self):
        with patch('core.bypass.techniques.primitives._gen_fake_sni', return_value="random.edu") as mock_gen_sni:
            recipe = BypassTechniques.apply_fake_packet_race(b'payload', fooling=['fakesni', 'badsum'])
            mock_gen_sni.assert_called_once()
            self.assertTrue(len(recipe) > 0)
            fake_packet_opts = recipe[0][2]
            self.assertTrue(fake_packet_opts.get('is_fake'))
            self.assertEqual(fake_packet_opts.get('fooling_sni'), "random.edu")

@patch('platform.system', return_value='Windows')
class TestBadsumAndTtlLogic(unittest.TestCase):

    def setUp(self):
        config = EngineConfig(debug=True)
        self.engine = WindowsBypassEngine(config)
        self.engine._packet_sender = MagicMock()

    def test_badsum_and_ttl_only_for_fake_packets(self, mock_platform):
        recipe = [
            (b'fake', 0, {'is_fake': True, 'ttl': 5, 'corrupt_tcp_checksum': True}),
            (b'real', 0, {'is_fake': False, 'ttl': 10, 'corrupt_tcp_checksum': True})
        ]
        specs = self.engine._recipe_to_specs(recipe, payload=b'')
        final_specs = []
        for sp in specs:
            if not getattr(sp, "is_fake", False):
                sp.ttl = None
                sp.corrupt_tcp_checksum = False
            final_specs.append(sp)

        self.assertEqual(len(final_specs), 2)
        self.assertEqual(final_specs[0].ttl, 5)
        self.assertTrue(final_specs[0].corrupt_tcp_checksum)
        self.assertIsNone(final_specs[1].ttl)
        self.assertFalse(final_specs[1].corrupt_tcp_checksum)

@patch('platform.system', return_value='Windows')
class TestDelayLogic(unittest.TestCase):

    def setUp(self):
        config = EngineConfig(debug=True)
        self.engine = WindowsBypassEngine(config)

    def test_delay_logic(self, mock_platform):
        recipe = [
            (b'seg1', 0, {'delay_ms': 10}),
            (b'seg2', 10, {'delay_ms_after': 20}),
            (b'seg3', 20, {'delay_ms': 30})
        ]
        specs = self.engine._recipe_to_specs(recipe, payload=b'')
        self.assertEqual(len(specs), 3)
        self.assertEqual(specs[0].delay_ms_after, 10)
        self.assertEqual(specs[1].delay_ms_after, 20)
        self.assertEqual(specs[2].delay_ms_after, 0)

@patch('core.fingerprint.unified_fingerprinter.FALLBACK_COMPONENTS_AVAILABLE', True)
@patch('core.fingerprint.unified_fingerprinter.HybridEngine', create=True)
@patch('core.fingerprint.unified_fingerprinter.DoHResolver', create=True)
@patch('core.fingerprint.unified_fingerprinter.build_json_report', create=True)
@patch('core.fingerprint.unified_fingerprinter.RSTTriggerAnalyzer', create=True)
class TestPcapFallbackLogic(unittest.TestCase):

    def test_pcap_fallback_with_universal_strategies(self, mock_rst, mock_report, mock_doh, mock_engine, mock_flag):
        from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter

        mock_rst.return_value.analyze.return_value = [{'trigger': True}]
        mock_report.return_value = {"incidents": []}
        mock_doh.return_value.resolve = AsyncMock(return_value="1.2.3.4")
        mock_engine.return_value.test_strategies_hybrid = AsyncMock(return_value=[])

        config = FingerprintingConfig(debug=True)
        fingerprinter = UnifiedFingerprinter(config)

        async def run_test():
            return await fingerprinter._run_pcap_fallback_pass(
                target="test.com", port=443, pcap_path="/fake/path.pcap"
            )

        asyncio.run(run_test())

        mock_engine.return_value.test_strategies_hybrid.assert_called_once()
        call_kwargs = mock_engine.return_value.test_strategies_hybrid.call_args.kwargs
        strategies_tested = call_kwargs.get('strategies', [])
        self.assertTrue(len(strategies_tested) > 0)
        self.assertIn(
            "--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-ttl=8",
            strategies_tested
        )

if __name__ == '__main__':
    unittest.main()