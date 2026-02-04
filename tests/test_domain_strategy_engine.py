import unittest
from types import SimpleNamespace
from unittest.mock import patch


class TestDomainStrategyEngineMemoryview(unittest.TestCase):
    def test_payload_memoryview_is_converted_to_bytes(self):
        # Late import so patches apply cleanly
        with patch(
            "core.bypass.engine.domain_strategy_engine.SNIDomainExtractor"
        ) as ExtractorCls, patch(
            "core.bypass.engine.domain_strategy_engine.HierarchicalDomainMatcher"
        ) as MatcherCls, patch(
            "core.bypass.engine.domain_strategy_engine.RuntimeIPResolver"
        ), patch(
            "core.bypass.engine.domain_strategy_engine.StrategyApplicationLogger"
        ) as AppLoggerCls, patch(
            "core.bypass.engine.domain_strategy_engine.ParentDomainRecommender"
        ) as ParentRecCls, patch(
            "core.bypass.engine.domain_strategy_engine.StrategyFailureTracker"
        ) as FailureTrackerCls:

            extractor_instance = ExtractorCls.return_value
            seen = {"payload": None}

            def _extract(payload):
                seen["payload"] = payload
                return SimpleNamespace(domain="example.com", source="tls_sni")

            extractor_instance.extract_from_payload.side_effect = _extract

            matcher_instance = MatcherCls.return_value
            matcher_instance.find_matching_rule.return_value = (
                {"type": "fake", "params": {}},
                "example.com",
                "exact",
            )

            # Stubs for auxiliary components
            AppLoggerCls.return_value.log_strategy_application.return_value = None
            AppLoggerCls.return_value.log_strategy_failure.return_value = None
            ParentRecCls.return_value.reload_domain_rules.return_value = None
            FailureTrackerCls.return_value._load_failure_data.return_value = None

            from core.bypass.engine.domain_strategy_engine import DomainStrategyEngine

            engine = DomainStrategyEngine(
                domain_rules={"example.com": {"type": "fake", "params": {}}},
                default_strategy={"type": "passthrough", "params": {}},
                enable_ip_resolution=False,
                domain_rules_path="nonexistent.json",
            )

            class P:
                dst_addr = "1.2.3.4"
                dst_port = 443
                payload = memoryview(b"\x16\x03\x01\x00\x2a")  # arbitrary bytes

            res = engine.get_strategy_for_packet(P())
            self.assertEqual(res.domain, "example.com")
            self.assertIsInstance(seen["payload"], (bytes, type(None)))
            self.assertEqual(seen["payload"], bytes(P.payload))


if __name__ == "__main__":
    unittest.main()
