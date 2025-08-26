#!/usr/bin/env python3
"""
Test suite for fingerprint-aware ZapretStrategyGenerator - Task 13 Implementation
Tests DPI-type-specific strategy generation, confidence-based ranking, and fallback mechanisms.
"""

import unittest
import sys
import os

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from ml.zapret_strategy_generator import ZapretStrategyGenerator
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
        ConfidenceLevel,
    )
except ImportError:
    # Fallback for different import paths
    from ml.zapret_strategy_generator import ZapretStrategyGenerator
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
    )


class TestZapretStrategyGeneratorFingerprint(unittest.TestCase):
    """Test fingerprint-aware strategy generation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = ZapretStrategyGenerator()

        # Create test fingerprints for different DPI types
        self.roskomnadzor_tspu_fingerprint = DPIFingerprint(
            target="blocked-site.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
            http_header_filtering=True,
            dns_hijacking_detected=False,
            reliability_score=0.8,
        )

        self.commercial_dpi_fingerprint = DPIFingerprint(
            target="corporate-site.com",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.92,
            tcp_window_manipulation=True,
            content_inspection_depth=2000,
            user_agent_filtering=True,
            packet_size_limitations=800,
            reliability_score=0.9,
        )

        self.government_censorship_fingerprint = DPIFingerprint(
            target="censored-site.com",
            dpi_type=DPIType.GOVERNMENT_CENSORSHIP,
            confidence=0.95,
            rst_injection_detected=True,
            sequence_number_anomalies=True,
            content_inspection_depth=5000,
            doh_blocking=True,
            dot_blocking=True,
            geographic_restrictions=True,
            reliability_score=0.95,
        )

        self.low_confidence_fingerprint = DPIFingerprint(
            target="unknown-site.com",
            dpi_type=DPIType.UNKNOWN,
            confidence=0.3,
            reliability_score=0.4,
        )

    def test_generate_strategies_with_fingerprint(self):
        """Test strategy generation with DPI fingerprint."""
        strategies = self.generator.generate_strategies(
            fingerprint=self.roskomnadzor_tspu_fingerprint, count=10
        )

        self.assertEqual(len(strategies), 10)
        self.assertIsInstance(strategies, list)

        # All strategies should be strings
        for strategy in strategies:
            self.assertIsInstance(strategy, str)
            self.assertIn("--dpi-desync", strategy)

    def test_generate_strategies_without_fingerprint(self):
        """Test fallback to generic strategies when fingerprint is None."""
        strategies = self.generator.generate_strategies(fingerprint=None, count=15)

        self.assertEqual(len(strategies), 15)
        self.assertIsInstance(strategies, list)

        # Should contain proven working strategies
        proven_found = any(
            strategy in self.generator.PROVEN_WORKING for strategy in strategies
        )
        self.assertTrue(proven_found, "Should include proven working strategies")

    def test_dpi_type_specific_strategies(self):
        """Test that different DPI types generate different strategies."""
        tspu_strategies = self.generator.generate_strategies(
            fingerprint=self.roskomnadzor_tspu_fingerprint, count=20
        )

        commercial_strategies = self.generator.generate_strategies(
            fingerprint=self.commercial_dpi_fingerprint, count=20
        )

        government_strategies = self.generator.generate_strategies(
            fingerprint=self.government_censorship_fingerprint, count=20
        )

        # Strategies should be different for different DPI types
        self.assertNotEqual(set(tspu_strategies), set(commercial_strategies))
        self.assertNotEqual(set(commercial_strategies), set(government_strategies))
        self.assertNotEqual(set(tspu_strategies), set(government_strategies))

    def test_get_dpi_type_strategies(self):
        """Test DPI-type-specific strategy templates."""
        # Test ROSKOMNADZOR_TSPU strategies
        tspu_strategies = self.generator._get_dpi_type_strategies(
            DPIType.ROSKOMNADZOR_TSPU
        )
        self.assertIsInstance(tspu_strategies, list)
        self.assertGreater(len(tspu_strategies), 0)

        # Test COMMERCIAL_DPI strategies
        commercial_strategies = self.generator._get_dpi_type_strategies(
            DPIType.COMMERCIAL_DPI
        )
        self.assertIsInstance(commercial_strategies, list)
        self.assertGreater(len(commercial_strategies), 0)

        # Test GOVERNMENT_CENSORSHIP strategies
        gov_strategies = self.generator._get_dpi_type_strategies(
            DPIType.GOVERNMENT_CENSORSHIP
        )
        self.assertIsInstance(gov_strategies, list)
        self.assertGreater(len(gov_strategies), 0)

        # Strategies should be different
        self.assertNotEqual(set(tspu_strategies), set(commercial_strategies))
        self.assertNotEqual(set(commercial_strategies), set(gov_strategies))

    def test_characteristic_based_strategies(self):
        """Test strategy generation based on DPI characteristics."""
        # Test RST injection characteristic
        rst_strategies = self.generator._get_characteristic_based_strategies(
            self.roskomnadzor_tspu_fingerprint
        )
        self.assertIsInstance(rst_strategies, list)

        # Should contain strategies with low TTL for RST injection
        low_ttl_found = any(
            "--dpi-desync-ttl=1" in strategy or "--dpi-desync-ttl=2" in strategy
            for strategy in rst_strategies
        )
        self.assertTrue(
            low_ttl_found, "Should include low TTL strategies for RST injection"
        )

        # Test deep content inspection characteristic
        deep_inspection_strategies = (
            self.generator._get_characteristic_based_strategies(
                self.commercial_dpi_fingerprint
            )
        )

        # Should contain aggressive segmentation for deep inspection
        multisplit_found = any(
            "multisplit" in strategy for strategy in deep_inspection_strategies
        )
        self.assertTrue(
            multisplit_found, "Should include multisplit for deep content inspection"
        )

    def test_confidence_based_ranking(self):
        """Test that strategies are ranked by confidence and relevance."""
        # High confidence fingerprint should have more targeted strategies at the top
        high_conf_strategies = self.generator.generate_strategies(
            fingerprint=self.commercial_dpi_fingerprint, count=10
        )

        # Low confidence fingerprint should fall back to more generic strategies
        low_conf_strategies = self.generator.generate_strategies(
            fingerprint=self.low_confidence_fingerprint, count=10
        )

        # High confidence should have different (more targeted) top strategies
        self.assertNotEqual(high_conf_strategies[0], low_conf_strategies[0])

    def test_strategy_complexity_calculation(self):
        """Test strategy complexity calculation."""
        simple_strategy = "--dpi-desync=fake --dpi-desync-ttl=5"
        complex_strategy = "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,3,5,7,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1 --dpi-desync-repeats=5"

        simple_complexity = self.generator._calculate_strategy_complexity(
            simple_strategy
        )
        complex_complexity = self.generator._calculate_strategy_complexity(
            complex_strategy
        )

        self.assertLess(simple_complexity, complex_complexity)
        self.assertGreaterEqual(simple_complexity, 0.0)
        self.assertLessEqual(complex_complexity, 1.0)

    def test_strategy_aggressiveness_calculation(self):
        """Test strategy aggressiveness calculation."""
        mild_strategy = "--dpi-desync=fake --dpi-desync-ttl=64"
        aggressive_strategy = "--dpi-desync=fake,multidisorder --dpi-desync-ttl=1 --dpi-desync-repeats=5 --dpi-desync-split-count=7"

        mild_aggressiveness = self.generator._calculate_strategy_aggressiveness(
            mild_strategy
        )
        aggressive_aggressiveness = self.generator._calculate_strategy_aggressiveness(
            aggressive_strategy
        )

        self.assertLess(mild_aggressiveness, aggressive_aggressiveness)
        self.assertGreaterEqual(mild_aggressiveness, 0.0)
        self.assertLessEqual(aggressive_aggressiveness, 1.0)

    def test_strategy_ranking_logic(self):
        """Test the strategy ranking algorithm."""
        test_strategies = [
            "--dpi-desync=fake --dpi-desync-ttl=5",  # Simple strategy
            "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=2",  # Complex strategy
            "--dpi-desync=fake --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=5",  # Medium strategy
        ]

        ranked_strategies = self.generator._rank_strategies_by_confidence(
            test_strategies, self.commercial_dpi_fingerprint
        )

        self.assertEqual(len(ranked_strategies), len(test_strategies))
        self.assertIsInstance(ranked_strategies, list)

        # All original strategies should be present
        self.assertEqual(set(ranked_strategies), set(test_strategies))

    def test_fingerprint_aware_vs_generic_strategies(self):
        """Test that fingerprint-aware strategies differ from generic ones."""
        fingerprint_strategies = self.generator._generate_fingerprint_aware_strategies(
            self.government_censorship_fingerprint, 15
        )

        generic_strategies = self.generator._generate_generic_strategies(15)

        # Should have some different strategies
        overlap = set(fingerprint_strategies) & set(generic_strategies)
        self.assertLess(
            len(overlap), min(len(fingerprint_strategies), len(generic_strategies))
        )

    def test_government_censorship_specific_strategies(self):
        """Test strategies specific to government censorship DPI."""
        strategies = self.generator.generate_strategies(
            fingerprint=self.government_censorship_fingerprint, count=20
        )

        # Should contain very aggressive strategies for government censorship
        very_low_ttl_found = any(
            "--dpi-desync-ttl=1" in strategy for strategy in strategies
        )
        high_repeats_found = any(
            "--dpi-desync-repeats=" in strategy
            and int(strategy.split("--dpi-desync-repeats=")[1].split()[0]) >= 3
            for strategy in strategies
            if "--dpi-desync-repeats=" in strategy
        )

        self.assertTrue(
            very_low_ttl_found, "Should include very low TTL for government censorship"
        )
        self.assertTrue(
            high_repeats_found, "Should include high repeats for government censorship"
        )

    def test_commercial_dpi_specific_strategies(self):
        """Test strategies specific to commercial DPI systems."""
        strategies = self.generator.generate_strategies(
            fingerprint=self.commercial_dpi_fingerprint, count=15
        )

        # Should contain strategies with md5sig or datanoack fooling for commercial DPI
        advanced_fooling_found = any(
            "md5sig" in strategy or "datanoack" in strategy for strategy in strategies
        )

        # Should contain strategies with higher TTL values (64, 128)
        high_ttl_found = any(
            "--dpi-desync-ttl=64" in strategy or "--dpi-desync-ttl=128" in strategy
            for strategy in strategies
        )

        self.assertTrue(
            advanced_fooling_found or high_ttl_found,
            "Should include commercial DPI specific techniques",
        )

    def test_packet_size_limitation_strategies(self):
        """Test strategies for DPI with packet size limitations."""
        strategies = self.generator._get_characteristic_based_strategies(
            self.commercial_dpi_fingerprint  # Has packet_size_limitations=800
        )

        # Should contain fine-grained segmentation for packet size limitations
        fine_segmentation_found = any(
            "--dpi-desync-split-count=6" in strategy
            or "--dpi-desync-split-pos=1,2,3,4,5" in strategy
            for strategy in strategies
        )

        self.assertTrue(
            fine_segmentation_found,
            "Should include fine segmentation for packet size limitations",
        )

    def test_dns_blocking_strategies(self):
        """Test strategies for DPI with DNS blocking capabilities."""
        strategies = self.generator._get_characteristic_based_strategies(
            self.government_censorship_fingerprint  # Has DoH/DoT blocking
        )

        # Should contain aggressive strategies for DNS blocking bypass
        aggressive_found = any(
            "multidisorder" in strategy or "multisplit" in strategy
            for strategy in strategies
        )

        self.assertTrue(
            aggressive_found, "Should include aggressive strategies for DNS blocking"
        )

    def test_empty_fingerprint_fallback(self):
        """Test behavior with minimal fingerprint data."""
        minimal_fingerprint = DPIFingerprint(
            target="minimal-site.com", dpi_type=DPIType.UNKNOWN, confidence=0.0
        )

        strategies = self.generator.generate_strategies(
            fingerprint=minimal_fingerprint, count=10
        )

        self.assertEqual(len(strategies), 10)

        # Should still generate valid strategies
        for strategy in strategies:
            self.assertIsInstance(strategy, str)
            self.assertIn("--dpi-desync", strategy)

    def test_strategy_count_limits(self):
        """Test that requested strategy count is respected."""
        for count in [5, 10, 15, 25, 50]:
            strategies = self.generator.generate_strategies(
                fingerprint=self.roskomnadzor_tspu_fingerprint, count=count
            )
            self.assertEqual(
                len(strategies), count, f"Should generate exactly {count} strategies"
            )

    def test_strategy_uniqueness(self):
        """Test that generated strategies are unique."""
        strategies = self.generator.generate_strategies(
            fingerprint=self.commercial_dpi_fingerprint, count=30
        )

        unique_strategies = set(strategies)
        self.assertEqual(
            len(strategies),
            len(unique_strategies),
            "All generated strategies should be unique",
        )


class TestZapretStrategyGeneratorIntegration(unittest.TestCase):
    """Integration tests for fingerprint-aware strategy generation."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.generator = ZapretStrategyGenerator()

    def test_full_workflow_high_confidence(self):
        """Test complete workflow with high confidence fingerprint."""
        fingerprint = DPIFingerprint(
            target="test-site.com",
            dpi_type=DPIType.ROSKOMNADZOR_DPI,
            confidence=0.9,
            rst_injection_detected=True,
            http_header_filtering=True,
            content_inspection_depth=1500,
            dns_hijacking_detected=True,
            reliability_score=0.85,
        )

        strategies = self.generator.generate_strategies(
            fingerprint=fingerprint, count=20
        )

        # Verify output quality
        self.assertEqual(len(strategies), 20)
        self.assertTrue(all(isinstance(s, str) for s in strategies))
        self.assertTrue(all("--dpi-desync" in s for s in strategies))

        # Should prioritize strategies relevant to the fingerprint
        relevant_strategies = 0
        for strategy in strategies[:5]:  # Check top 5 strategies
            if any(
                keyword in strategy
                for keyword in ["fake", "multidisorder", "badsum", "badseq"]
            ):
                relevant_strategies += 1

        self.assertGreaterEqual(
            relevant_strategies,
            3,
            "Top strategies should be relevant to DPI characteristics",
        )

    def test_full_workflow_low_confidence(self):
        """Test complete workflow with low confidence fingerprint."""
        fingerprint = DPIFingerprint(
            target="uncertain-site.com",
            dpi_type=DPIType.UNKNOWN,
            confidence=0.2,
            reliability_score=0.3,
        )

        strategies = self.generator.generate_strategies(
            fingerprint=fingerprint, count=15
        )

        # Should still generate valid strategies
        self.assertEqual(len(strategies), 15)
        self.assertTrue(all(isinstance(s, str) for s in strategies))

        # Should include proven working strategies due to low confidence
        proven_included = any(
            strategy in self.generator.PROVEN_WORKING for strategy in strategies
        )
        self.assertTrue(
            proven_included, "Should include proven strategies for low confidence"
        )

    def test_performance_with_large_strategy_count(self):
        """Test performance with large strategy count requests."""
        fingerprint = DPIFingerprint(
            target="performance-test.com",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.8,
            reliability_score=0.7,
        )

        import time

        start_time = time.time()

        strategies = self.generator.generate_strategies(
            fingerprint=fingerprint, count=100
        )

        end_time = time.time()
        execution_time = end_time - start_time

        # Should complete within reasonable time (less than 5 seconds)
        self.assertLess(
            execution_time, 5.0, "Should generate 100 strategies within 5 seconds"
        )
        self.assertEqual(len(strategies), 100)
        self.assertEqual(len(set(strategies)), 100, "All strategies should be unique")


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
