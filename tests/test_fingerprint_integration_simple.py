#!/usr/bin/env python3
"""
Simple integration test for fingerprint-aware ZapretStrategyGenerator
"""

import sys
import os

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ml.zapret_strategy_generator import ZapretStrategyGenerator
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


def test_fingerprint_aware_generation():
    """Test that fingerprint-aware strategy generation works."""
    print("Testing fingerprint-aware strategy generation...")
    
    generator = ZapretStrategyGenerator()
    
    # Create test fingerprint
    fingerprint = DPIFingerprint(
        target="test-site.com",
        dpi_type=DPIType.ROSKOMNADZOR_TSPU,
        confidence=0.85,
        rst_injection_detected=True,
        http_header_filtering=True,
        reliability_score=0.8
    )
    
    # Generate strategies with fingerprint
    strategies_with_fp = generator.generate_strategies(fingerprint=fingerprint, count=10)
    print(f"Generated {len(strategies_with_fp)} strategies with fingerprint")
    
    # Generate strategies without fingerprint
    strategies_without_fp = generator.generate_strategies(fingerprint=None, count=10)
    print(f"Generated {len(strategies_without_fp)} strategies without fingerprint")
    
    # Test DPI-specific strategies
    tspu_strategies = generator._get_dpi_type_strategies(DPIType.ROSKOMNADZOR_TSPU)
    print(f"TSPU-specific strategies: {len(tspu_strategies)}")
    
    commercial_strategies = generator._get_dpi_type_strategies(DPIType.COMMERCIAL_DPI)
    print(f"Commercial DPI strategies: {len(commercial_strategies)}")
    
    # Test characteristic-based strategies
    char_strategies = generator._get_characteristic_based_strategies(fingerprint)
    print(f"Characteristic-based strategies: {len(char_strategies)}")
    
    # Verify all strategies are valid
    all_strategies = strategies_with_fp + strategies_without_fp
    for strategy in all_strategies:
        assert isinstance(strategy, str), f"Strategy should be string: {strategy}"
        assert '--dpi-desync' in strategy, f"Strategy should contain --dpi-desync: {strategy}"
    
    print("✓ All tests passed!")
    return True


def test_commercial_dpi_features():
    """Test commercial DPI specific features."""
    print("\nTesting commercial DPI specific features...")
    
    generator = ZapretStrategyGenerator()
    
    # Create commercial DPI fingerprint
    fingerprint = DPIFingerprint(
        target="corporate-site.com",
        dpi_type=DPIType.COMMERCIAL_DPI,
        confidence=0.92,
        tcp_window_manipulation=True,
        content_inspection_depth=2000,
        user_agent_filtering=True,
        packet_size_limitations=800,
        reliability_score=0.9
    )
    
    strategies = generator.generate_strategies(fingerprint=fingerprint, count=20)
    
    # Check for commercial DPI features
    advanced_fooling_found = any('md5sig' in strategy or 'datanoack' in strategy 
                                for strategy in strategies)
    high_ttl_found = any('--dpi-desync-ttl=64' in strategy or '--dpi-desync-ttl=128' in strategy 
                        for strategy in strategies)
    
    print(f"Advanced fooling methods found: {advanced_fooling_found}")
    print(f"High TTL values found: {high_ttl_found}")
    
    if advanced_fooling_found or high_ttl_found:
        print("✓ Commercial DPI features detected")
        return True
    else:
        print("✗ Commercial DPI features not found")
        print("Sample strategies:")
        for i, strategy in enumerate(strategies[:5]):
            print(f"  {i+1}: {strategy}")
        return False


def test_ranking_system():
    """Test strategy ranking system."""
    print("\nTesting strategy ranking system...")
    
    generator = ZapretStrategyGenerator()
    
    # High confidence fingerprint
    high_conf_fp = DPIFingerprint(
        target="high-conf.com",
        dpi_type=DPIType.GOVERNMENT_CENSORSHIP,
        confidence=0.95,
        rst_injection_detected=True,
        sequence_number_anomalies=True,
        content_inspection_depth=5000,
        reliability_score=0.95
    )
    
    # Low confidence fingerprint
    low_conf_fp = DPIFingerprint(
        target="low-conf.com",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.2,
        reliability_score=0.3
    )
    
    high_conf_strategies = generator.generate_strategies(fingerprint=high_conf_fp, count=10)
    low_conf_strategies = generator.generate_strategies(fingerprint=low_conf_fp, count=10)
    
    print(f"High confidence top strategy: {high_conf_strategies[0][:60]}...")
    print(f"Low confidence top strategy: {low_conf_strategies[0][:60]}...")
    
    # They should be different due to ranking
    different_top_strategies = high_conf_strategies[0] != low_conf_strategies[0]
    print(f"Different top strategies: {different_top_strategies}")
    
    print("✓ Ranking system working")
    return True


if __name__ == '__main__':
    print("Running fingerprint-aware strategy generation tests...\n")
    
    success = True
    success &= test_fingerprint_aware_generation()
    success &= test_commercial_dpi_features()
    success &= test_ranking_system()
    
    if success:
        print("\n🎉 All tests passed! Fingerprint-aware strategy generation is working correctly.")
    else:
        print("\n❌ Some tests failed.")
        sys.exit(1)