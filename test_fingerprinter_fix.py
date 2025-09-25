#!/usr/bin/env python3
"""
Test script to verify fingerprinter logic fixes.
"""

import asyncio
import logging
from core.fingerprint.tcp_analyzer import TCPAnalyzer
from ml.zapret_strategy_generator import ZapretStrategyGenerator

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_tcp_analyzer():
    """Test the TCP analyzer fragmentation detection."""
    logger.info("Testing TCP analyzer fragmentation detection...")
    
    analyzer = TCPAnalyzer(timeout=5.0)
    
    # Test with a known domain
    result = await analyzer.analyze_tcp_behavior("x.com", 443)
    
    logger.info(f"TCP Analysis Result for x.com:")
    logger.info(f"  - Fragmentation handling: {result.get('fragmentation_handling', 'unknown')}")
    logger.info(f"  - RST injection detected: {result.get('rst_injection_detected', False)}")
    logger.info(f"  - TCP window manipulation: {result.get('tcp_window_manipulation', False)}")
    
    return result

def test_strategy_generator():
    """Test the strategy generator with fragmentation info."""
    logger.info("Testing strategy generator with fragmentation vulnerability...")
    
    generator = ZapretStrategyGenerator()
    
    # Create a mock fingerprint with fragmentation vulnerability
    class MockFingerprint:
        def __init__(self, fragmentation_handling):
            self.fragmentation_handling = fragmentation_handling
            self.confidence = 0.8
            self.raw_metrics = {
                'tcp_analysis': {
                    'fragmentation_handling': fragmentation_handling
                },
                'strategy_hints': ['tcp_segment_reordering']
            }
    
    # Test with vulnerable fragmentation
    vulnerable_fp = MockFingerprint("vulnerable")
    strategies_vulnerable = generator.generate_strategies(vulnerable_fp, count=10)
    
    logger.info("Strategies for vulnerable fragmentation:")
    for i, strategy in enumerate(strategies_vulnerable[:5], 1):
        logger.info(f"  {i}. {strategy}")
    
    # Test with filtered fragmentation
    filtered_fp = MockFingerprint("filtered")
    strategies_filtered = generator.generate_strategies(filtered_fp, count=10)
    
    logger.info("Strategies for filtered fragmentation:")
    for i, strategy in enumerate(strategies_filtered[:5], 1):
        logger.info(f"  {i}. {strategy}")
    
    # Check if fragmentation strategies are properly prioritized
    vulnerable_has_multisplit = any("multisplit" in s or "multidisorder" in s for s in strategies_vulnerable)
    filtered_has_multisplit = any("multisplit" in s or "multidisorder" in s for s in strategies_filtered)
    
    logger.info(f"Vulnerable fingerprint has fragmentation strategies: {vulnerable_has_multisplit}")
    logger.info(f"Filtered fingerprint has fragmentation strategies: {filtered_has_multisplit}")
    
    return strategies_vulnerable, strategies_filtered

async def main():
    """Main test function."""
    logger.info("Starting fingerprinter logic tests...")
    
    # Test TCP analyzer
    try:
        tcp_result = await test_tcp_analyzer()
    except Exception as e:
        logger.error(f"TCP analyzer test failed: {e}")
        tcp_result = None
    
    # Test strategy generator
    try:
        vulnerable_strategies, filtered_strategies = test_strategy_generator()
        logger.info("Strategy generator test completed successfully")
    except Exception as e:
        logger.error(f"Strategy generator test failed: {e}")
    
    logger.info("Fingerprinter logic tests completed")

if __name__ == "__main__":
    asyncio.run(main())