#!/usr/bin/env python3
"""
Test script to verify the strategy generation uses fragmentation detection correctly.
"""

import logging
from ml.zapret_strategy_generator import ZapretStrategyGenerator
from core.fingerprint.advanced_models import DPIFingerprint, DPIType

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_strategy_generation():
    """Test that strategy generation uses fragmentation detection correctly."""
    
    generator = ZapretStrategyGenerator()
    
    # Test case 1: DPI vulnerable to fragmentation
    logger.info("=== Test 1: DPI vulnerable to fragmentation ===")
    vulnerable_fingerprint = DPIFingerprint(
        target="test-vulnerable.com:443",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.8,
        fragmentation_handling="vulnerable"
    )
    
    strategies = generator.generate_strategies(vulnerable_fingerprint, count=10)
    logger.info(f"Generated {len(strategies)} strategies for vulnerable DPI:")
    for i, strategy in enumerate(strategies[:5], 1):
        logger.info(f"  {i}. {strategy}")
        if "multisplit" in strategy or "multidisorder" in strategy:
            logger.info(f"     ✓ Contains fragmentation attack")
    
    # Test case 2: DPI filters fragmentation
    logger.info("\n=== Test 2: DPI filters fragmentation ===")
    filtered_fingerprint = DPIFingerprint(
        target="test-filtered.com:443",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.8,
        fragmentation_handling="filtered"
    )
    
    strategies = generator.generate_strategies(filtered_fingerprint, count=10)
    logger.info(f"Generated {len(strategies)} strategies for filtering DPI:")
    for i, strategy in enumerate(strategies[:5], 1):
        logger.info(f"  {i}. {strategy}")
        if "multisplit" in strategy or "multidisorder" in strategy:
            logger.info(f"     ⚠ Contains fragmentation attack (should be avoided)")
        else:
            logger.info(f"     ✓ No fragmentation attack")
    
    # Test case 3: Unknown fragmentation handling
    logger.info("\n=== Test 3: Unknown fragmentation handling ===")
    unknown_fingerprint = DPIFingerprint(
        target="test-unknown.com:443",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.8,
        fragmentation_handling="unknown"
    )
    
    strategies = generator.generate_strategies(unknown_fingerprint, count=10)
    logger.info(f"Generated {len(strategies)} strategies for unknown DPI:")
    for i, strategy in enumerate(strategies[:5], 1):
        logger.info(f"  {i}. {strategy}")

if __name__ == "__main__":
    test_strategy_generation()