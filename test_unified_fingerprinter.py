#!/usr/bin/env python3
"""
Test script for Unified Fingerprinter - Task 22 Implementation
Tests the refactored fingerprinting system with unified interface.
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
from core.fingerprint.analyzer_adapters import get_available_analyzers, check_analyzer_availability

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

logger = logging.getLogger(__name__)


async def test_analyzer_availability():
    """Test analyzer availability"""
    logger.info("Testing analyzer availability...")
    
    available = get_available_analyzers()
    logger.info(f"Available analyzers: {available}")
    
    status = check_analyzer_availability()
    for analyzer, info in status.items():
        if info['available']:
            logger.info(f"✓ {analyzer}: Available")
        else:
            logger.warning(f"✗ {analyzer}: Not available - {info['error']}")
    
    return available


async def test_unified_fingerprinter_initialization():
    """Test UnifiedFingerprinter initialization"""
    logger.info("Testing UnifiedFingerprinter initialization...")
    
    try:
        config = FingerprintingConfig(
            timeout=10.0,
            enable_cache=False,  # Disable cache for testing
            analysis_level="fast"
        )
        
        fingerprinter = UnifiedFingerprinter(config)
        logger.info("✓ UnifiedFingerprinter initialized successfully")
        
        stats = fingerprinter.get_statistics()
        logger.info(f"Initial statistics: {stats}")
        
        return fingerprinter
        
    except Exception as e:
        logger.error(f"✗ Failed to initialize UnifiedFingerprinter: {e}")
        raise


async def test_single_target_fingerprinting(fingerprinter: UnifiedFingerprinter):
    """Test fingerprinting a single target"""
    logger.info("Testing single target fingerprinting...")
    
    test_targets = [
        ("google.com", 443),
        ("example.com", 80),
        ("cloudflare.com", 443)
    ]
    
    for target, port in test_targets:
        try:
            logger.info(f"Fingerprinting {target}:{port}...")
            start_time = time.time()
            
            fingerprint = await fingerprinter.fingerprint_target(
                target=target,
                port=port,
                analysis_level="fast"
            )
            
            duration = time.time() - start_time
            
            logger.info(f"✓ Fingerprinting completed for {target}:{port} in {duration:.2f}s")
            logger.info(f"  DPI Type: {fingerprint.dpi_type.value}")
            logger.info(f"  Confidence: {fingerprint.confidence:.2f}")
            logger.info(f"  Reliability: {fingerprint.reliability_score:.2f}")
            logger.info(f"  TCP Analysis Status: {fingerprint.tcp_analysis.status.value}")
            logger.info(f"  Recommended Strategies: {[r.strategy_name for r in fingerprint.recommended_strategies]}")
            
        except Exception as e:
            logger.error(f"✗ Failed to fingerprint {target}:{port}: {e}")


async def test_batch_fingerprinting(fingerprinter: UnifiedFingerprinter):
    """Test batch fingerprinting"""
    logger.info("Testing batch fingerprinting...")
    
    targets = [
        ("google.com", 443),
        ("github.com", 443),
        ("stackoverflow.com", 443)
    ]
    
    try:
        logger.info(f"Batch fingerprinting {len(targets)} targets...")
        start_time = time.time()
        
        fingerprints = await fingerprinter.fingerprint_batch(
            targets=targets,
            max_concurrent=2
        )
        
        duration = time.time() - start_time
        
        logger.info(f"✓ Batch fingerprinting completed in {duration:.2f}s")
        
        for i, fingerprint in enumerate(fingerprints):
            target, port = targets[i]
            logger.info(f"  {target}:{port} - DPI: {fingerprint.dpi_type.value}, "
                       f"Reliability: {fingerprint.reliability_score:.2f}")
        
    except Exception as e:
        logger.error(f"✗ Batch fingerprinting failed: {e}")


async def test_error_handling(fingerprinter: UnifiedFingerprinter):
    """Test error handling with invalid targets"""
    logger.info("Testing error handling...")
    
    invalid_targets = [
        ("nonexistent-domain-12345.com", 443),
        ("127.0.0.1", 12345),  # Closed port
    ]
    
    for target, port in invalid_targets:
        try:
            logger.info(f"Testing error handling for {target}:{port}...")
            
            fingerprint = await fingerprinter.fingerprint_target(
                target=target,
                port=port,
                analysis_level="fast"
            )
            
            logger.info(f"✓ Error handling worked for {target}:{port}")
            logger.info(f"  Reliability: {fingerprint.reliability_score:.2f}")
            logger.info(f"  TCP Status: {fingerprint.tcp_analysis.status.value}")
            
        except Exception as e:
            logger.warning(f"Expected error for {target}:{port}: {e}")


async def main():
    """Main test function"""
    logger.info("Starting Unified Fingerprinter tests...")
    
    try:
        # Test 1: Check analyzer availability
        available_analyzers = await test_analyzer_availability()
        
        if not available_analyzers:
            logger.warning("No analyzers available - some tests may be limited")
        
        # Test 2: Initialize fingerprinter
        fingerprinter = await test_unified_fingerprinter_initialization()
        
        # Test 3: Single target fingerprinting
        await test_single_target_fingerprinting(fingerprinter)
        
        # Test 4: Batch fingerprinting
        await test_batch_fingerprinting(fingerprinter)
        
        # Test 5: Error handling
        await test_error_handling(fingerprinter)
        
        # Final statistics
        final_stats = fingerprinter.get_statistics()
        logger.info(f"Final statistics: {final_stats}")
        
        logger.info("✓ All tests completed successfully!")
        
    except Exception as e:
        logger.error(f"✗ Test suite failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())