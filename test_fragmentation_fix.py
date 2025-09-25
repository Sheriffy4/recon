#!/usr/bin/env python3
"""
Test script to verify the fragmentation detection fix.
"""

import asyncio
import logging
from core.fingerprint.tcp_analyzer import TCPAnalyzer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_fragmentation_detection():
    """Test the fixed fragmentation detection logic."""
    
    analyzer = TCPAnalyzer(timeout=5.0)
    
    # Test domains
    test_domains = [
        ("google.com", 443),
        ("youtube.com", 443),
        ("facebook.com", 443)
    ]
    
    for domain, port in test_domains:
        logger.info(f"Testing fragmentation detection for {domain}:{port}")
        
        try:
            result = await analyzer.analyze_tcp_behavior(domain, port)
            fragmentation_result = result.get('fragmentation_handling', 'unknown')
            
            logger.info(f"  {domain}: fragmentation_handling = {fragmentation_result}")
            
            # Interpret results
            if fragmentation_result == "vulnerable":
                logger.info(f"  → {domain} is VULNERABLE to fragmentation attacks (multisplit/multidisorder should work)")
            elif fragmentation_result == "filtered":
                logger.info(f"  → {domain} FILTERS fragmentation (avoid multisplit/multidisorder)")
            else:
                logger.info(f"  → {domain} fragmentation status unknown")
                
        except Exception as e:
            logger.error(f"  Error testing {domain}: {e}")
    
    logger.info("Fragmentation detection test completed!")

if __name__ == "__main__":
    asyncio.run(test_fragmentation_detection())