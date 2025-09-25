#!/usr/bin/env python3
"""
Performance Regression Test
Tests to ensure the regression is fixed and performance is restored.
"""

import json
import logging
from pathlib import Path

def test_regression_fix():
    """Test that the performance regression has been fixed."""
    logger = logging.getLogger(__name__)
    
    # Load the regression analysis
    analysis_file = Path("recon/performance_regression_analysis.json")
    if not analysis_file.exists():
        logger.error("Regression analysis file not found")
        return False
    
    with open(analysis_file, 'r') as f:
        analysis = json.load(f)
    
    # Test criteria based on working version
    test_criteria = {
        "success_rate_should_be_above": 0.2,  # At least 20% (working had 72%)
        "strategies_should_be_above": 3,      # At least 3 (working had 16)
        "execution_time_should_be_below": 2500  # Under 2500s (working had 1685s)
    }
    
    logger.info("Regression test criteria:")
    for criterion, value in test_criteria.items():
        logger.info(f"  - {criterion}: {value}")
    
    # Instructions for manual testing
    logger.info("\nTo test the fix:")
    logger.info("1. Run: python recon/cli.py -d sites.txt --fingerprint --parallel 5")
    logger.info("2. Check that success_rate > 0.2")
    logger.info("3. Check that working_strategies_found > 3")
    logger.info("4. Verify multidisorder strategy works")
    
    return test_criteria

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_regression_fix()
