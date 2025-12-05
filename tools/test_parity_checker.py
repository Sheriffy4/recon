#!/usr/bin/env python3
"""
Testing-Production Parity Checker

This tool helps verify that production mode uses the same packet sending
functions and parameters as testing mode.

Usage:
    python tools/test_parity_checker.py --domain www.youtube.com --strategy multisplit
    python tools/test_parity_checker.py --check-all
    python tools/test_parity_checker.py --summary
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
from core.unified_bypass_engine import UnifiedBypassEngine, UnifiedEngineConfig


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )


def check_parity(domain: str, strategy_type: str, verbose: bool = False):
    """
    Check testing-production parity for a specific domain and strategy.
    
    Args:
        domain: Domain name to test
        strategy_type: Type of strategy to test
        verbose: Enable verbose logging
    """
    setup_logging(verbose)
    logger = logging.getLogger("ParityChecker")
    
    logger.info(f"=" * 80)
    logger.info(f"TESTING-PRODUCTION PARITY CHECK")
    logger.info(f"=" * 80)
    logger.info(f"Domain: {domain}")
    logger.info(f"Strategy: {strategy_type}")
    logger.info(f"=" * 80)
    
    try:
        # Create unified bypass engine
        config = UnifiedEngineConfig(debug=verbose)
        engine = UnifiedBypassEngine(config)
        
        # Test in testing mode
        logger.info("\n📊 Step 1: Testing in TESTING mode...")
        test_result = engine.test_strategy_like_testing_mode(
            target_ip="142.250.185.206",  # Example IP for www.youtube.com
            strategy_input={"type": strategy_type, "params": {"split_pos": 3, "split_count": 8}},
            domain=domain,
            timeout=10.0
        )
        
        if test_result.get("success"):
            logger.info("✅ Testing mode: SUCCESS")
        else:
            logger.error(f"❌ Testing mode: FAILED - {test_result.get('error', 'Unknown error')}")
        
        # Simulate production mode (would normally be done by recon_service.py)
        logger.info("\n📊 Step 2: Simulating PRODUCTION mode...")
        logger.info("   (In real scenario, this would be recon_service.py applying the strategy)")
        
        # Compare modes
        logger.info("\n📊 Step 3: Comparing TESTING vs PRODUCTION modes...")
        comparison = engine.engine.compare_testing_production_parity(
            strategy_type=strategy_type,
            domain=domain
        )
        
        if "error" in comparison:
            logger.error(f"❌ Comparison failed: {comparison['error']}")
            if "recommendation" in comparison:
                logger.info(f"💡 Recommendation: {comparison['recommendation']}")
            return False
        
        # Display comparison results
        logger.info("\n" + "=" * 80)
        logger.info("COMPARISON RESULTS")
        logger.info("=" * 80)
        
        if comparison.get("identical"):
            logger.info("✅ PARITY VERIFIED: Testing and production modes are identical")
        else:
            logger.error("❌ PARITY FAILED: Differences detected between modes")
            logger.error(f"\nNumber of differences: {len(comparison.get('differences', []))}")
            
            for diff in comparison.get("differences", []):
                severity = diff.get("severity", "unknown")
                diff_type = diff.get("type", "unknown")
                testing_val = diff.get("testing")
                production_val = diff.get("production")
                
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢"
                }.get(severity, "⚪")
                
                logger.error(f"\n{severity_icon} {severity.upper()} - {diff_type}:")
                logger.error(f"   Testing:    {testing_val}")
                logger.error(f"   Production: {production_val}")
        
        logger.info("\n" + "=" * 80)
        
        return comparison.get("identical", False)
        
    except Exception as e:
        logger.error(f"❌ Parity check failed: {e}", exc_info=verbose)
        return False


def show_summary(verbose: bool = False):
    """
    Show summary of all testing-production parity comparisons.
    
    Args:
        verbose: Enable verbose logging
    """
    setup_logging(verbose)
    logger = logging.getLogger("ParityChecker")
    
    try:
        # Create unified bypass engine
        config = UnifiedEngineConfig(debug=verbose)
        engine = UnifiedBypassEngine(config)
        
        # Get summary
        summary = engine.engine.get_testing_production_parity_summary()
        
        if "error" in summary:
            logger.error(f"❌ Failed to get summary: {summary['error']}")
            return
        
        logger.info("=" * 80)
        logger.info("TESTING-PRODUCTION PARITY SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total comparisons: {summary.get('total_comparisons', 0)}")
        logger.info(f"Identical: {summary.get('identical_count', 0)}")
        logger.info(f"Mismatches: {summary.get('mismatch_count', 0)}")
        logger.info(f"Parity percentage: {summary.get('parity_percentage', 0):.1f}%")
        logger.info("=" * 80)
        
        # Show details of each comparison
        for i, comp in enumerate(summary.get('comparisons', []), 1):
            status = "✅ PASS" if comp.get('identical') else "❌ FAIL"
            logger.info(f"\n{i}. {status} - {comp.get('strategy_type')} ({comp.get('domain', 'unknown')})")
            
            if not comp.get('identical'):
                logger.info(f"   Differences: {len(comp.get('differences', []))}")
                for diff in comp.get('differences', []):
                    logger.info(f"   - {diff.get('type')}: {diff.get('severity')}")
        
    except Exception as e:
        logger.error(f"❌ Failed to show summary: {e}", exc_info=verbose)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Check testing-production parity for DPI bypass strategies"
    )
    
    parser.add_argument(
        "--domain",
        help="Domain name to test"
    )
    
    parser.add_argument(
        "--strategy",
        help="Strategy type to test (e.g., multisplit, fakeddisorder)"
    )
    
    parser.add_argument(
        "--check-all",
        action="store_true",
        help="Check parity for all configured domains"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show summary of all parity checks"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.summary:
        show_summary(args.verbose)
    elif args.domain and args.strategy:
        success = check_parity(args.domain, args.strategy, args.verbose)
        sys.exit(0 if success else 1)
    elif args.check_all:
        print("Checking all domains is not yet implemented")
        sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
