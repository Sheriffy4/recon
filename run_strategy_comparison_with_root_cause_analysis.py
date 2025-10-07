#!/usr/bin/env python3
"""
Strategy Comparison with Root Cause Analysis

This script demonstrates how to run a complete strategy comparison between
discovery and service modes, including comprehensive root cause analysis.
"""

import sys
import logging
from pathlib import Path

# Add recon directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_comparator import StrategyComparator


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def run_comparison_for_domain(domain: str, capture_duration: int = 30):
    """
    Run complete strategy comparison with root cause analysis for a domain.
    
    Args:
        domain: Domain to analyze (e.g., 'x.com')
        capture_duration: How long to capture service mode (seconds)
    """
    print(f"Running Strategy Comparison with Root Cause Analysis")
    print(f"Domain: {domain}")
    print(f"Capture Duration: {capture_duration} seconds")
    print("="*60)
    
    try:
        # Initialize strategy comparator
        comparator = StrategyComparator("strategy_comparison_results")
        
        # Run complete comparison with root cause analysis
        print(f"Starting comprehensive analysis for {domain}...")
        results = comparator.compare_modes(domain, capture_duration)
        
        # Print summary
        print(f"\n✓ Analysis completed successfully!")
        
        # Extract key metrics
        strategy_comp = results['strategy_comparison']
        packet_comp = results['packet_comparison']
        rca = results['root_cause_analysis']
        
        print(f"\nSUMMARY:")
        print(f"  Strategy Differences: {strategy_comp['difference_count']}")
        print(f"  Packet Differences: {packet_comp['difference_count']}")
        print(f"  Root Causes Identified: {len(rca['identified_causes'])}")
        print(f"  Fix Recommendations: {len(rca['fix_recommendations'])}")
        print(f"  Overall Confidence: {rca['confidence_score']:.2f}")
        
        # Show top issues
        if rca['identified_causes']:
            print(f"\nTOP ROOT CAUSE:")
            top_cause = rca['identified_causes'][0]
            print(f"  {top_cause.get('type', 'Unknown').replace('_', ' ').title()}")
            print(f"  Severity: {top_cause.get('severity', 'unknown').upper()}")
            print(f"  Confidence: {top_cause.get('confidence', 0.0):.2f}")
        
        if rca['fix_recommendations']:
            print(f"\nTOP FIX RECOMMENDATION:")
            top_fix = rca['fix_recommendations'][0]
            print(f"  {top_fix.get('title', 'Unknown')}")
            print(f"  Priority: {top_fix.get('priority', 'unknown').upper()}")
            print(f"  Effort: {top_fix.get('estimated_effort', 'unknown').upper()}")
        
        print(f"\nResults saved to strategy_comparison_results/")
        return True
        
    except Exception as e:
        print(f"\n✗ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main function"""
    setup_logging()
    
    # Default domain for testing
    domain = "x.com"
    capture_duration = 30
    
    # Parse command line arguments if provided
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            capture_duration = int(sys.argv[2])
        except ValueError:
            print(f"Invalid capture duration: {sys.argv[2]}")
            return False
    
    print(f"Strategy Comparison Tool with Root Cause Analysis")
    print(f"Usage: {sys.argv[0]} [domain] [capture_duration_seconds]")
    print(f"Example: {sys.argv[0]} x.com 30")
    print("")
    
    # Run the comparison
    success = run_comparison_for_domain(domain, capture_duration)
    
    if success:
        print(f"\n🎉 Analysis completed successfully!")
        print(f"\nNext steps:")
        print(f"  1. Review the generated report files")
        print(f"  2. Implement the recommended fixes")
        print(f"  3. Test the fixes incrementally")
        print(f"  4. Re-run this analysis to verify improvements")
    else:
        print(f"\n❌ Analysis failed. Check the logs for details.")
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)