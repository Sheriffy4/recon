#!/usr/bin/env python3
"""
Test script for root cause analysis functionality.

This script demonstrates the root cause analysis capabilities for strategy
and packet differences between discovery and service modes.
"""

import json
import logging
import sys
from pathlib import Path

# Add recon directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_comparator import (
    StrategyComparator, StrategyDifference, PacketDifference,
    StrategyComparison, PacketComparison, RootCauseAnalyzer
)


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_test_strategy_differences():
    """Create test strategy differences for analysis"""
    return [
        StrategyDifference(
            parameter='desync_method',
            discovery_value='multidisorder',
            service_value='fakeddisorder',
            is_critical=True
        ),
        StrategyDifference(
            parameter='ttl',
            discovery_value=None,  # autottl
            service_value=1,
            is_critical=True
        ),
        StrategyDifference(
            parameter='split_pos',
            discovery_value=46,
            service_value=1,
            is_critical=False
        ),
        StrategyDifference(
            parameter='overlap_size',
            discovery_value=1,
            service_value=0,
            is_critical=False
        ),
        StrategyDifference(
            parameter='repeats',
            discovery_value=2,
            service_value=1,
            is_critical=False
        ),
        StrategyDifference(
            parameter='fooling',
            discovery_value=['badseq'],
            service_value=['badsum', 'badseq'],
            is_critical=True
        )
    ]


def create_test_packet_differences():
    """Create test packet differences for analysis"""
    return [
        PacketDifference(
            packet_index=0,
            field='ttl',
            discovery_value=3,
            service_value=1,
            is_critical=True
        ),
        PacketDifference(
            packet_index=0,
            field='flags',
            discovery_value='SA',
            service_value='S',
            is_critical=True
        ),
        PacketDifference(
            packet_index=1,
            field='payload_len',
            discovery_value=46,
            service_value=1,
            is_critical=False
        ),
        PacketDifference(
            packet_index=1,
            field='seq',
            discovery_value=1000,
            service_value=1001,
            is_critical=False
        )
    ]


def test_root_cause_analysis():
    """Test root cause analysis functionality"""
    print("Testing Root Cause Analysis...")
    
    # Create test data
    strategy_differences = create_test_strategy_differences()
    packet_differences = create_test_packet_differences()
    
    # Create comparison objects
    strategy_comparison = StrategyComparison(
        domain='x.com',
        timestamp='20251006_120000',
        discovery_strategy='--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
        service_strategy='--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq --dpi-desync-split-pos=1',
        differences=strategy_differences,
        strategies_match=False
    )
    
    packet_comparison = PacketComparison(
        domain='x.com',
        timestamp='20251006_120000',
        discovery_pcap='discovery_x.com_20251006_120000.pcap',
        service_pcap='service_x.com_20251006_120000.pcap',
        discovery_packet_count=3,
        service_packet_count=2,
        differences=packet_differences,
        packets_match=False,
        timing_differences={'avg_discovery_delay_ms': 1.5, 'avg_service_delay_ms': 0.8}
    )
    
    # Perform root cause analysis
    analyzer = RootCauseAnalyzer()
    analysis = analyzer.analyze_root_causes(strategy_comparison, packet_comparison)
    
    # Print results
    print(f"\nRoot Cause Analysis Results for {analysis.domain}:")
    print(f"Confidence Score: {analysis.confidence_score:.2f}")
    print(f"Causes Identified: {len(analysis.identified_causes)}")
    print(f"Fix Recommendations: {len(analysis.fix_recommendations)}")
    print(f"Code Locations: {len(analysis.code_locations)}")
    
    # Print identified causes
    print("\nIdentified Causes:")
    for i, cause in enumerate(analysis.identified_causes, 1):
        print(f"{i}. {cause.get('type', 'Unknown').replace('_', ' ').title()}")
        print(f"   Severity: {cause.get('severity', 'unknown').upper()}")
        print(f"   Confidence: {cause.get('confidence', 0.0):.2f}")
        print(f"   Component: {cause.get('component', 'unknown')}")
    
    # Print fix recommendations
    print("\nFix Recommendations:")
    for i, fix in enumerate(analysis.fix_recommendations, 1):
        print(f"{i}. {fix.get('title', 'Unknown Fix')}")
        print(f"   Priority: {fix.get('priority', 'unknown').upper()}")
        print(f"   Effort: {fix.get('estimated_effort', 'unknown').upper()}")
        
        action_items = fix.get('action_items', [])
        if action_items:
            print("   Action Items:")
            for item in action_items[:3]:  # Show first 3
                print(f"     • {item}")
            if len(action_items) > 3:
                print(f"     ... and {len(action_items) - 3} more")
    
    # Generate and print full report
    print("\n" + "="*80)
    print("FULL ROOT CAUSE ANALYSIS REPORT")
    print("="*80)
    report = analyzer.generate_report(analysis)
    print(report)
    
    # Save results to file
    output_dir = Path("strategy_comparison_results")
    output_dir.mkdir(exist_ok=True)
    
    # Save JSON results
    json_file = output_dir / "test_root_cause_analysis.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(analysis.to_dict(), f, indent=2, default=str)
    print(f"\nResults saved to: {json_file}")
    
    # Save text report
    report_file = output_dir / "test_root_cause_analysis_report.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"Report saved to: {report_file}")
    
    return analysis


def test_strategy_comparator():
    """Test the full strategy comparator with root cause analysis"""
    print("\nTesting Strategy Comparator...")
    
    # Initialize comparator
    comparator = StrategyComparator("test_comparison_results")
    
    # Note: This would normally run actual discovery and service mode captures
    # For testing, we'll simulate the process
    print("Note: Full strategy comparison requires running discovery and service modes")
    print("This test demonstrates the root cause analysis component only")
    
    return True


def main():
    """Main test function"""
    setup_logging()
    
    print("Root Cause Analysis Test Suite")
    print("="*50)
    
    try:
        # Test root cause analysis
        analysis = test_root_cause_analysis()
        
        # Test strategy comparator
        test_strategy_comparator()
        
        print("\n✓ All tests completed successfully!")
        print(f"\nKey findings from analysis:")
        print(f"- {len(analysis.identified_causes)} root causes identified")
        print(f"- {len(analysis.fix_recommendations)} actionable fixes generated")
        print(f"- Overall confidence: {analysis.confidence_score:.2f}")
        
        # Show top recommendations
        if analysis.fix_recommendations:
            print(f"\nTop fix recommendation:")
            top_fix = analysis.fix_recommendations[0]
            print(f"  {top_fix.get('title', 'Unknown')}")
            print(f"  Priority: {top_fix.get('priority', 'unknown').upper()}")
            print(f"  Files to modify: {len(top_fix.get('files_to_modify', []))}")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)