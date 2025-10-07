#!/usr/bin/env python3
"""
X.com Root Cause Analysis Demo

This script demonstrates root cause analysis specifically for x.com bypass issues,
correlating strategy and packet differences to identify actionable fixes.
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime

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
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def create_x_com_strategy_differences():
    """Create realistic x.com strategy differences based on known issues"""
    return [
        # Critical: multidisorder mapped to fakeddisorder
        StrategyDifference(
            parameter='desync_method',
            discovery_value='multidisorder',
            service_value='fakeddisorder',
            is_critical=True
        ),
        
        # Critical: autottl not implemented, using fixed TTL
        StrategyDifference(
            parameter='autottl',
            discovery_value=2,
            service_value=None,
            is_critical=True
        ),
        StrategyDifference(
            parameter='ttl',
            discovery_value=None,  # Should be calculated
            service_value=1,       # Fixed value used instead
            is_critical=True
        ),
        
        # High: Wrong split position
        StrategyDifference(
            parameter='split_pos',
            discovery_value=46,
            service_value=1,
            is_critical=False
        ),
        
        # Medium: Sequence overlap not implemented
        StrategyDifference(
            parameter='overlap_size',
            discovery_value=1,
            service_value=0,
            is_critical=False
        ),
        
        # Medium: Repeats not implemented
        StrategyDifference(
            parameter='repeats',
            discovery_value=2,
            service_value=1,
            is_critical=False
        ),
        
        # High: Fooling method differs
        StrategyDifference(
            parameter='fooling',
            discovery_value=['badseq'],
            service_value=['badsum', 'badseq'],
            is_critical=True
        )
    ]


def create_x_com_packet_differences():
    """Create realistic x.com packet differences based on PCAP analysis"""
    return [
        # Critical: Fake packet has wrong TTL
        PacketDifference(
            packet_index=0,
            field='ttl',
            discovery_value=7,  # Calculated with autottl=2 (5 hops + 2)
            service_value=1,    # Fixed TTL used
            is_critical=True
        ),
        
        # Critical: Fake packet missing or has wrong flags
        PacketDifference(
            packet_index=0,
            field='flags',
            discovery_value='SA',  # SYN+ACK for fake packet
            service_value='S',     # Only SYN
            is_critical=True
        ),
        
        # Medium: First segment has wrong payload length
        PacketDifference(
            packet_index=1,
            field='payload_len',
            discovery_value=46,  # Split at position 46
            service_value=1,     # Split at position 1
            is_critical=False
        ),
        
        # Medium: Second segment has wrong sequence number
        PacketDifference(
            packet_index=2,
            field='seq',
            discovery_value=1046,  # Original seq + 46 - 1 (overlap)
            service_value=1001,    # Original seq + 1
            is_critical=False
        ),
        
        # Low: Checksum differences
        PacketDifference(
            packet_index=0,
            field='checksum',
            discovery_value='invalid',
            service_value='valid',
            is_critical=False
        )
    ]


def analyze_x_com_root_causes():
    """Perform root cause analysis for x.com bypass issues"""
    print("Analyzing X.com Bypass Root Causes...")
    print("="*50)
    
    # Create realistic x.com comparison data
    strategy_differences = create_x_com_strategy_differences()
    packet_differences = create_x_com_packet_differences()
    
    # Create comparison objects
    strategy_comparison = StrategyComparison(
        domain='x.com',
        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
        discovery_strategy='--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1',
        service_strategy='--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq --dpi-desync-split-pos=1',
        differences=strategy_differences,
        strategies_match=False
    )
    
    packet_comparison = PacketComparison(
        domain='x.com',
        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S"),
        discovery_pcap='zapret_x.com_working.pcap',
        service_pcap='recon_x.com_failing.pcap',
        discovery_packet_count=4,  # Fake + 3 segments
        service_packet_count=2,    # Only 2 segments (no fake)
        differences=packet_differences,
        packets_match=False,
        timing_differences={
            'avg_discovery_delay_ms': 1.2,
            'avg_service_delay_ms': 0.5,
            'max_discovery_delay_ms': 2.1,
            'max_service_delay_ms': 0.8
        }
    )
    
    # Perform root cause analysis
    analyzer = RootCauseAnalyzer()
    analysis = analyzer.analyze_root_causes(strategy_comparison, packet_comparison)
    
    return analysis


def print_analysis_summary(analysis):
    """Print a summary of the root cause analysis"""
    print(f"\nROOT CAUSE ANALYSIS SUMMARY")
    print(f"Domain: {analysis.domain}")
    print(f"Overall Confidence: {analysis.confidence_score:.2f}")
    print(f"Strategy Differences: {len(analysis.strategy_differences)}")
    print(f"Packet Differences: {len(analysis.packet_differences)}")
    print(f"Root Causes Identified: {len(analysis.identified_causes)}")
    print(f"Actionable Fixes: {len(analysis.fix_recommendations)}")
    
    # Show critical issues
    critical_strategy = [d for d in analysis.strategy_differences if d.is_critical]
    critical_packet = [d for d in analysis.packet_differences if d.is_critical]
    
    print(f"\nCRITICAL ISSUES:")
    print(f"  Strategy Issues: {len(critical_strategy)}")
    print(f"  Packet Issues: {len(critical_packet)}")
    
    if critical_strategy:
        print(f"  Critical Strategy Problems:")
        for diff in critical_strategy:
            print(f"    • {diff.parameter}: {diff.discovery_value} → {diff.service_value}")
    
    if critical_packet:
        print(f"  Critical Packet Problems:")
        for diff in critical_packet:
            print(f"    • Packet {diff.packet_index} {diff.field}: {diff.discovery_value} → {diff.service_value}")


def print_top_causes(analysis):
    """Print the top identified root causes"""
    print(f"\nTOP ROOT CAUSES:")
    
    for i, cause in enumerate(analysis.identified_causes[:5], 1):
        print(f"\n{i}. {cause.get('type', 'Unknown').replace('_', ' ').title()}")
        print(f"   Severity: {cause.get('severity', 'unknown').upper()}")
        print(f"   Confidence: {cause.get('confidence', 0.0):.2f}")
        print(f"   Component: {cause.get('component', 'unknown')}")
        print(f"   Description: {cause.get('description', 'No description')}")
        
        # Show key evidence
        evidence = cause.get('evidence', {})
        if evidence:
            print(f"   Key Evidence:")
            for key, value in list(evidence.items())[:3]:
                print(f"     • {key.replace('_', ' ').title()}: {value}")


def print_fix_recommendations(analysis):
    """Print actionable fix recommendations"""
    print(f"\nFIX RECOMMENDATIONS:")
    
    for i, fix in enumerate(analysis.fix_recommendations[:3], 1):
        print(f"\n{i}. {fix.get('title', 'Unknown Fix')}")
        print(f"   Priority: {fix.get('priority', 'unknown').upper()}")
        print(f"   Estimated Effort: {fix.get('estimated_effort', 'unknown').upper()}")
        print(f"   Description: {fix.get('description', 'No description')}")
        
        # Show action items
        action_items = fix.get('action_items', [])
        if action_items:
            print(f"   Action Items:")
            for item in action_items[:4]:
                print(f"     • {item}")
            if len(action_items) > 4:
                print(f"     ... and {len(action_items) - 4} more items")
        
        # Show files to modify
        files = fix.get('files_to_modify', [])
        if files:
            print(f"   Files to Modify:")
            for file in files:
                print(f"     • {file}")


def print_code_locations(analysis):
    """Print relevant code locations"""
    print(f"\nRELEVANT CODE LOCATIONS:")
    
    for location in analysis.code_locations:
        print(f"  • {location}")


def save_results(analysis):
    """Save analysis results to files"""
    output_dir = Path("x_com_root_cause_analysis")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save JSON results
    json_file = output_dir / f"x_com_root_cause_analysis_{timestamp}.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(analysis.to_dict(), f, indent=2, default=str)
    
    # Generate and save detailed report
    analyzer = RootCauseAnalyzer()
    report = analyzer.generate_report(analysis)
    
    report_file = output_dir / f"x_com_root_cause_report_{timestamp}.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nResults saved to:")
    print(f"  JSON: {json_file}")
    print(f"  Report: {report_file}")
    
    return json_file, report_file


def generate_implementation_plan(analysis):
    """Generate implementation plan based on root cause analysis"""
    print(f"\nIMPLEMENTATION PLAN:")
    print("="*50)
    
    # Group fixes by priority
    critical_fixes = [f for f in analysis.fix_recommendations if f.get('priority') == 'critical']
    high_fixes = [f for f in analysis.fix_recommendations if f.get('priority') == 'high']
    medium_fixes = [f for f in analysis.fix_recommendations if f.get('priority') == 'medium']
    
    print(f"Phase 1 - Critical Fixes ({len(critical_fixes)} items):")
    for fix in critical_fixes:
        print(f"  • {fix.get('title', 'Unknown')}")
        print(f"    Effort: {fix.get('estimated_effort', 'unknown').upper()}")
        files = fix.get('files_to_modify', [])
        if files:
            print(f"    Files: {', '.join(files[:2])}")
    
    print(f"\nPhase 2 - High Priority Fixes ({len(high_fixes)} items):")
    for fix in high_fixes:
        print(f"  • {fix.get('title', 'Unknown')}")
    
    print(f"\nPhase 3 - Medium Priority Fixes ({len(medium_fixes)} items):")
    for fix in medium_fixes:
        print(f"  • {fix.get('title', 'Unknown')}")
    
    # Estimate total effort
    effort_map = {'low': 1, 'medium': 3, 'high': 5}
    total_effort = sum(
        effort_map.get(fix.get('estimated_effort', 'medium'), 3)
        for fix in analysis.fix_recommendations
    )
    
    print(f"\nEstimated Total Effort: {total_effort} points")
    print(f"Recommended Implementation Order:")
    print(f"  1. Fix strategy interpreter mapping (critical)")
    print(f"  2. Implement AutoTTL calculation (critical)")
    print(f"  3. Fix multidisorder attack implementation (critical)")
    print(f"  4. Add missing parameter support (medium)")


def main():
    """Main function"""
    setup_logging()
    
    print("X.com Bypass Root Cause Analysis")
    print("="*50)
    
    try:
        # Perform root cause analysis
        analysis = analyze_x_com_root_causes()
        
        # Print results
        print_analysis_summary(analysis)
        print_top_causes(analysis)
        print_fix_recommendations(analysis)
        print_code_locations(analysis)
        
        # Save results
        json_file, report_file = save_results(analysis)
        
        # Generate implementation plan
        generate_implementation_plan(analysis)
        
        print(f"\n✓ Root cause analysis completed successfully!")
        print(f"\nKey Findings:")
        print(f"  • {len(analysis.identified_causes)} root causes identified")
        print(f"  • {analysis.confidence_score:.2f} overall confidence score")
        print(f"  • {len([f for f in analysis.fix_recommendations if f.get('priority') == 'critical'])} critical fixes needed")
        
        print(f"\nNext Steps:")
        print(f"  1. Review detailed report: {report_file}")
        print(f"  2. Implement critical fixes first")
        print(f"  3. Test each fix incrementally")
        print(f"  4. Validate with x.com access tests")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)