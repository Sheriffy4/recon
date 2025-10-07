#!/usr/bin/env python3
"""
Demonstration of DifferenceDetector usage with PCAP analysis.
"""

import sys
import os
import json
from typing import List, Dict, Any

# Add the recon directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis import (
    DifferenceDetector, DetectionConfig, CriticalDifference,
    DifferenceCategory, ImpactLevel, PCAPComparator, ComparisonResult
)


def demo_difference_detection():
    """Demonstrate difference detection capabilities."""
    print("=== DifferenceDetector Demo ===\n")
    
    # Initialize detector with custom configuration
    config = DetectionConfig(
        timing_threshold_ms=5.0,  # More sensitive timing detection
        ttl_difference_threshold=1,
        checksum_mismatch_threshold=0.05  # More sensitive checksum detection
    )
    
    detector = DifferenceDetector(config)
    
    print("1. Detector Configuration:")
    print(f"   - Timing threshold: {config.timing_threshold_ms}ms")
    print(f"   - TTL difference threshold: {config.ttl_difference_threshold}")
    print(f"   - Checksum mismatch threshold: {config.checksum_mismatch_threshold}")
    print()
    
    # Simulate PCAP comparison (in real usage, this would come from PCAPComparator)
    comparison = create_sample_comparison()
    
    print("2. Sample PCAP Comparison:")
    print(f"   - Recon packets: {len(comparison.recon_packets)}")
    print(f"   - Zapret packets: {len(comparison.zapret_packets)}")
    print()
    
    # Detect differences
    print("3. Detecting Critical Differences...")
    differences = detector.detect_critical_differences(comparison)
    
    print(f"   Found {len(differences)} differences\n")
    
    # Display differences
    print("4. Detected Differences (prioritized):")
    for i, diff in enumerate(differences, 1):
        print(f"\n   {i}. {diff.category.value.upper()}: {diff.description}")
        print(f"      Impact: {diff.impact_level.value}")
        print(f"      Confidence: {diff.confidence:.2f}")
        print(f"      Priority: {diff.fix_priority}")
        print(f"      Severity Score: {diff.calculate_severity_score():.2f}")
        print(f"      Fix Urgency: {diff.get_fix_urgency()}")
        print(f"      Blocking: {'Yes' if diff.is_blocking() else 'No'}")
        
        if diff.suggested_fix:
            print(f"      Suggested Fix: {diff.suggested_fix}")
        
        if diff.code_location:
            print(f"      Code Location: {diff.code_location}")
        
        if diff.evidence:
            print(f"      Evidence: {len(diff.evidence)} pieces")
    
    # Categorize differences
    print("\n5. Differences by Category:")
    categorized = detector.categorize_differences(differences)
    
    for category, cat_diffs in categorized.items():
        print(f"\n   {category.value.upper()} ({len(cat_diffs)} differences):")
        for diff in cat_diffs:
            urgency = diff.get_fix_urgency()
            print(f"     - {diff.description} [{urgency}]")
    
    # Impact assessment
    print("\n6. Impact Assessment for Critical Differences:")
    critical_diffs = [d for d in differences if d.impact_level == ImpactLevel.CRITICAL]
    
    for diff in critical_diffs:
        assessment = detector.assess_impact(diff)
        print(f"\n   {diff.description}:")
        print(f"     - Severity Score: {assessment['severity_score']:.2f}")
        print(f"     - Is Blocking: {assessment['is_blocking']}")
        print(f"     - Fix Urgency: {assessment['fix_urgency']}")
        print(f"     - Estimated Fix Time: {assessment['estimated_fix_time']}")
        print(f"     - Risk Level: {assessment['risk_level']}")
        if assessment['dependencies']:
            print(f"     - Dependencies: {', '.join(assessment['dependencies'])}")
    
    # Group related differences
    print("\n7. Related Difference Groups:")
    groups = detector.group_related_differences(differences)
    
    for group in groups:
        print(f"\n   Group: {group.name}")
        print(f"   Group Severity: {group.group_severity:.2f}")
        print(f"   Differences: {len(group.differences)}")
        
        fix_order = group.get_fix_order()
        print("   Recommended Fix Order:")
        for i, diff in enumerate(fix_order, 1):
            print(f"     {i}. {diff.description} (Priority: {diff.fix_priority})")
    
    # Detection statistics
    print("\n8. Detection Statistics:")
    stats = detector.get_detection_statistics()
    for key, value in stats.items():
        if key == 'categories_detected':
            print(f"   {key}:")
            for cat, count in value.items():
                print(f"     - {cat}: {count}")
        else:
            print(f"   {key}: {value}")
    
    # Export results
    print("\n9. Exporting Results...")
    export_results(differences, "difference_detection_results.json")
    print("   Results exported to difference_detection_results.json")
    
    print("\n=== Demo Complete ===")


def create_sample_comparison() -> ComparisonResult:
    """Create a sample comparison with various types of differences."""
    from core.pcap_analysis.packet_info import PacketInfo
    
    # Recon packets (with issues)
    recon_packets = [
        # Normal SYN packet
        PacketInfo(
            timestamp=1.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",  # x.com
            src_port=54321,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0,
            checksum_valid=True
        ),
        
        # SYN-ACK response
        PacketInfo(
            timestamp=1.02,
            src_ip="104.244.42.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            sequence_num=2000,
            ack_num=1001,
            ttl=64,
            flags=["SYN", "ACK"],
            payload_length=0,
            checksum_valid=True,
            direction="inbound"
        ),
        
        # ACK packet
        PacketInfo(
            timestamp=1.03,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["ACK"],
            payload_length=0,
            checksum_valid=True
        ),
        
        # Fake packet with WRONG TTL (should be 3)
        PacketInfo(
            timestamp=1.1,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,  # WRONG! Should be 3 for fake packet
            flags=["PSH", "ACK"],
            payload_length=517,
            payload=b"\x16\x03\x01\x02\x00" + b"A" * 512,  # Fake TLS ClientHello
            checksum_valid=True,  # WRONG! Should be False for fake packet
            is_client_hello=True
        ),
        
        # Real ClientHello packet (split)
        PacketInfo(
            timestamp=1.15,  # WRONG timing - too slow
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=517,
            payload=b"\x16\x03\x01\x02\x00" + b"B" * 512,  # Real TLS ClientHello
            checksum_valid=True,
            is_client_hello=True
        )
    ]
    
    # Zapret packets (correct implementation)
    zapret_packets = [
        # Normal SYN packet
        PacketInfo(
            timestamp=1.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=["SYN"],
            payload_length=0,
            checksum_valid=True
        ),
        
        # SYN-ACK response
        PacketInfo(
            timestamp=1.02,
            src_ip="104.244.42.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            sequence_num=2000,
            ack_num=1001,
            ttl=64,
            flags=["SYN", "ACK"],
            payload_length=0,
            checksum_valid=True,
            direction="inbound"
        ),
        
        # ACK packet
        PacketInfo(
            timestamp=1.03,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["ACK"],
            payload_length=0,
            checksum_valid=True
        ),
        
        # Fake packet with CORRECT TTL=3
        PacketInfo(
            timestamp=1.1,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=3,  # CORRECT! TTL=3 for fake packet
            flags=["PSH", "ACK"],
            payload_length=517,
            payload=b"\x16\x03\x01\x02\x00" + b"A" * 512,  # Fake TLS ClientHello
            checksum_valid=False,  # CORRECT! Bad checksum for fake packet
            is_client_hello=True
        ),
        
        # Real ClientHello packet (split) with correct timing
        PacketInfo(
            timestamp=1.105,  # CORRECT timing - faster
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=54321,
            dst_port=443,
            sequence_num=1001,
            ack_num=2001,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=517,
            payload=b"\x16\x03\x01\x02\x00" + b"B" * 512,  # Real TLS ClientHello
            checksum_valid=True,
            is_client_hello=True
        )
    ]
    
    return ComparisonResult(
        recon_packets=recon_packets,
        zapret_packets=zapret_packets,
        recon_file="recon_x.pcap",
        zapret_file="zapret_x.pcap",
        analysis_timestamp=1.0
    )


def export_results(differences: List[CriticalDifference], filename: str):
    """Export detection results to JSON file."""
    results = {
        'summary': {
            'total_differences': len(differences),
            'critical_count': len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL]),
            'high_count': len([d for d in differences if d.impact_level == ImpactLevel.HIGH]),
            'medium_count': len([d for d in differences if d.impact_level == ImpactLevel.MEDIUM]),
            'low_count': len([d for d in differences if d.impact_level == ImpactLevel.LOW]),
            'blocking_count': len([d for d in differences if d.is_blocking()])
        },
        'differences': [diff.to_dict() for diff in differences],
        'categories': {}
    }
    
    # Add category breakdown
    from collections import defaultdict
    categories = defaultdict(int)
    for diff in differences:
        categories[diff.category.value] += 1
    
    results['categories'] = dict(categories)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def demo_integration_with_pcap_comparator():
    """Demonstrate integration with existing PCAPComparator."""
    print("\n=== Integration with PCAPComparator ===\n")
    
    # This would be used in real scenarios where you have actual PCAP files
    print("Example integration code:")
    print("""
    from core.pcap_analysis import PCAPComparator, DifferenceDetector
    
    # Initialize components
    comparator = PCAPComparator()
    detector = DifferenceDetector()
    
    # Compare PCAP files
    comparison = comparator.compare_pcaps('recon_x.pcap', 'zapret_x.pcap')
    
    # Detect critical differences
    differences = detector.detect_critical_differences(comparison)
    
    # Process results
    for diff in differences:
        if diff.is_blocking():
            print(f"BLOCKING ISSUE: {diff.description}")
            print(f"Fix: {diff.suggested_fix}")
    """)


if __name__ == '__main__':
    demo_difference_detection()
    demo_integration_with_pcap_comparator()