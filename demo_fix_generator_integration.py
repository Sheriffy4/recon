#!/usr/bin/env python3
"""
Integration demo for the FixGenerator with other PCAP analysis components.

This script demonstrates how the FixGenerator integrates with the complete
PCAP analysis pipeline to provide end-to-end automated fix generation.
"""

import json
from pathlib import Path

from core.pcap_analysis import (
    FixGenerator, PCAPComparator, StrategyAnalyzer, PacketSequenceAnalyzer,
    DifferenceDetector, PatternRecognizer, RootCauseAnalyzer,
    PacketInfo, StrategyConfig, ComparisonResult
)


def create_sample_pcap_data():
    """Create sample PCAP data for demonstration."""
    # Sample recon packets (problematic)
    recon_packets = [
        PacketInfo(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",  # x.com IP
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,  # Wrong TTL - should be 3 for fake packet
            flags=["SYN"],
            payload_length=60,
            payload_hex="160301003b010000370303...",
            checksum=0x1234,  # Valid checksum - should be invalid for fake
            checksum_valid=True,
            is_client_hello=True
        ),
        PacketInfo(
            timestamp=1000.1,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1060,
            ack_num=0,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=30,
            payload_hex="160301001b...",
            checksum=0x5678,
            checksum_valid=True,
            is_client_hello=False
        )
    ]
    
    # Sample zapret packets (working correctly)
    zapret_packets = [
        PacketInfo(
            timestamp=2000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2000,
            ack_num=0,
            ttl=3,  # Correct TTL for fake packet
            flags=["SYN"],
            payload_length=60,
            payload_hex="160301003b010000370303...",
            checksum=0xFFFF,  # Invalid checksum for fake packet
            checksum_valid=False,
            is_client_hello=True
        ),
        PacketInfo(
            timestamp=2000.001,  # Much faster timing
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2000,  # Overlapping sequence for fakeddisorder
            ack_num=0,
            ttl=64,  # Normal TTL for real packet
            flags=["PSH", "ACK"],
            payload_length=3,  # Split at position 3
            payload_hex="160301",
            checksum=0x9ABC,
            checksum_valid=True,
            is_client_hello=False
        ),
        PacketInfo(
            timestamp=2000.002,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2003,  # Continuing from split
            ack_num=0,
            ttl=64,
            flags=["PSH", "ACK"],
            payload_length=57,
            payload_hex="003b010000370303...",
            checksum=0xDEF0,
            checksum_valid=True,
            is_client_hello=False
        )
    ]
    
    return recon_packets, zapret_packets


def create_sample_strategy_configs():
    """Create sample strategy configurations."""
    recon_config = StrategyConfig(
        name="fake,fakeddisorder",
        dpi_desync="fake,fakeddisorder",
        split_pos=5,  # Wrong split position
        ttl=64,       # Wrong TTL
        fooling=["badsum"],  # Missing badseq
        source="recon"
    )
    
    zapret_config = StrategyConfig(
        name="fake,fakeddisorder",
        dpi_desync="fake,fakeddisorder",
        split_pos=3,  # Correct split position
        ttl=3,        # Correct TTL
        fooling=["badsum", "badseq"],  # Complete fooling methods
        source="zapret"
    )
    
    return recon_config, zapret_config


def demonstrate_complete_pipeline():
    """Demonstrate the complete PCAP analysis and fix generation pipeline."""
    print("🔧 Complete PCAP Analysis & Fix Generation Pipeline")
    print("=" * 60)
    
    # Step 1: Create sample data
    print("\n📊 Step 1: Preparing Sample Data")
    recon_packets, zapret_packets = create_sample_pcap_data()
    recon_config, zapret_config = create_sample_strategy_configs()
    
    print(f"  • Recon packets: {len(recon_packets)}")
    print(f"  • Zapret packets: {len(zapret_packets)}")
    print(f"  • Strategy configs prepared")
    
    # Step 2: PCAP Comparison
    print("\n🔍 Step 2: PCAP Comparison")
    comparator = PCAPComparator()
    
    # Create comparison result
    comparison_result = ComparisonResult(
        recon_packets=recon_packets,
        zapret_packets=zapret_packets,
        similarity_score=0.4,
        recon_file="recon_x.pcap",
        zapret_file="zapret_x.pcap",
        analysis_timestamp=1000.0
    )
    
    # Add some analysis metadata
    comparison_result.detected_strategies = {
        "domain": "x.com",
        "strategy": "fake,fakeddisorder",
        "analysis_time": "2024-01-01T12:00:00Z"
    }
    
    print(f"  • Similarity score: {comparison_result.similarity_score:.1%}")
    print(f"  • Analysis metadata: {comparison_result.detected_strategies}")
    
    # Step 3: Strategy Analysis
    print("\n📋 Step 3: Strategy Analysis")
    strategy_analyzer = StrategyAnalyzer()
    strategy_comparison = strategy_analyzer.compare_strategies(recon_config, zapret_config)
    
    print(f"  • Strategy differences found: {len(strategy_comparison.differences)}")
    print(f"  • Strategy compatibility: {strategy_comparison.is_compatible}")
    
    for diff in strategy_comparison.differences:
        print(f"    - {diff.parameter}: {diff.recon_value} → {diff.zapret_value} ({diff.impact_level})")
    
    # Step 4: Packet Sequence Analysis
    print("\n🔄 Step 4: Packet Sequence Analysis")
    sequence_analyzer = PacketSequenceAnalyzer()
    
    # Analyze recon packets for fake packet detection
    fake_analysis = sequence_analyzer.detect_fake_packet(
        recon_packets[0], recon_packets, 0
    )
    
    print(f"  • Fake packet detected: {fake_analysis.is_fake}")
    print(f"  • Detection confidence: {fake_analysis.confidence:.1%}")
    print(f"  • Suspicious indicators: {fake_analysis.indicators}")
    print(f"  • TTL suspicious: {fake_analysis.ttl_suspicious}")
    print(f"  • Checksum invalid: {fake_analysis.checksum_invalid}")
    
    # Step 5: Difference Detection
    print("\n🎯 Step 5: Critical Difference Detection")
    difference_detector = DifferenceDetector()
    critical_differences = difference_detector.detect_critical_differences(comparison_result)
    
    print(f"  • Critical differences detected: {len(critical_differences)}")
    for diff in critical_differences:
        print(f"    - {diff.category}: {diff.description} (Impact: {diff.impact_level})")
    
    # Step 6: Pattern Recognition
    print("\n🔍 Step 6: Pattern Recognition")
    pattern_recognizer = PatternRecognizer()
    
    recon_patterns = pattern_recognizer.recognize_dpi_evasion_patterns(recon_packets)
    zapret_patterns = pattern_recognizer.recognize_dpi_evasion_patterns(zapret_packets)
    
    print(f"  • Recon patterns found: {len(recon_patterns)}")
    print(f"  • Zapret patterns found: {len(zapret_patterns)}")
    
    anomalies = pattern_recognizer.detect_anomalies(recon_patterns, zapret_patterns, recon_packets, zapret_packets)
    print(f"  • Anomalies detected: {len(anomalies)}")
    
    for anomaly in anomalies:
        print(f"    - {anomaly.anomaly_type}: {anomaly.description}")
    
    # Step 7: Root Cause Analysis
    print("\n🔬 Step 7: Root Cause Analysis")
    root_cause_analyzer = RootCauseAnalyzer()
    
    root_causes = root_cause_analyzer.analyze_failure_causes(
        critical_differences, recon_patterns
    )
    
    print(f"  • Root causes identified: {len(root_causes)}")
    for cause in root_causes:
        print(f"    - {cause.cause_type.value}: {cause.description}")
        print(f"      Confidence: {cause.confidence:.1%}, Impact: {cause.impact_on_success:.1%}")
    
    # Step 8: Fix Generation (Main Task)
    print("\n🛠️  Step 8: Automated Fix Generation")
    fix_generator = FixGenerator()
    
    # Generate all types of fixes
    code_fixes = fix_generator.generate_code_fixes(root_causes)
    strategy_patches = fix_generator.create_strategy_patches(strategy_comparison.differences)
    sequence_fixes = fix_generator.generate_packet_sequence_fixes(fake_analysis)
    checksum_fixes = fix_generator.create_checksum_corruption_fix({
        "fake_packets_have_bad_checksum": not fake_analysis.checksum_invalid
    })
    timing_fixes = fix_generator.generate_timing_optimization_fixes({
        "delay_too_long": fake_analysis.timing_suspicious,
        "optimal_delay": 0.001,
        "send_order_incorrect": True,
        "correct_send_order": ["fake", "real1", "real2"]
    })
    
    all_fixes = code_fixes + checksum_fixes + timing_fixes
    regression_tests = fix_generator.create_regression_tests(all_fixes)
    
    print(f"  • Code fixes generated: {len(code_fixes)}")
    print(f"  • Strategy patches generated: {len(strategy_patches)}")
    print(f"  • Sequence fixes generated: {len(sequence_fixes)}")
    print(f"  • Checksum fixes generated: {len(checksum_fixes)}")
    print(f"  • Timing fixes generated: {len(timing_fixes)}")
    print(f"  • Regression tests generated: {len(regression_tests)}")
    
    # Step 9: Fix Prioritization and Summary
    print("\n📈 Step 9: Fix Prioritization & Summary")
    
    def calculate_priority_score(fix):
        """Calculate priority score for a fix."""
        risk_weights = {
            "low": 1.0,
            "medium": 0.8,
            "high": 0.6,
            "critical": 0.4
        }
        return fix.confidence * risk_weights.get(fix.risk_level.value, 0.5)
    
    prioritized_fixes = sorted(all_fixes, key=calculate_priority_score, reverse=True)
    
    print(f"  • Total fixes: {len(all_fixes)}")
    print(f"  • High-confidence fixes: {len([f for f in all_fixes if f.confidence >= 0.8])}")
    print(f"  • Low-risk fixes: {len([f for f in all_fixes if f.risk_level.value == 'low'])}")
    
    print(f"\n  Top 3 Priority Fixes:")
    for i, fix in enumerate(prioritized_fixes[:3], 1):
        priority_score = calculate_priority_score(fix)
        print(f"    {i}. {fix.description}")
        print(f"       Priority: {priority_score:.2f}, Confidence: {fix.confidence:.1%}, Risk: {fix.risk_level.value}")
    
    # Step 10: Export Results
    print("\n💾 Step 10: Export Results")
    
    results = {
        "analysis_summary": {
            "domain": "x.com",
            "strategy": "fake,fakeddisorder",
            "similarity_score": comparison_result.similarity_score,
            "total_differences": len(strategy_comparison.differences),
            "critical_differences": len(critical_differences),
            "root_causes": len(root_causes),
            "total_fixes": len(all_fixes)
        },
        "strategy_differences": [
            {
                "parameter": diff.parameter,
                "recon_value": diff.recon_value,
                "zapret_value": diff.zapret_value,
                "impact_level": diff.impact_level,
                "description": diff.description
            }
            for diff in strategy_comparison.differences
        ],
        "root_causes": [
            {
                "type": cause.cause_type.value,
                "description": cause.description,
                "confidence": cause.confidence,
                "impact": cause.impact_on_success,
                "affected_components": cause.affected_components
            }
            for cause in root_causes
        ],
        "generated_fixes": [fix.to_dict() for fix in all_fixes],
        "strategy_patches": [patch.to_dict() for patch in strategy_patches],
        "sequence_fixes": [fix.to_dict() for fix in sequence_fixes],
        "regression_tests": [test.to_dict() for test in regression_tests],
        "recommendations": {
            "immediate_actions": [
                "Apply TTL fix (highest priority)",
                "Fix checksum corruption for fake packets",
                "Optimize packet timing"
            ],
            "testing_requirements": [
                "Test against x.com domain",
                "Validate PCAP output matches zapret",
                "Run regression tests"
            ],
            "success_metrics": [
                "Domain accessibility improvement",
                "PCAP similarity score > 0.8",
                "All regression tests pass"
            ]
        }
    }
    
    output_file = "complete_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"  • Complete analysis exported to: {output_file}")
    
    # Step 11: Implementation Guidance
    print("\n🚀 Step 11: Implementation Guidance")
    
    print(f"  Implementation Phases:")
    print(f"    Phase 1 - Critical Fixes (Apply First):")
    critical_fixes = [f for f in prioritized_fixes if calculate_priority_score(f) >= 0.8]
    for fix in critical_fixes:
        print(f"      • {fix.fix_type.value}: {fix.file_path}")
    
    print(f"    Phase 2 - Validation & Testing:")
    print(f"      • Run {len(regression_tests)} regression tests")
    print(f"      • Validate against target domains")
    print(f"      • Monitor success rates")
    
    print(f"    Phase 3 - Performance Optimization:")
    performance_fixes = [f for f in all_fixes if f.fix_type.value in ['timing_fix', 'packet_order_fix']]
    for fix in performance_fixes:
        print(f"      • {fix.description}")
    
    print(f"\n✅ Complete Pipeline Demonstration Finished!")
    print(f"📁 Results saved to: {output_file}")
    
    return results


def demonstrate_fix_application_simulation():
    """Simulate applying fixes and measuring improvement."""
    print("\n🧪 Fix Application Simulation")
    print("=" * 40)
    
    # Simulate before/after metrics
    before_metrics = {
        "success_rate": 0.2,  # 20% success rate
        "pcap_similarity": 0.4,  # 40% similarity to zapret
        "ttl_compliance": 0.0,  # 0% TTL compliance
        "checksum_compliance": 0.5,  # 50% checksum compliance
        "timing_compliance": 0.3   # 30% timing compliance
    }
    
    # Simulate after applying fixes
    after_metrics = {
        "success_rate": 0.85,  # 85% success rate (improved)
        "pcap_similarity": 0.92,  # 92% similarity to zapret
        "ttl_compliance": 1.0,  # 100% TTL compliance (fixed)
        "checksum_compliance": 0.95,  # 95% checksum compliance
        "timing_compliance": 0.88   # 88% timing compliance
    }
    
    print("📊 Simulated Fix Impact:")
    for metric, before_value in before_metrics.items():
        after_value = after_metrics[metric]
        if before_value > 0:
            improvement = ((after_value - before_value) / before_value) * 100
        else:
            improvement = float('inf') if after_value > 0 else 0
        print(f"  • {metric.replace('_', ' ').title()}:")
        print(f"    Before: {before_value:.1%}")
        print(f"    After:  {after_value:.1%}")
        if improvement == float('inf'):
            print(f"    Improvement: ∞% (from 0%)")
        else:
            print(f"    Improvement: {improvement:+.1f}%")
    
    print(f"\n🎯 Key Improvements:")
    print(f"  • Success rate increased by {((after_metrics['success_rate'] - before_metrics['success_rate']) / before_metrics['success_rate']) * 100:.0f}%")
    print(f"  • PCAP similarity improved to {after_metrics['pcap_similarity']:.1%}")
    print(f"  • TTL compliance achieved 100%")
    
    return before_metrics, after_metrics


if __name__ == "__main__":
    try:
        # Run the complete pipeline demonstration
        results = demonstrate_complete_pipeline()
        
        # Run fix application simulation
        before, after = demonstrate_fix_application_simulation()
        
        print(f"\n🎉 Integration Demo Completed Successfully!")
        print(f"📈 Overall Success: Domain bypass success rate improved from {before['success_rate']:.1%} to {after['success_rate']:.1%}")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()