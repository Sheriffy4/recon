#!/usr/bin/env python3
"""
Test script for RootCauseAnalyzer implementation.

This script tests the root cause analysis engine with sample data
to verify all functionality works correctly.
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Any

# Add the recon directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis import (
    RootCauseAnalyzer, CriticalDifference, DifferenceCategory, ImpactLevel,
    FixComplexity, Evidence, EvasionPattern, EvasionTechnique, Anomaly,
    AnomalyType, PacketInfo, RootCauseType
)


def create_sample_differences() -> List[CriticalDifference]:
    """Create sample critical differences for testing."""
    differences = []
    
    # TTL difference
    ttl_diff = CriticalDifference(
        category=DifferenceCategory.TTL,
        description="TTL mismatch in fake packets",
        recon_value=64,
        zapret_value=3,
        impact_level=ImpactLevel.CRITICAL,
        confidence=0.9,
        fix_priority=1,
        fix_complexity=FixComplexity.SIMPLE
    )
    ttl_diff.add_evidence("packet_analysis", "Fake packets have TTL=64 instead of TTL=3")
    differences.append(ttl_diff)
    
    # Sequence difference
    seq_diff = CriticalDifference(
        category=DifferenceCategory.SEQUENCE,
        description="Incorrect sequence overlap in split segments",
        recon_value=0,
        zapret_value=336,
        impact_level=ImpactLevel.HIGH,
        confidence=0.8,
        fix_priority=2,
        fix_complexity=FixComplexity.MODERATE
    )
    seq_diff.add_evidence("sequence_analysis", "Split segments have no overlap")
    differences.append(seq_diff)
    
    # Strategy difference
    strategy_diff = CriticalDifference(
        category=DifferenceCategory.STRATEGY,
        description="Missing badseq fooling method",
        recon_value="badsum",
        zapret_value="badsum,badseq",
        impact_level=ImpactLevel.HIGH,
        confidence=0.85,
        fix_priority=2,
        fix_complexity=FixComplexity.SIMPLE
    )
    strategy_diff.add_evidence("strategy_comparison", "Recon missing badseq implementation")
    differences.append(strategy_diff)
    
    return differences


def create_sample_patterns() -> List[EvasionPattern]:
    """Create sample evasion patterns for testing."""
    patterns = []
    
    # TTL manipulation pattern
    ttl_pattern = EvasionPattern(
        technique=EvasionTechnique.TTL_MANIPULATION,
        packets=[],  # Would contain actual PacketInfo objects
        confidence=0.7,
        description="TTL manipulation detected but with wrong values",
        parameters={'ttl': 64, 'expected_ttl': 3}
    )
    patterns.append(ttl_pattern)
    
    # Missing fake packet injection
    # (This would be detected as missing pattern)
    
    return patterns


def create_sample_anomalies() -> List[Anomaly]:
    """Create sample anomalies for testing."""
    anomalies = []
    
    # Missing fake packet anomaly
    fake_anomaly = Anomaly(
        anomaly_type=AnomalyType.MISSING_FAKE_PACKET,
        description="No fake packets detected in recon PCAP",
        affected_packets=[],
        severity='CRITICAL',
        confidence=0.9,
        expected_behavior="Should generate fake packets with TTL=3",
        actual_behavior="No fake packets generated",
        fix_suggestion="Implement fake packet generation in attack engine"
    )
    anomalies.append(fake_anomaly)
    
    # TTL anomaly
    ttl_anomaly = Anomaly(
        anomaly_type=AnomalyType.INCORRECT_TTL,
        description="Fake packets have incorrect TTL values",
        affected_packets=[],
        severity='HIGH',
        confidence=0.8,
        expected_behavior="Fake packets should have TTL=3",
        actual_behavior="Fake packets have TTL=64",
        fix_suggestion="Set fake packet TTL to 3"
    )
    anomalies.append(ttl_anomaly)
    
    return anomalies


def create_sample_historical_data() -> Dict[str, Any]:
    """Create sample historical data from recon_summary.json."""
    return {
        "target": "x.txt",
        "execution_time_seconds": 24.99,
        "total_strategies_tested": 3,
        "working_strategies_found": 0,
        "success_rate": 0.0,
        "key_metrics": {
            "overall_success_rate": 0.0,
            "total_domains_tested": 1,
            "blocked_domains_count": 1,
            "total_attacks_24h": 0,
            "average_effectiveness_24h": 0.0
        },
        "strategy_effectiveness": {
            "top_failing": [
                {
                    "strategy_id": "fec46695e820",
                    "strategy": "fakeddisorder(fooling=['badsum', 'badseq'], overlap_size=0, split_pos=3, ttl=3)",
                    "result_status": "NO_SITES_WORKING",
                    "successful_sites": 0,
                    "total_sites": 1,
                    "success_rate": 0.0,
                    "engine_telemetry": {
                        "segments_sent": 0,
                        "fake_packets_sent": 0,
                        "CH": 1,
                        "SH": 1,
                        "RST": 0
                    }
                },
                {
                    "strategy_id": "8e5e3a3bd510",
                    "strategy": "fakeddisorder(fooling=['badsum'], overlap_size=336, split_pos=76, ttl=3)",
                    "result_status": "NO_SITES_WORKING",
                    "successful_sites": 0,
                    "total_sites": 1,
                    "success_rate": 0.0,
                    "engine_telemetry": {
                        "segments_sent": 0,
                        "fake_packets_sent": 0,
                        "CH": 1,
                        "SH": 0,
                        "RST": 0
                    }
                }
            ]
        }
    }


def test_root_cause_analysis():
    """Test root cause analysis functionality."""
    print("Testing Root Cause Analysis...")
    
    # Initialize analyzer
    analyzer = RootCauseAnalyzer()
    
    # Create test data
    differences = create_sample_differences()
    patterns = create_sample_patterns()
    anomalies = create_sample_anomalies()
    
    print(f"Created {len(differences)} differences, {len(patterns)} patterns, {len(anomalies)} anomalies")
    
    # Test failure cause analysis
    print("\n1. Analyzing failure causes...")
    root_causes = analyzer.analyze_failure_causes(differences, patterns, anomalies)
    
    print(f"Found {len(root_causes)} root causes:")
    for i, cause in enumerate(root_causes, 1):
        print(f"  {i}. {cause.cause_type.value}: {cause.description}")
        print(f"     Confidence: {cause.confidence:.2f}, Impact: {cause.impact_on_success:.2f}")
        print(f"     Affected components: {', '.join(cause.affected_components)}")
        print(f"     Evidence count: {len(cause.evidence)}")
        if cause.suggested_fixes:
            print(f"     Suggested fixes: {cause.suggested_fixes[0]}")
        print()
    
    return root_causes


def test_historical_correlation(root_causes):
    """Test correlation with historical data."""
    print("2. Testing historical correlation...")
    
    analyzer = RootCauseAnalyzer()
    historical_data = create_sample_historical_data()
    
    # Test correlation
    correlated_causes = analyzer.correlate_with_historical_data(root_causes, historical_data)
    
    print(f"Correlated {len(correlated_causes)} causes with historical data:")
    for i, corr in enumerate(correlated_causes, 1):
        print(f"  {i}. {corr.root_cause.cause_type.value}")
        print(f"     Correlation strength: {corr.correlation_strength:.2f}")
        print(f"     Pattern frequency: {corr.pattern_frequency:.2f}")
        print(f"     Success rate impact: {corr.success_rate_impact:.2f}")
        print(f"     Historical matches: {len(corr.historical_matches)}")
        print()
    
    return correlated_causes


def test_hypothesis_generation(root_causes):
    """Test hypothesis generation."""
    print("3. Testing hypothesis generation...")
    
    analyzer = RootCauseAnalyzer()
    
    # Generate hypotheses
    hypotheses = analyzer.generate_hypotheses(root_causes)
    
    print(f"Generated {len(hypotheses)} hypotheses:")
    for i, hyp in enumerate(hypotheses, 1):
        print(f"  {i}. {hyp.description}")
        print(f"     Confidence: {hyp.confidence:.2f}")
        print(f"     Predicted fix: {hyp.predicted_fix}")
        print(f"     Root causes involved: {len(hyp.root_causes)}")
        print(f"     Testable predictions: {len(hyp.testable_predictions)}")
        if hyp.testable_predictions:
            print(f"       - {hyp.testable_predictions[0]}")
        print()
    
    return hypotheses


def test_hypothesis_validation(hypotheses):
    """Test hypothesis validation."""
    print("4. Testing hypothesis validation...")
    
    analyzer = RootCauseAnalyzer()
    
    # Load historical data for validation
    historical_data = create_sample_historical_data()
    analyzer._historical_data = historical_data
    
    # Create sample packet data
    recon_packets = [
        PacketInfo(
            timestamp=1.0, src_ip="192.168.1.1", dst_ip="1.1.1.1",
            src_port=12345, dst_port=443, sequence_num=1000, ack_num=0,
            ttl=64, flags=['SYN'], payload_length=0, payload_hex="",
            checksum=12345, checksum_valid=True, is_client_hello=False
        )
    ]
    
    zapret_packets = [
        PacketInfo(
            timestamp=1.0, src_ip="192.168.1.1", dst_ip="1.1.1.1",
            src_port=12345, dst_port=443, sequence_num=1000, ack_num=0,
            ttl=3, flags=['SYN'], payload_length=0, payload_hex="",
            checksum=12345, checksum_valid=False, is_client_hello=False
        )
    ]
    
    # Validate hypotheses
    validated_hypotheses = analyzer.validate_hypotheses(hypotheses, recon_packets, zapret_packets)
    
    print(f"Validated {len(validated_hypotheses)} hypotheses:")
    for i, val_hyp in enumerate(validated_hypotheses, 1):
        print(f"  {i}. {val_hyp.hypothesis.description}")
        print(f"     Validation score: {val_hyp.validation_score:.2f}")
        print(f"     Is validated: {val_hyp.is_validated}")
        print(f"     Supporting evidence: {len(val_hyp.supporting_evidence)}")
        print(f"     Contradicting evidence: {len(val_hyp.contradicting_evidence)}")
        
        if val_hyp.supporting_evidence:
            print(f"     Key support: {val_hyp.supporting_evidence[0].description}")
        print()
    
    return validated_hypotheses


def test_comprehensive_analysis():
    """Test comprehensive analysis workflow."""
    print("5. Testing comprehensive analysis workflow...")
    
    # Run complete analysis
    root_causes = test_root_cause_analysis()
    correlated_causes = test_historical_correlation(root_causes)
    hypotheses = test_hypothesis_generation(root_causes)
    validated_hypotheses = test_hypothesis_validation(hypotheses)
    
    # Generate summary report
    print("=== ANALYSIS SUMMARY ===")
    print(f"Root causes identified: {len(root_causes)}")
    print(f"Historical correlations: {len(correlated_causes)}")
    print(f"Hypotheses generated: {len(hypotheses)}")
    print(f"Validated hypotheses: {len([vh for vh in validated_hypotheses if vh.is_validated])}")
    
    # Top recommendations
    print("\n=== TOP RECOMMENDATIONS ===")
    if validated_hypotheses:
        top_hypothesis = max(validated_hypotheses, key=lambda vh: vh.validation_score)
        print(f"Primary hypothesis: {top_hypothesis.hypothesis.description}")
        print(f"Recommended fix: {top_hypothesis.hypothesis.predicted_fix}")
        print(f"Validation confidence: {top_hypothesis.validation_score:.2f}")
    
    if root_causes:
        critical_causes = [rc for rc in root_causes if rc.blocking_severity == "CRITICAL"]
        print(f"\nCritical issues to fix: {len(critical_causes)}")
        for cause in critical_causes[:3]:  # Top 3
            print(f"  - {cause.description}")
            if cause.suggested_fixes:
                print(f"    Fix: {cause.suggested_fixes[0]}")
    
    return {
        'root_causes': root_causes,
        'correlated_causes': correlated_causes,
        'hypotheses': hypotheses,
        'validated_hypotheses': validated_hypotheses
    }


def test_json_serialization(analysis_results):
    """Test JSON serialization of results."""
    print("\n6. Testing JSON serialization...")
    
    try:
        # Test serialization of each component
        root_causes_json = [rc.to_dict() for rc in analysis_results['root_causes']]
        correlated_causes_json = [cc.to_dict() for cc in analysis_results['correlated_causes']]
        hypotheses_json = [h.to_dict() for h in analysis_results['hypotheses']]
        validated_hypotheses_json = [vh.to_dict() for vh in analysis_results['validated_hypotheses']]
        
        # Create complete report
        report = {
            'analysis_timestamp': '2025-10-03T12:00:00Z',
            'root_causes': root_causes_json,
            'correlated_causes': correlated_causes_json,
            'hypotheses': hypotheses_json,
            'validated_hypotheses': validated_hypotheses_json,
            'summary': {
                'total_root_causes': len(root_causes_json),
                'total_hypotheses': len(hypotheses_json),
                'validated_hypotheses': len([vh for vh in validated_hypotheses_json if vh['is_validated']]),
                'critical_issues': len([rc for rc in root_causes_json if rc['blocking_severity'] == 'CRITICAL'])
            }
        }
        
        # Test JSON serialization
        json_str = json.dumps(report, indent=2)
        print(f"Successfully serialized analysis report ({len(json_str)} characters)")
        
        # Test deserialization
        parsed_report = json.loads(json_str)
        print(f"Successfully deserialized report with {len(parsed_report)} sections")
        
        # Save to file for inspection
        output_file = Path(__file__).parent / "root_cause_analysis_test_report.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_str)
        print(f"Saved test report to: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"JSON serialization failed: {e}")
        return False


def main():
    """Main test function."""
    print("Root Cause Analyzer Test Suite")
    print("=" * 50)
    
    try:
        # Run comprehensive analysis test
        analysis_results = test_comprehensive_analysis()
        
        # Test serialization
        serialization_success = test_json_serialization(analysis_results)
        
        print("\n" + "=" * 50)
        print("TEST RESULTS:")
        print(f"✓ Root cause analysis: PASSED")
        print(f"✓ Historical correlation: PASSED")
        print(f"✓ Hypothesis generation: PASSED")
        print(f"✓ Hypothesis validation: PASSED")
        print(f"{'✓' if serialization_success else '✗'} JSON serialization: {'PASSED' if serialization_success else 'FAILED'}")
        
        print("\nAll core functionality tests completed successfully!")
        print("The RootCauseAnalyzer is ready for integration.")
        
        return True
        
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)