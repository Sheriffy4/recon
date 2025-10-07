#!/usr/bin/env python3
"""
Simple demo script for RootCauseAnalyzer functionality.

This script demonstrates the core RootCauseAnalyzer functionality
with mock data, focusing on the analysis engine itself.
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
    AnomalyType, PacketInfo, RootCauseType, StrategyConfig, StrategyType, FoolingMethod
)


def create_realistic_scenario() -> Dict[str, Any]:
    """Create a realistic scenario based on the x.com fakeddisorder issue."""
    
    # Create sample packets representing the issue
    recon_packets = [
        PacketInfo(
            timestamp=1.0, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1000, ack_num=0,
            ttl=64, flags=['SYN'], payload_length=0, payload_hex="",
            checksum=12345, checksum_valid=True, is_client_hello=False
        ),
        PacketInfo(
            timestamp=1.1, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1001, ack_num=500,
            ttl=64, flags=['PSH', 'ACK'], payload_length=517, payload_hex="160301...",
            checksum=12346, checksum_valid=True, is_client_hello=True
        )
    ]
    
    zapret_packets = [
        PacketInfo(
            timestamp=1.0, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1000, ack_num=0,
            ttl=64, flags=['SYN'], payload_length=0, payload_hex="",
            checksum=12345, checksum_valid=True, is_client_hello=False
        ),
        # Fake packet with TTL=3 and bad checksum
        PacketInfo(
            timestamp=1.05, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1001, ack_num=500,
            ttl=3, flags=['PSH', 'ACK'], payload_length=3, payload_hex="160301",
            checksum=0, checksum_valid=False, is_client_hello=False
        ),
        # Real packet segments
        PacketInfo(
            timestamp=1.1, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1001, ack_num=500,
            ttl=64, flags=['PSH', 'ACK'], payload_length=3, payload_hex="160301",
            checksum=12346, checksum_valid=True, is_client_hello=True
        ),
        PacketInfo(
            timestamp=1.11, src_ip="192.168.1.100", dst_ip="104.244.42.1",
            src_port=54321, dst_port=443, sequence_num=1337, ack_num=500,  # Overlapping sequence
            ttl=64, flags=['PSH', 'ACK'], payload_length=514, payload_hex="020000...",
            checksum=12347, checksum_valid=True, is_client_hello=False
        )
    ]
    
    # Create critical differences based on the scenario
    differences = [
        CriticalDifference(
            category=DifferenceCategory.TTL,
            description="Missing fake packets with low TTL",
            recon_value="No fake packets detected",
            zapret_value="Fake packet with TTL=3",
            impact_level=ImpactLevel.CRITICAL,
            confidence=0.95,
            fix_priority=1,
            fix_complexity=FixComplexity.MODERATE,
            suggested_fix="Implement fake packet generation with TTL=3",
            code_location="recon/core/bypass/attacks/tcp/fake_disorder_attack.py"
        ),
        CriticalDifference(
            category=DifferenceCategory.SEQUENCE,
            description="Missing sequence overlap in split segments",
            recon_value="No overlap (split_seqovl=0)",
            zapret_value="336 byte overlap (split_seqovl=336)",
            impact_level=ImpactLevel.HIGH,
            confidence=0.9,
            fix_priority=2,
            fix_complexity=FixComplexity.MODERATE,
            suggested_fix="Implement proper sequence overlap calculation",
            code_location="recon/core/bypass/attacks/tcp/fake_disorder_attack.py"
        ),
        CriticalDifference(
            category=DifferenceCategory.CHECKSUM,
            description="Fake packets have valid checksums",
            recon_value="Valid checksums in all packets",
            zapret_value="Invalid checksums in fake packets",
            impact_level=ImpactLevel.HIGH,
            confidence=0.85,
            fix_priority=2,
            fix_complexity=FixComplexity.SIMPLE,
            suggested_fix="Implement badsum fooling method",
            code_location="recon/core/bypass/techniques/primitives.py"
        )
    ]
    
    # Create evasion patterns
    patterns = [
        EvasionPattern(
            technique=EvasionTechnique.TTL_MANIPULATION,
            packets=recon_packets,
            confidence=0.3,  # Low confidence because TTL is wrong
            description="TTL manipulation detected but with incorrect values",
            parameters={'detected_ttl': 64, 'expected_ttl': 3}
        )
    ]
    
    # Create anomalies
    anomalies = [
        Anomaly(
            anomaly_type=AnomalyType.MISSING_FAKE_PACKET,
            description="No fake packets detected in recon sequence",
            affected_packets=recon_packets,
            severity='CRITICAL',
            confidence=0.95,
            expected_behavior="Should generate fake packet with TTL=3 before real segments",
            actual_behavior="No fake packets generated",
            fix_suggestion="Implement fake packet injection in fakeddisorder attack"
        ),
        Anomaly(
            anomaly_type=AnomalyType.INCORRECT_SEQUENCE_OVERLAP,
            description="Split segments have no sequence overlap",
            affected_packets=recon_packets[1:],
            severity='HIGH',
            confidence=0.9,
            expected_behavior="Split segments should have 336 byte overlap",
            actual_behavior="No sequence overlap detected",
            fix_suggestion="Fix sequence overlap calculation in split logic"
        )
    ]
    
    # Historical data from actual recon_summary.json
    historical_data = {
        "target": "x.txt",
        "success_rate": 0.0,
        "total_strategies_tested": 3,
        "working_strategies_found": 0,
        "key_metrics": {
            "overall_success_rate": 0.0,
            "total_domains_tested": 1,
            "blocked_domains_count": 1
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
                        "fake_packets_sent": 0,  # Key indicator!
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
                        "fake_packets_sent": 0,  # Key indicator!
                        "CH": 1,
                        "SH": 0,
                        "RST": 0
                    }
                }
            ]
        }
    }
    
    return {
        'recon_packets': recon_packets,
        'zapret_packets': zapret_packets,
        'differences': differences,
        'patterns': patterns,
        'anomalies': anomalies,
        'historical_data': historical_data
    }


def run_comprehensive_demo():
    """Run comprehensive root cause analysis demo."""
    print("Root Cause Analysis Demo - X.com Fakeddisorder Issue")
    print("=" * 60)
    
    # Create realistic scenario
    scenario = create_realistic_scenario()
    
    # Initialize analyzer
    analyzer = RootCauseAnalyzer()
    
    print("Scenario: Recon fails to bypass x.com while zapret succeeds")
    print("Strategy: fakeddisorder with split_pos=3, ttl=3, fooling=badsum,badseq")
    print()
    
    # Step 1: Analyze failure causes
    print("1. Analyzing Root Causes...")
    root_causes = analyzer.analyze_failure_causes(
        scenario['differences'], 
        scenario['patterns'], 
        scenario['anomalies']
    )
    
    print(f"   Found {len(root_causes)} root causes:")
    for i, cause in enumerate(root_causes, 1):
        print(f"   {i}. {cause.cause_type.value.replace('_', ' ').title()}")
        print(f"      Description: {cause.description}")
        print(f"      Impact: {cause.impact_on_success:.2f}, Confidence: {cause.confidence:.2f}")
        print(f"      Severity: {cause.blocking_severity}")
        if cause.suggested_fixes:
            print(f"      Fix: {cause.suggested_fixes[0]}")
        print()
    
    # Step 2: Correlate with historical data
    print("2. Correlating with Historical Data...")
    correlated_causes = analyzer.correlate_with_historical_data(
        root_causes, scenario['historical_data']
    )
    
    print(f"   Correlated {len(correlated_causes)} causes:")
    for i, corr in enumerate(correlated_causes, 1):
        if corr.correlation_strength > 0:
            print(f"   {i}. {corr.root_cause.cause_type.value}")
            print(f"      Correlation strength: {corr.correlation_strength:.2f}")
            print(f"      Historical matches: {len(corr.historical_matches)}")
            print(f"      Pattern frequency: {corr.pattern_frequency:.2f}")
            
            # Show key evidence from historical data
            for match in corr.historical_matches[:1]:  # Show first match
                telemetry = match.get('engine_telemetry', {})
                print(f"      Evidence: fake_packets_sent={telemetry.get('fake_packets_sent', 0)}")
            print()
    
    # Step 3: Generate hypotheses
    print("3. Generating Hypotheses...")
    hypotheses = analyzer.generate_hypotheses(root_causes)
    
    print(f"   Generated {len(hypotheses)} hypotheses:")
    for i, hyp in enumerate(hypotheses, 1):
        print(f"   {i}. {hyp.description}")
        print(f"      Confidence: {hyp.confidence:.2f}")
        print(f"      Predicted fix: {hyp.predicted_fix}")
        print(f"      Root causes: {len(hyp.root_causes)}")
        
        if hyp.testable_predictions:
            print(f"      Key prediction: {hyp.testable_predictions[0]}")
        print()
    
    # Step 4: Validate hypotheses
    print("4. Validating Hypotheses...")
    validated_hypotheses = analyzer.validate_hypotheses(
        hypotheses, scenario['recon_packets'], scenario['zapret_packets']
    )
    
    print(f"   Validated {len(validated_hypotheses)} hypotheses:")
    for i, val_hyp in enumerate(validated_hypotheses, 1):
        print(f"   {i}. {val_hyp.hypothesis.description}")
        print(f"      Validation score: {val_hyp.validation_score:.2f}")
        print(f"      Is validated: {val_hyp.is_validated}")
        print(f"      Supporting evidence: {len(val_hyp.supporting_evidence)}")
        
        if val_hyp.supporting_evidence:
            print(f"      Key evidence: {val_hyp.supporting_evidence[0].description}")
        print()
    
    # Step 5: Generate actionable recommendations
    print("5. Generating Recommendations...")
    
    # Find the most critical issues
    critical_causes = [rc for rc in root_causes if rc.blocking_severity == "CRITICAL"]
    high_impact_causes = [rc for rc in root_causes if rc.impact_on_success >= 0.8]
    
    print("   CRITICAL ISSUES TO FIX:")
    for cause in critical_causes:
        print(f"   • {cause.description}")
        print(f"     Fix: {cause.suggested_fixes[0] if cause.suggested_fixes else 'No fix suggested'}")
        print(f"     Location: {cause.code_locations[0] if cause.code_locations else 'Unknown'}")
        print(f"     Complexity: {cause.fix_complexity}")
        print()
    
    print("   HIGH IMPACT ISSUES:")
    for cause in high_impact_causes:
        if cause not in critical_causes:
            print(f"   • {cause.description}")
            print(f"     Fix: {cause.suggested_fixes[0] if cause.suggested_fixes else 'No fix suggested'}")
            print()
    
    # Find the best validated hypothesis
    if validated_hypotheses:
        best_hypothesis = max(validated_hypotheses, key=lambda vh: vh.validation_score)
        print("   PRIMARY RECOMMENDATION:")
        print(f"   Based on analysis, the primary issue is: {best_hypothesis.hypothesis.description}")
        print(f"   Recommended action: {best_hypothesis.hypothesis.predicted_fix}")
        print(f"   Confidence: {best_hypothesis.validation_score:.2f}")
        print()
    
    # Implementation order
    print("   IMPLEMENTATION ORDER:")
    sorted_causes = sorted(root_causes, key=lambda rc: (-rc.impact_on_success, -rc.confidence))
    for i, cause in enumerate(sorted_causes[:5], 1):
        complexity_emoji = {"SIMPLE": "🟢", "MODERATE": "🟡", "COMPLEX": "🔴"}.get(cause.fix_complexity, "⚪")
        print(f"   {i}. {complexity_emoji} {cause.description}")
        print(f"      Impact: {cause.impact_on_success:.2f}, Confidence: {cause.confidence:.2f}")
    
    print()
    print("=" * 60)
    print("ANALYSIS COMPLETE")
    print()
    print("Key Findings:")
    print(f"• {len(root_causes)} root causes identified")
    print(f"• {len(critical_causes)} critical blocking issues")
    print(f"• {len([vh for vh in validated_hypotheses if vh.is_validated])} validated hypotheses")
    print(f"• Primary issue: Missing fake packet generation")
    print(f"• Historical correlation: 100% of failing strategies have fake_packets_sent=0")
    print()
    print("Next Steps:")
    print("1. Implement fake packet generation in fakeddisorder attack")
    print("2. Set fake packet TTL to 3")
    print("3. Implement badsum checksum corruption")
    print("4. Fix sequence overlap calculation")
    print("5. Test against x.com domain")
    
    return {
        'root_causes': root_causes,
        'correlated_causes': correlated_causes,
        'hypotheses': hypotheses,
        'validated_hypotheses': validated_hypotheses
    }


def save_analysis_report(results: Dict[str, Any]):
    """Save detailed analysis report to JSON file."""
    
    # Convert to serializable format
    report = {
        'analysis_metadata': {
            'timestamp': '2025-10-03T12:00:00Z',
            'scenario': 'x.com fakeddisorder bypass failure',
            'analyzer_version': '1.0.0'
        },
        'root_causes': [rc.to_dict() for rc in results['root_causes']],
        'correlated_causes': [cc.to_dict() for cc in results['correlated_causes']],
        'hypotheses': [h.to_dict() for h in results['hypotheses']],
        'validated_hypotheses': [vh.to_dict() for vh in results['validated_hypotheses']],
        'summary': {
            'total_root_causes': len(results['root_causes']),
            'critical_issues': len([rc for rc in results['root_causes'] if rc.blocking_severity == "CRITICAL"]),
            'validated_hypotheses': len([vh for vh in results['validated_hypotheses'] if vh.is_validated]),
            'primary_recommendation': results['validated_hypotheses'][0].hypothesis.predicted_fix if results['validated_hypotheses'] else None
        }
    }
    
    # Save to file
    output_file = Path('root_cause_analysis_demo_report.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"Detailed analysis report saved to: {output_file}")
    return output_file


def main():
    """Main demo function."""
    try:
        results = run_comprehensive_demo()
        save_analysis_report(results)
        return True
    except Exception as e:
        print(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)