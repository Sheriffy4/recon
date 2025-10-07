#!/usr/bin/env python3
"""
Demo script for the FixGenerator class.

This script demonstrates the automated fix generation system for PCAP comparison issues.
"""

import json
from pathlib import Path

from core.pcap_analysis.fix_generator import FixGenerator, FixType, RiskLevel
from core.pcap_analysis.root_cause_analyzer import RootCause, RootCauseType, Evidence
from core.pcap_analysis.strategy_config import StrategyDifference
from core.pcap_analysis.packet_sequence_analyzer import FakePacketAnalysis


def create_sample_root_causes():
    """Create sample root causes for demonstration."""
    return [
        RootCause(
            cause_type=RootCauseType.INCORRECT_TTL,
            description="TTL value mismatch between recon and zapret for fake packets",
            affected_components=["core/bypass/packet/builder.py", "fake_packet_builder"],
            evidence=[
                Evidence(
                    type="ttl_mismatch",
                    description="Recon uses TTL=64, zapret uses TTL=3 for fake packets",
                    data={
                        "recon_ttl": 64,
                        "zapret_ttl": 3,
                        "packet_count": 15,
                        "success_rate_impact": 0.85
                    },
                    confidence=0.95
                ),
                Evidence(
                    type="pcap_analysis",
                    description="PCAP analysis shows consistent TTL=3 in zapret fake packets",
                    data={
                        "zapret_fake_packets": 5,
                        "all_have_ttl_3": True,
                        "recon_fake_packets": 5,
                        "all_have_ttl_64": True
                    },
                    confidence=1.0
                )
            ],
            confidence=0.95,
            fix_complexity="SIMPLE",
            impact_on_success=0.85,
            suggested_fixes=[
                "Change TTL value from 64 to 3 in fake packet builder",
                "Add TTL parameter validation in strategy configuration"
            ],
            code_locations=[
                "core/bypass/packet/builder.py:build_fake_packet",
                "core/bypass/attacks/tcp/fake_disorder_attack.py"
            ]
        ),
        
        RootCause(
            cause_type=RootCauseType.WRONG_SPLIT_POSITION,
            description="Split position calculation differs between recon and zapret",
            affected_components=["core/bypass/attacks/tcp/fake_disorder_attack.py"],
            evidence=[
                Evidence(
                    type="split_position_mismatch",
                    description="Recon calculates split_pos dynamically, zapret uses fixed split_pos=3",
                    data={
                        "recon_split_pos": 5,
                        "zapret_split_pos": 3,
                        "domain": "x.com",
                        "strategy": "fake,fakeddisorder"
                    },
                    confidence=0.9
                )
            ],
            confidence=0.9,
            fix_complexity="MODERATE",
            impact_on_success=0.7,
            suggested_fixes=[
                "Use fixed split_pos=3 instead of dynamic calculation",
                "Add split position validation against zapret behavior"
            ]
        ),
        
        RootCause(
            cause_type=RootCauseType.MISSING_FOOLING_METHOD,
            description="Fooling methods not properly applied to fake packets",
            affected_components=["core/bypass/packet/builder.py"],
            evidence=[
                Evidence(
                    type="fooling_method_missing",
                    description="badsum and badseq not applied consistently",
                    data={
                        "expected_methods": ["badsum", "badseq"],
                        "applied_methods": ["badsum"],
                        "missing_methods": ["badseq"]
                    },
                    confidence=0.8
                )
            ],
            confidence=0.8,
            fix_complexity="MODERATE",
            impact_on_success=0.6
        ),
        
        RootCause(
            cause_type=RootCauseType.TIMING_ISSUES,
            description="Packet sending timing differs from zapret optimal timing",
            affected_components=["core/bypass/packet/sender.py"],
            evidence=[
                Evidence(
                    type="timing_analysis",
                    description="Recon has longer delays between packets",
                    data={
                        "recon_avg_delay": 0.1,
                        "zapret_avg_delay": 0.001,
                        "optimal_delay": 0.001
                    },
                    confidence=0.75
                )
            ],
            confidence=0.75,
            fix_complexity="SIMPLE",
            impact_on_success=0.4
        )
    ]


def create_sample_strategy_differences():
    """Create sample strategy differences for demonstration."""
    return [
        StrategyDifference(
            parameter="ttl",
            recon_value=64,
            zapret_value=3,
            impact_level="HIGH",
            description="TTL parameter mismatch in fake,fakeddisorder strategy"
        ),
        
        StrategyDifference(
            parameter="split_pos",
            recon_value=5,
            zapret_value=3,
            impact_level="HIGH",
            description="Split position parameter mismatch"
        ),
        
        StrategyDifference(
            parameter="fooling",
            recon_value=["badsum"],
            zapret_value=["badsum", "badseq"],
            impact_level="MEDIUM",
            description="Missing badseq fooling method"
        )
    ]


def create_sample_fake_analysis():
    """Create sample fake packet analysis for demonstration."""
    return FakePacketAnalysis(
        is_fake=True,
        confidence=0.4,  # Low compliance
        indicators=["ttl_mismatch", "timing_suspicious"],
        ttl_suspicious=True,  # TTL should be 3, not 64
        checksum_invalid=False,  # Should be True for fake packets
        timing_suspicious=True,  # Too slow timing
        payload_suspicious=False
    )


def demonstrate_fix_generation():
    """Demonstrate the complete fix generation process."""
    print("🔧 FixGenerator Demo - Automated Fix Generation System")
    print("=" * 60)
    
    # Initialize the fix generator
    generator = FixGenerator()
    
    # Create sample data
    root_causes = create_sample_root_causes()
    strategy_differences = create_sample_strategy_differences()
    fake_analysis = create_sample_fake_analysis()
    
    print(f"\n📊 Input Analysis:")
    print(f"  • Root causes identified: {len(root_causes)}")
    print(f"  • Strategy differences: {len(strategy_differences)}")
    print(f"  • Fake packet analysis: Confidence {fake_analysis.confidence:.1%}")
    
    # Generate code fixes
    print(f"\n🛠️  Generating Code Fixes...")
    code_fixes = generator.generate_code_fixes(root_causes)
    print(f"  • Generated {len(code_fixes)} code fixes")
    
    for fix in code_fixes:
        print(f"    - {fix.fix_type.value}: {fix.description}")
        print(f"      Confidence: {fix.confidence:.1%}, Risk: {fix.risk_level.value}")
    
    # Generate strategy patches
    print(f"\n📋 Generating Strategy Patches...")
    strategy_patches = generator.create_strategy_patches(strategy_differences)
    print(f"  • Generated {len(strategy_patches)} strategy patches")
    
    for patch in strategy_patches:
        print(f"    - {patch.strategy_name}: {patch.description}")
        print(f"      Changes: {patch.parameter_changes}")
        print(f"      Confidence: {patch.confidence:.1%}")
    
    # Generate packet sequence fixes
    print(f"\n🔄 Generating Packet Sequence Fixes...")
    sequence_fixes = generator.generate_packet_sequence_fixes(fake_analysis)
    print(f"  • Generated {len(sequence_fixes)} sequence fixes")
    
    for fix in sequence_fixes:
        print(f"    - {fix.sequence_type}: {fix.description}")
        if fix.split_position:
            print(f"      Split position: {fix.split_position}")
        if fix.ttl_value:
            print(f"      TTL value: {fix.ttl_value}")
    
    # Generate checksum fixes
    print(f"\n✅ Generating Checksum Fixes...")
    checksum_analysis = {
        "fake_packets_have_bad_checksum": fake_analysis.checksum_invalid,
        "real_packets_have_good_checksum": not fake_analysis.checksum_invalid
    }
    checksum_fixes = generator.create_checksum_corruption_fix(checksum_analysis)
    print(f"  • Generated {len(checksum_fixes)} checksum fixes")
    
    for fix in checksum_fixes:
        print(f"    - {fix.description}")
        print(f"      Confidence: {fix.confidence:.1%}")
    
    # Generate timing fixes
    print(f"\n⏱️  Generating Timing Fixes...")
    timing_analysis = {
        "delay_too_long": fake_analysis.timing_suspicious,
        "optimal_delay": 0.001,
        "send_order_incorrect": True,
        "correct_send_order": ["fake", "real1", "real2"]
    }
    timing_fixes = generator.generate_timing_optimization_fixes(timing_analysis)
    print(f"  • Generated {len(timing_fixes)} timing fixes")
    
    for fix in timing_fixes:
        print(f"    - {fix.fix_type.value}: {fix.description}")
    
    # Generate regression tests
    print(f"\n🧪 Generating Regression Tests...")
    all_fixes = code_fixes + checksum_fixes + timing_fixes
    regression_tests = generator.create_regression_tests(all_fixes)
    print(f"  • Generated {len(regression_tests)} regression tests")
    
    for test in regression_tests:
        print(f"    - {test.test_name} ({test.test_type})")
        if test.pcap_validation:
            print(f"      Includes PCAP validation")
    
    # Show summary
    print(f"\n📈 Fix Generation Summary:")
    summary = generator.get_fix_summary()
    print(f"  • Total fixes: {summary['total_fixes']}")
    print(f"  • High confidence fixes: {len(summary['high_confidence_fixes'])}")
    
    print(f"\n  Fix types breakdown:")
    for fix_type, count in summary['fix_types'].items():
        if count > 0:
            print(f"    - {fix_type}: {count}")
    
    print(f"\n  Risk levels breakdown:")
    for risk_level, count in summary['risk_levels'].items():
        if count > 0:
            print(f"    - {risk_level}: {count}")
    
    # Export fixes
    output_file = "generated_fixes_demo.json"
    generator.export_fixes(output_file)
    print(f"\n💾 Exported all fixes to: {output_file}")
    
    # Show sample fix details
    if code_fixes:
        print(f"\n🔍 Sample Fix Details:")
        sample_fix = code_fixes[0]
        print(f"  Fix ID: {sample_fix.fix_id}")
        print(f"  Type: {sample_fix.fix_type.value}")
        print(f"  File: {sample_fix.file_path}")
        print(f"  Function: {sample_fix.function_name}")
        print(f"  Description: {sample_fix.description}")
        print(f"  Confidence: {sample_fix.confidence:.1%}")
        print(f"  Risk Level: {sample_fix.risk_level.value}")
        
        if sample_fix.old_code and sample_fix.new_code:
            print(f"\n  Code Change:")
            print(f"    Old: {sample_fix.old_code}")
            print(f"    New: {sample_fix.new_code}")
        
        if sample_fix.test_cases:
            print(f"\n  Test Cases:")
            for test_case in sample_fix.test_cases:
                print(f"    - {test_case}")
    
    # Show validation requirements
    print(f"\n✅ Validation Requirements:")
    all_validation_reqs = set()
    for fix in all_fixes:
        all_validation_reqs.update(fix.validation_requirements)
    
    for req in sorted(all_validation_reqs):
        print(f"  • {req}")
    
    print(f"\n🎯 Next Steps:")
    print(f"  1. Review generated fixes for accuracy and completeness")
    print(f"  2. Apply high-confidence, low-risk fixes first")
    print(f"  3. Run regression tests to validate fixes")
    print(f"  4. Test against target domains (x.com, twitter.com)")
    print(f"  5. Monitor success rates and adjust as needed")
    
    return generator


def demonstrate_fix_prioritization():
    """Demonstrate fix prioritization and risk assessment."""
    print(f"\n🎯 Fix Prioritization Demo")
    print("=" * 40)
    
    generator = FixGenerator()
    root_causes = create_sample_root_causes()
    fixes = generator.generate_code_fixes(root_causes)
    
    # Sort fixes by priority (confidence * impact, risk level)
    def fix_priority_score(fix):
        risk_weights = {
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 0.8,
            RiskLevel.HIGH: 0.6,
            RiskLevel.CRITICAL: 0.4
        }
        return fix.confidence * risk_weights.get(fix.risk_level, 0.5)
    
    prioritized_fixes = sorted(fixes, key=fix_priority_score, reverse=True)
    
    print(f"📊 Prioritized Fix List:")
    for i, fix in enumerate(prioritized_fixes, 1):
        priority_score = fix_priority_score(fix)
        print(f"  {i}. {fix.description}")
        print(f"     Priority Score: {priority_score:.2f}")
        print(f"     Confidence: {fix.confidence:.1%}, Risk: {fix.risk_level.value}")
        print(f"     Type: {fix.fix_type.value}")
        print()
    
    # Recommend implementation order
    print(f"🚀 Recommended Implementation Order:")
    high_priority = [f for f in prioritized_fixes if fix_priority_score(f) >= 0.8]
    medium_priority = [f for f in prioritized_fixes if 0.6 <= fix_priority_score(f) < 0.8]
    low_priority = [f for f in prioritized_fixes if fix_priority_score(f) < 0.6]
    
    print(f"  Phase 1 (High Priority): {len(high_priority)} fixes")
    for fix in high_priority:
        print(f"    • {fix.fix_type.value}: {fix.description[:50]}...")
    
    print(f"  Phase 2 (Medium Priority): {len(medium_priority)} fixes")
    for fix in medium_priority:
        print(f"    • {fix.fix_type.value}: {fix.description[:50]}...")
    
    print(f"  Phase 3 (Low Priority): {len(low_priority)} fixes")
    for fix in low_priority:
        print(f"    • {fix.fix_type.value}: {fix.description[:50]}...")


if __name__ == "__main__":
    try:
        # Run the main demonstration
        generator = demonstrate_fix_generation()
        
        # Run prioritization demo
        demonstrate_fix_prioritization()
        
        print(f"\n✅ Demo completed successfully!")
        print(f"📁 Check 'generated_fixes_demo.json' for exported fixes")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()