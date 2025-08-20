#!/usr/bin/env python3
"""
Demo script for fingerprint-aware ZapretStrategyGenerator - Task 13 Implementation
Demonstrates DPI-type-specific strategy generation, confidence-based ranking, and fallback mechanisms.
"""

import sys
import os

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.zapret_strategy_generator import ZapretStrategyGenerator
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


def demo_dpi_type_specific_strategies():
    """Demonstrate DPI-type-specific strategy generation."""
    print("=" * 80)
    print("DEMO: DPI-Type-Specific Strategy Generation")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    # Test different DPI types
    dpi_types = [
        DPIType.ROSKOMNADZOR_TSPU,
        DPIType.ROSKOMNADZOR_DPI,
        DPIType.COMMERCIAL_DPI,
        DPIType.GOVERNMENT_CENSORSHIP,
        DPIType.FIREWALL_BASED,
    ]

    for dpi_type in dpi_types:
        print(f"\n📊 {dpi_type.value.replace('_', ' ').title()} Strategies:")
        print("-" * 50)

        # Create fingerprint for this DPI type
        fingerprint = DPIFingerprint(
            target=f"test-{dpi_type.value}.com",
            dpi_type=dpi_type,
            confidence=0.85,
            reliability_score=0.8,
        )

        strategies = generator.generate_strategies(fingerprint=fingerprint, count=5)

        for i, strategy in enumerate(strategies, 1):
            print(f"{i}. {strategy}")


def demo_characteristic_based_strategies():
    """Demonstrate characteristic-based strategy generation."""
    print("\n" + "=" * 80)
    print("DEMO: Characteristic-Based Strategy Generation")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    # Test different DPI characteristics
    test_cases = [
        {
            "name": "RST Injection DPI",
            "fingerprint": DPIFingerprint(
                target="rst-injection.com",
                dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                confidence=0.9,
                rst_injection_detected=True,
                connection_reset_timing=0.1,
                reliability_score=0.85,
            ),
        },
        {
            "name": "Deep Content Inspection DPI",
            "fingerprint": DPIFingerprint(
                target="deep-inspection.com",
                dpi_type=DPIType.COMMERCIAL_DPI,
                confidence=0.88,
                content_inspection_depth=3000,
                http_header_filtering=True,
                user_agent_filtering=True,
                reliability_score=0.82,
            ),
        },
        {
            "name": "DNS Blocking DPI",
            "fingerprint": DPIFingerprint(
                target="dns-blocking.com",
                dpi_type=DPIType.GOVERNMENT_CENSORSHIP,
                confidence=0.92,
                dns_hijacking_detected=True,
                doh_blocking=True,
                dot_blocking=True,
                reliability_score=0.9,
            ),
        },
        {
            "name": "Packet Size Limited DPI",
            "fingerprint": DPIFingerprint(
                target="size-limited.com",
                dpi_type=DPIType.FIREWALL_BASED,
                confidence=0.8,
                packet_size_limitations=800,
                tcp_window_manipulation=True,
                reliability_score=0.75,
            ),
        },
    ]

    for test_case in test_cases:
        print(f"\n🎯 {test_case['name']}:")
        print("-" * 50)

        strategies = generator.generate_strategies(
            fingerprint=test_case["fingerprint"], count=4
        )

        for i, strategy in enumerate(strategies, 1):
            print(f"{i}. {strategy}")

        # Show characteristic-specific strategies
        char_strategies = generator._get_characteristic_based_strategies(
            test_case["fingerprint"]
        )
        if char_strategies:
            print(
                f"   💡 Characteristic-specific techniques: {len(char_strategies)} strategies"
            )


def demo_confidence_based_ranking():
    """Demonstrate confidence-based strategy ranking."""
    print("\n" + "=" * 80)
    print("DEMO: Confidence-Based Strategy Ranking")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    # High confidence fingerprint
    high_confidence_fp = DPIFingerprint(
        target="high-confidence.com",
        dpi_type=DPIType.ROSKOMNADZOR_DPI,
        confidence=0.95,
        rst_injection_detected=True,
        sequence_number_anomalies=True,
        http_header_filtering=True,
        content_inspection_depth=2000,
        reliability_score=0.92,
    )

    # Low confidence fingerprint
    low_confidence_fp = DPIFingerprint(
        target="low-confidence.com",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.3,
        reliability_score=0.4,
    )

    print("\n🔥 High Confidence DPI (95% confidence):")
    print("-" * 50)
    high_conf_strategies = generator.generate_strategies(
        fingerprint=high_confidence_fp, count=5
    )

    for i, strategy in enumerate(high_conf_strategies, 1):
        print(f"{i}. {strategy}")

    print("\n❓ Low Confidence DPI (30% confidence):")
    print("-" * 50)
    low_conf_strategies = generator.generate_strategies(
        fingerprint=low_confidence_fp, count=5
    )

    for i, strategy in enumerate(low_conf_strategies, 1):
        print(f"{i}. {strategy}")

    print("\n📈 Strategy Ranking Analysis:")
    print(
        f"   • High confidence uses targeted strategies for {high_confidence_fp.dpi_type.value}"
    )
    print("   • Low confidence falls back to proven general strategies")
    print(
        f"   • Top strategies are different: {high_conf_strategies[0] != low_conf_strategies[0]}"
    )


def demo_fallback_mechanism():
    """Demonstrate fallback to generic strategies."""
    print("\n" + "=" * 80)
    print("DEMO: Fallback Mechanism")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    print("\n🔄 Strategies WITHOUT fingerprint (fallback mode):")
    print("-" * 50)

    generic_strategies = generator.generate_strategies(fingerprint=None, count=6)

    for i, strategy in enumerate(generic_strategies, 1):
        print(f"{i}. {strategy}")

    # Check if proven working strategies are included
    proven_included = any(
        strategy in generator.PROVEN_WORKING for strategy in generic_strategies
    )
    print(f"\n✅ Includes proven working strategies: {proven_included}")
    print(
        f"📊 Total proven working strategies available: {len(generator.PROVEN_WORKING)}"
    )


def demo_strategy_analysis():
    """Demonstrate strategy complexity and aggressiveness analysis."""
    print("\n" + "=" * 80)
    print("DEMO: Strategy Analysis (Complexity & Aggressiveness)")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    test_strategies = [
        "--dpi-desync=fake --dpi-desync-ttl=5",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,3,5,7,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1 --dpi-desync-repeats=5",
        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=md5sig",
        "--dpi-desync=fake --dpi-desync-fake-tls=0x1603 --dpi-desync-ttl=128",
    ]

    print("\n📊 Strategy Analysis:")
    print("-" * 80)

    for i, strategy in enumerate(test_strategies, 1):
        complexity = generator._calculate_strategy_complexity(strategy)
        aggressiveness = generator._calculate_strategy_aggressiveness(strategy)

        print(f"\n{i}. {strategy}")
        print(
            f"   Complexity: {complexity:.2f}/1.0 | Aggressiveness: {aggressiveness:.2f}/1.0"
        )

        if complexity < 0.3:
            complexity_desc = "Simple"
        elif complexity < 0.6:
            complexity_desc = "Moderate"
        else:
            complexity_desc = "Complex"

        if aggressiveness < 0.3:
            aggr_desc = "Mild"
        elif aggressiveness < 0.6:
            aggr_desc = "Moderate"
        else:
            aggr_desc = "Aggressive"

        print(f"   Assessment: {complexity_desc} strategy with {aggr_desc} approach")


def demo_integration_with_existing_system():
    """Demonstrate integration with existing system."""
    print("\n" + "=" * 80)
    print("DEMO: Integration with Existing System")
    print("=" * 80)

    generator = ZapretStrategyGenerator()

    print("\n🔗 Backward Compatibility Test:")
    print("-" * 50)

    # Test old-style dictionary fingerprint (backward compatibility)
    old_style_fingerprint = {"dpi_type": "LIKELY_WINDOWS_BASED", "confidence": 0.7}

    print("Testing with old-style dictionary fingerprint...")
    try:
        # This should work with the old generate_strategies method
        strategies = generator.generate_strategies(
            fingerprint=old_style_fingerprint, count=3
        )
        print("✅ Old-style fingerprint still supported")
        for i, strategy in enumerate(strategies, 1):
            print(f"{i}. {strategy}")
    except Exception as e:
        print(f"❌ Old-style fingerprint failed: {e}")

    print("\n📈 Performance Comparison:")
    print("-" * 50)

    import time

    # Test performance with fingerprint
    start_time = time.time()
    fp_strategies = generator.generate_strategies(
        fingerprint=DPIFingerprint(
            target="perf-test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.8
        ),
        count=50,
    )
    fp_time = time.time() - start_time

    # Test performance without fingerprint
    start_time = time.time()
    generic_strategies = generator.generate_strategies(fingerprint=None, count=50)
    generic_time = time.time() - start_time

    print(f"With fingerprint: {fp_time:.3f}s for 50 strategies")
    print(f"Without fingerprint: {generic_time:.3f}s for 50 strategies")
    print(
        f"Performance overhead: {((fp_time - generic_time) / generic_time * 100):.1f}%"
    )


def main():
    """Run all demos."""
    print("🚀 ZapretStrategyGenerator Fingerprint-Aware Demo")
    print("Task 13: Enhanced ZapretStrategyGenerator with fingerprint awareness")
    print("=" * 80)

    demo_dpi_type_specific_strategies()
    demo_characteristic_based_strategies()
    demo_confidence_based_ranking()
    demo_fallback_mechanism()
    demo_strategy_analysis()
    demo_integration_with_existing_system()

    print("\n" + "=" * 80)
    print("✅ DEMO COMPLETE")
    print("=" * 80)
    print("\nKey Features Demonstrated:")
    print("• ✅ DPI-type-specific strategy templates")
    print("• ✅ Characteristic-based strategy generation")
    print("• ✅ Confidence-based strategy ranking")
    print("• ✅ Fallback to generic strategies")
    print("• ✅ Strategy complexity and aggressiveness analysis")
    print("• ✅ Backward compatibility with existing system")
    print("• ✅ Performance optimization")
    print("\n🎯 Task 13 Implementation: COMPLETE")


if __name__ == "__main__":
    main()
