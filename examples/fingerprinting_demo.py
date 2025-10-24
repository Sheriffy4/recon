#!/usr/bin/env python3
"""
Fingerprinting System Demo - Shows the new optimized fingerprinting workflow.

This demonstrates:
1. Passive analysis (fast diagnosis)
2. Bypass probes (validate strategies)
3. Strategy mapping (get recommendations)
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer
from core.fingerprint.bypass_prober import QuickBypassProber

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger(__name__)


async def demo_passive_analysis(target: str, port: int = 443):
    """Demo 1: Passive analysis - quick diagnosis without full connection"""
    print("\n" + "=" * 80)
    print("DEMO 1: Passive Analysis (1-3 seconds)")
    print("=" * 80)

    analyzer = PassiveDPIAnalyzer(timeout=3.0)
    result = await analyzer.analyze_blocking_method(target, port)

    print(f"\nTarget: {target}:{port}")
    print(f"Blocking Method: {result.blocking_method.value}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"RST Detected: {result.rst_detected}")
    if result.rst_ttl:
        print(f"RST TTL: {result.rst_ttl}")
    if result.timeout_stage:
        print(f"Timeout Stage: {result.timeout_stage}")

    print("\nRecommended Bypasses:")
    for bypass in result.recommended_bypasses:
        print(f"  - {bypass}")

    print(f"\nAnalysis Duration: {result.analysis_duration:.2f}s")

    return result


async def demo_bypass_probes(target: str, ip: str, port: int = 443):
    """Demo 2: Bypass probes - test if strategies actually work"""
    print("\n" + "=" * 80)
    print("DEMO 2: Bypass Probes (2-6 seconds)")
    print("=" * 80)

    prober = QuickBypassProber(timeout=2.0)
    results = await prober.probe_bypasses(target, ip, port, max_probes=3)

    print(f"\nTarget: {target} ({ip}:{port})")
    print(f"Probes Run: {len(results)}")

    for i, result in enumerate(results, 1):
        status = "✅ SUCCESS" if result.success else "❌ FAILED"
        print(f"\n{i}. {result.strategy_name}: {status}")
        print(f"   Response Time: {result.response_time_ms:.1f}ms")
        print(f"   ServerHello Received: {result.server_hello_received}")
        if result.error:
            print(f"   Error: {result.error}")

    # Get best strategy
    best = prober.get_best_strategy(results)
    if best:
        print(f"\n🎯 Best Strategy: {best['name']}")
        print(f"   Response Time: {best['response_time_ms']:.1f}ms")
        print(f"   Confidence: {best['confidence']:.2f}")
    else:
        print("\n❌ No working strategies found")

    return results


async def demo_fast_fingerprinting(target: str, port: int = 443):
    """Demo 3: Fast fingerprinting - complete workflow in 5-10 seconds"""
    print("\n" + "=" * 80)
    print("DEMO 3: Fast Fingerprinting (5-10 seconds)")
    print("=" * 80)

    # Configure for fast mode
    config = FingerprintingConfig(
        analysis_level="fast",
        connect_timeout=1.5,
        tls_timeout=3.0,
        enable_http_analysis=False,  # Skip HTTP for speed
        use_system_proxy=False,
    )

    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)

    print(f"\nTarget: {target}:{port}")
    print(f"Reliability Score: {fingerprint.reliability_score:.2f}")
    print(f"Analysis Duration: {fingerprint.analysis_duration:.2f}s")

    # Show DPI type
    if fingerprint.ml_classification.predicted_dpi_type:
        print(f"DPI Type: {fingerprint.ml_classification.predicted_dpi_type}")

    # Show recommended strategies
    print(f"\nRecommended Strategies ({len(fingerprint.recommended_strategies)}):")
    for i, strategy in enumerate(fingerprint.recommended_strategies[:5], 1):
        print(f"\n{i}. {strategy.strategy_name}")
        print(f"   Effectiveness: {strategy.predicted_effectiveness:.2f}")
        print(f"   Confidence: {strategy.confidence:.2f}")
        print(f"   Reasoning: {', '.join(strategy.reasoning)}")

    # Show statistics
    stats = fingerprinter.get_statistics()
    print("\nFingerprinter Statistics:")
    print(f"  Fingerprints Created: {stats['fingerprints_created']}")
    print(f"  Cache Hits: {stats['cache_hits']}")
    print(f"  Cache Misses: {stats['cache_misses']}")

    return fingerprint


async def demo_strategy_mapping(target: str, port: int = 443):
    """Demo 4: Strategy mapping - convert fingerprint to strategies"""
    print("\n" + "=" * 80)
    print("DEMO 4: Strategy Mapping")
    print("=" * 80)

    # Get a fingerprint first
    config = FingerprintingConfig(analysis_level="balanced")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)

    # Convert to dict for mapping
    fingerprint_dict = fingerprint.to_dict()

    # Get mapped strategies
    strategies = get_strategies_for_fingerprint(fingerprint_dict)

    print(f"\nTarget: {target}:{port}")
    print(f"Mapped Strategies ({len(strategies)}):")

    for i, strategy in enumerate(strategies[:5], 1):
        print(f"\n{i}. {strategy['name']} (Priority: {strategy['priority']})")
        print(f"   Type: {strategy['type']}")
        print(f"   Params: {strategy['params']}")
        print(f"   Reasoning: {strategy['reasoning']}")

    # Show fallback strategies
    fallback = get_fallback_strategies()
    print(f"\nFallback Strategies ({len(fallback)}):")
    for strategy in fallback:
        print(f"  - {strategy['name']} (Priority: {strategy['priority']})")

    return strategies


async def demo_batch_fingerprinting(targets: list):
    """Demo 5: Batch fingerprinting with concurrency control"""
    print("\n" + "=" * 80)
    print("DEMO 5: Batch Fingerprinting")
    print("=" * 80)

    config = FingerprintingConfig(
        analysis_level="fast", connect_timeout=1.0, tls_timeout=2.0
    )

    fingerprinter = UnifiedFingerprinter(config)

    print(f"\nFingerprinting {len(targets)} targets...")
    results = await fingerprinter.fingerprint_batch(
        targets, max_concurrent=5, force_refresh=True
    )

    # Analyze results
    successful = [r for r in results if r.reliability_score > 0.5]
    failed = [r for r in results if r.reliability_score <= 0.5]

    print("\nResults:")
    print(f"  Total: {len(results)}")
    print(f"  Successful: {len(successful)}")
    print(f"  Failed: {len(failed)}")

    # Show successful fingerprints
    print("\nSuccessful Fingerprints:")
    for fp in successful:
        print(f"  - {fp.target}:{fp.port} (reliability: {fp.reliability_score:.2f})")
        if fp.recommended_strategies:
            best = fp.recommended_strategies[0]
            print(
                f"    Best strategy: {best.strategy_name} (confidence: {best.confidence:.2f})"
            )

    return results


async def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("FINGERPRINTING SYSTEM DEMO")
    print("=" * 80)

    # Example targets (replace with real targets)
    target = "example.com"
    ip = "93.184.216.34"  # example.com IP
    port = 443

    try:
        # Demo 1: Passive analysis
        await demo_passive_analysis(target, port)

        # Demo 2: Bypass probes
        # Note: This requires actual packet manipulation, so it may not work in demo
        # await demo_bypass_probes(target, ip, port)

        # Demo 3: Fast fingerprinting
        await demo_fast_fingerprinting(target, port)

        # Demo 4: Strategy mapping
        await demo_strategy_mapping(target, port)

        # Demo 5: Batch fingerprinting
        batch_targets = [(target, 443), ("www.example.com", 443), ("example.org", 443)]
        # await demo_batch_fingerprinting(batch_targets)

    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        LOG.error(f"Demo failed: {e}", exc_info=True)

    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
