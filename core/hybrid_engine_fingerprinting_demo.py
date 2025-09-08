#!/usr/bin/env python3
"""
Demo script for HybridEngine with Advanced DPI Fingerprinting Integration
Demonstrates the enhanced capabilities of fingerprint-aware strategy testing.
"""

import asyncio
import logging
import time

from core.hybrid_engine import HybridEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger(__name__)


async def demo_fingerprint_aware_testing():
    """Demonstrate fingerprint-aware strategy testing"""

    LOG.info("=== HybridEngine with Advanced DPI Fingerprinting Demo ===")

    # Initialize HybridEngine with fingerprinting enabled
    engine = HybridEngine(debug=True, enable_advanced_fingerprinting=True)

    # Check if advanced fingerprinting is available
    if not engine.advanced_fingerprinting_enabled:
        LOG.warning("Advanced fingerprinting not available - running basic demo")
        return await demo_basic_testing(engine)

    LOG.info("Advanced fingerprinting is enabled")

    # Demo data
    domain = "blocked-site.com"
    port = 443
    test_sites = [f"https://{domain}", "https://another-blocked.com"]
    ips = {"1.2.3.4", "5.6.7.8"}
    dns_cache = {domain: "1.2.3.4", "another-blocked.com": "5.6.7.8"}

    # Sample strategies to test
    strategies = [
        "--dpi-desync=fake --dpi-desync-ttl=10 --dpi-desync-fooling=badsum",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10",
        "--dpi-desync=disorder --dpi-desync-split-pos=midsld",
        "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
    ]

    try:
        # Step 1: Perform DPI fingerprinting
        LOG.info(f"\n--- Step 1: DPI Fingerprinting for {domain}:{port} ---")
        start_time = time.time()

        fingerprint = await engine.fingerprint_target(domain, port)

        fingerprint_time = time.time() - start_time

        if fingerprint:
            LOG.info(f"✓ Fingerprinting completed in {fingerprint_time:.2f}s")
            LOG.info(f"  DPI Type: {fingerprint.dpi_type.value}")
            LOG.info(f"  Confidence: {fingerprint.confidence:.2f}")
            LOG.info(f"  Reliability: {fingerprint.reliability_score:.2f}")
            LOG.info(f"  RST Injection: {fingerprint.rst_injection_detected}")
            LOG.info(
                f"  TCP Window Manipulation: {fingerprint.tcp_window_manipulation}"
            )
            LOG.info(f"  HTTP Header Filtering: {fingerprint.http_header_filtering}")
            LOG.info(f"  DNS Hijacking: {fingerprint.dns_hijacking_detected}")
        else:
            LOG.warning("✗ Fingerprinting failed")

        # Step 2: Test strategies with fingerprint awareness
        LOG.info("\n--- Step 2: Fingerprint-Aware Strategy Testing ---")

        # Mock the actual network testing for demo purposes
        original_execute = engine.execute_strategy_real_world

        async def mock_execute_strategy(strategy_str, *args, **kwargs):
            """Mock strategy execution for demo"""
            await asyncio.sleep(0.1)  # Simulate network delay

            # Simulate different success rates based on strategy and fingerprint
            if fingerprint and fingerprint.dpi_type.value == "roskomnadzor_tspu":
                if "--dpi-desync-ttl=1" in strategy_str:
                    return ("ALL_SITES_WORKING", 2, 2, 80.0)
                elif "fake" in strategy_str and "disorder" in strategy_str:
                    return ("PARTIAL_SUCCESS", 1, 2, 150.0)
                else:
                    return ("NO_SITES_WORKING", 0, 2, 0.0)
            else:
                # Generic success simulation
                if "multisplit" in strategy_str:
                    return ("PARTIAL_SUCCESS", 1, 2, 200.0)
                else:
                    return ("NO_SITES_WORKING", 0, 2, 0.0)

        engine.execute_strategy_real_world = mock_execute_strategy

        # Test strategies with fingerprinting
        results = await engine.test_strategies_hybrid(
            strategies=strategies,
            test_sites=test_sites,
            ips=ips,
            dns_cache=dns_cache,
            port=port,
            domain=domain,
            enable_fingerprinting=True,
        )

        # Step 3: Display results
        LOG.info("\n--- Step 3: Results Analysis ---")
        LOG.info(f"Tested {len(results)} strategies")

        successful_results = [r for r in results if r["success_rate"] > 0]
        LOG.info(f"Successful strategies: {len(successful_results)}")

        for i, result in enumerate(results[:5]):  # Show top 5 results
            LOG.info(
                f"  {i+1}. Success: {result['success_rate']:.0%} "
                f"({result['successful_sites']}/{result['total_sites']}) "
                f"Latency: {result['avg_latency_ms']:.1f}ms"
            )
            LOG.info(f"     Strategy: {result['strategy']}")
            LOG.info(f"     Fingerprint used: {result['fingerprint_used']}")
            if result["dpi_type"]:
                LOG.info(
                    f"     DPI Type: {result['dpi_type']} "
                    f"(confidence: {result['dpi_confidence']:.2f})"
                )

        # Step 4: Show statistics
        LOG.info("\n--- Step 4: Statistics ---")
        stats = engine.get_fingerprint_stats()

        LOG.info(f"Fingerprints created: {stats['fingerprints_created']}")
        LOG.info(f"Fingerprint-aware tests: {stats['fingerprint_aware_tests']}")
        LOG.info(f"Fallback tests: {stats['fallback_tests']}")
        LOG.info(f"Fingerprint failures: {stats['fingerprint_failures']}")

        if "advanced_cache_hit_rate" in stats:
            LOG.info(f"Cache hit rate: {stats['advanced_cache_hit_rate']:.1%}")

        # Step 5: Compare with non-fingerprint testing
        LOG.info("\n--- Step 5: Comparison with Standard Testing ---")

        # Reset stats for comparison
        engine.fingerprint_stats = {k: 0 for k in engine.fingerprint_stats}

        results_no_fp = await engine.test_strategies_hybrid(
            strategies=strategies,
            test_sites=test_sites,
            ips=ips,
            dns_cache=dns_cache,
            port=port,
            domain=domain,
            enable_fingerprinting=False,
        )

        successful_no_fp = [r for r in results_no_fp if r["success_rate"] > 0]

        LOG.info(f"Standard testing successful strategies: {len(successful_no_fp)}")
        LOG.info(f"Fingerprint-aware successful strategies: {len(successful_results)}")

        if len(successful_results) > len(successful_no_fp):
            LOG.info("✓ Fingerprint-aware testing found more successful strategies!")
        elif len(successful_results) == len(successful_no_fp):
            LOG.info("= Both methods found the same number of successful strategies")
        else:
            LOG.info("- Standard testing found more successful strategies")

        # Restore original method
        engine.execute_strategy_real_world = original_execute

    except Exception as e:
        LOG.error(f"Demo failed: {e}", exc_info=True)

    finally:
        # Cleanup
        engine.cleanup()
        LOG.info("\n=== Demo completed ===")


async def demo_basic_testing(engine: HybridEngine):
    """Demo basic testing when fingerprinting is not available"""

    LOG.info("Running basic HybridEngine demo without fingerprinting")

    # Basic demo data
    strategies = [
        "--dpi-desync=fake --dpi-desync-ttl=5",
        "--dpi-desync=disorder --dpi-desync-split-pos=3",
    ]

    test_sites = ["https://example.com"]
    ips = {"1.2.3.4"}
    dns_cache = {"example.com": "1.2.3.4"}

    # Mock basic strategy execution
    async def mock_basic_execute(strategy_str, *args, **kwargs):
        await asyncio.sleep(0.1)
        return ("PARTIAL_SUCCESS", 1, 1, 100.0)

    engine.execute_strategy_real_world = mock_basic_execute

    results = await engine.test_strategies_hybrid(
        strategies=strategies,
        test_sites=test_sites,
        ips=ips,
        dns_cache=dns_cache,
        port=443,
        domain="example.com",
    )

    LOG.info(f"Basic testing completed with {len(results)} results")
    for result in results:
        LOG.info(f"  Strategy: {result['strategy']}")
        LOG.info(f"  Success: {result['success_rate']:.0%}")


async def demo_error_handling():
    """Demonstrate error handling in fingerprinting integration"""

    LOG.info("\n=== Error Handling Demo ===")

    engine = HybridEngine(debug=True, enable_advanced_fingerprinting=True)

    if not engine.advanced_fingerprinting_enabled:
        LOG.info("Fingerprinting not available - skipping error handling demo")
        return

    # Test fingerprinting failure handling
    LOG.info("Testing fingerprinting failure handling...")

    # This should handle the error gracefully
    fingerprint = await engine.fingerprint_target("invalid-domain-12345.com", 443)

    if fingerprint is None:
        LOG.info("✓ Fingerprinting failure handled gracefully")
    else:
        LOG.info(f"Unexpected success: {fingerprint.dpi_type.value}")

    stats = engine.get_fingerprint_stats()
    LOG.info(f"Fingerprint failures recorded: {stats['fingerprint_failures']}")

    engine.cleanup()


if __name__ == "__main__":

    async def main():
        await demo_fingerprint_aware_testing()
        await demo_error_handling()

    asyncio.run(main())
