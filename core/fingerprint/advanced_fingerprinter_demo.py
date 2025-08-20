# recon/core/fingerprint/advanced_fingerprinter_demo.py
"""
Demo script for AdvancedFingerprinter - Task 10 Implementation
Demonstrates the complete fingerprinting workflow with real and simulated targets.
"""

import asyncio
import logging
import tempfile
import os

from .advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
from .advanced_models import DPIFingerprint, DPIType


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


async def demo_basic_fingerprinting():
    """Demonstrate basic fingerprinting functionality"""
    print("\n" + "=" * 60)
    print("ADVANCED FINGERPRINTER DEMO - BASIC FUNCTIONALITY")
    print("=" * 60)

    # Create temporary cache file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        # Configure fingerprinter
        config = FingerprintingConfig(
            cache_ttl=300,  # 5 minutes
            enable_ml=False,  # Disable ML for demo (no trained model)
            enable_cache=True,
            timeout=5.0,  # Short timeout for demo
            retry_attempts=1,
        )

        async with AdvancedFingerprinter(
            config=config, cache_file=cache_file
        ) as fingerprinter:
            print(f"Initialized: {fingerprinter}")

            # Show health check
            health = await fingerprinter.health_check()
            print(f"\nHealth Status: {health['status']}")
            print("Component Status:")
            for component, status in health["components"].items():
                print(f"  {component}: {status['status']}")

            # Test targets (using localhost to avoid external dependencies)
            test_targets = [
                ("127.0.0.1", 80),  # HTTP
                ("127.0.0.1", 443),  # HTTPS
                ("127.0.0.1", 53),  # DNS
            ]

            print(f"\nTesting {len(test_targets)} targets...")

            for target, port in test_targets:
                print(f"\n--- Fingerprinting {target}:{port} ---")

                try:
                    # Perform fingerprinting
                    fingerprint = await fingerprinter.fingerprint_target(target, port)

                    # Display results
                    print(f"Target: {fingerprint.target}")
                    print(f"DPI Type: {fingerprint.dpi_type.value}")
                    print(f"Confidence: {fingerprint.confidence:.2f}")
                    print(f"Reliability: {fingerprint.reliability_score:.2f}")
                    print(f"Analysis Duration: {fingerprint.analysis_duration:.2f}s")
                    print(
                        f"Analysis Methods: {', '.join(fingerprint.analysis_methods_used)}"
                    )

                    # Show key findings
                    findings = []
                    if fingerprint.rst_injection_detected:
                        findings.append(
                            f"RST injection ({fingerprint.rst_source_analysis})"
                        )
                    if fingerprint.dns_hijacking_detected:
                        findings.append("DNS hijacking")
                    if fingerprint.http_header_filtering:
                        findings.append("HTTP header filtering")
                    if fingerprint.content_inspection_depth > 0:
                        findings.append(
                            f"Content inspection (depth: {fingerprint.content_inspection_depth})"
                        )

                    if findings:
                        print(f"Key Findings: {', '.join(findings)}")
                    else:
                        print("Key Findings: No blocking detected")

                    # Show recommended strategies
                    strategies = fingerprint.get_recommended_strategies()
                    if strategies:
                        print(f"Recommended Strategies: {', '.join(strategies[:3])}...")

                except Exception as e:
                    print(f"Fingerprinting failed: {e}")

            # Show final statistics
            stats = fingerprinter.get_stats()
            print("\n--- Final Statistics ---")
            print(f"Fingerprints Created: {stats['fingerprints_created']}")
            print(f"Cache Hits: {stats['cache_hits']}")
            print(f"Cache Misses: {stats['cache_misses']}")
            print(f"Cache Hit Rate: {stats['cache_hit_rate']:.1%}")
            print(f"ML Classifications: {stats['ml_classifications']}")
            print(f"Fallback Classifications: {stats['fallback_classifications']}")
            print(f"Errors: {stats['errors']}")
            print(f"Average Analysis Time: {stats['avg_analysis_time']:.2f}s")

    finally:
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass


async def demo_heuristic_classification():
    """Demonstrate heuristic classification patterns"""
    print("\n" + "=" * 60)
    print("ADVANCED FINGERPRINTER DEMO - HEURISTIC CLASSIFICATION")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        config = FingerprintingConfig(enable_cache=False, enable_ml=False)
        fingerprinter = AdvancedFingerprinter(config=config, cache_file=cache_file)

        # Test different DPI patterns
        test_patterns = [
            {
                "name": "Roskomnadzor TSPU (Fast RST)",
                "fingerprint": DPIFingerprint(
                    target="blocked-site.com:443",
                    rst_injection_detected=True,
                    dns_hijacking_detected=True,
                    http_header_filtering=True,
                    connection_reset_timing=25.0,  # Fast reset
                ),
            },
            {
                "name": "Roskomnadzor DPI (Slow RST)",
                "fingerprint": DPIFingerprint(
                    target="blocked-site2.com:443",
                    rst_injection_detected=True,
                    dns_hijacking_detected=True,
                    http_header_filtering=True,
                    connection_reset_timing=150.0,  # Slow reset
                ),
            },
            {
                "name": "Commercial DPI",
                "fingerprint": DPIFingerprint(
                    target="corporate-site.com:443",
                    content_inspection_depth=2000,
                    user_agent_filtering=True,
                    content_type_filtering=True,
                    http_header_filtering=True,
                ),
            },
            {
                "name": "ISP Transparent Proxy",
                "fingerprint": DPIFingerprint(
                    target="redirected-site.com:443",
                    redirect_injection=True,
                    http_response_modification=True,
                    rst_injection_detected=False,
                ),
            },
            {
                "name": "Firewall-based Blocking",
                "fingerprint": DPIFingerprint(
                    target="firewall-blocked.com:443",
                    rst_injection_detected=True,
                    dns_hijacking_detected=False,
                    protocol_whitelist=["http", "https", "dns"],
                ),
            },
            {
                "name": "Unknown/Clean Connection",
                "fingerprint": DPIFingerprint(target="clean-site.com:443"),
            },
        ]

        print("Testing heuristic classification patterns:\n")

        for pattern in test_patterns:
            fingerprint = pattern["fingerprint"]
            dpi_type, confidence = fingerprinter._heuristic_classification(fingerprint)

            print(f"Pattern: {pattern['name']}")
            print(f"  Classified as: {dpi_type.value.replace('_', ' ').title()}")
            print(f"  Confidence: {confidence:.2f}")
            print(
                f"  Difficulty Score: {fingerprint.calculate_evasion_difficulty():.2f}"
            )

            # Show key characteristics
            characteristics = []
            if fingerprint.rst_injection_detected:
                characteristics.append(
                    f"RST injection ({fingerprint.connection_reset_timing:.0f}ms)"
                )
            if fingerprint.dns_hijacking_detected:
                characteristics.append("DNS hijacking")
            if fingerprint.http_header_filtering:
                characteristics.append("Header filtering")
            if fingerprint.content_inspection_depth > 0:
                characteristics.append(
                    f"Content inspection ({fingerprint.content_inspection_depth})"
                )
            if fingerprint.redirect_injection:
                characteristics.append("Redirect injection")
            if len(fingerprint.protocol_whitelist) > 0:
                characteristics.append(
                    f"Protocol whitelist ({len(fingerprint.protocol_whitelist)})"
                )

            if characteristics:
                print(f"  Characteristics: {', '.join(characteristics)}")

            # Show recommended strategies
            strategies = fingerprint.get_recommended_strategies()
            if strategies:
                print(f"  Recommended: {', '.join(strategies[:3])}")

            print()

    finally:
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass


async def demo_ml_feature_extraction():
    """Demonstrate ML feature extraction"""
    print("\n" + "=" * 60)
    print("ADVANCED FINGERPRINTER DEMO - ML FEATURE EXTRACTION")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        fingerprinter = AdvancedFingerprinter(cache_file=cache_file)

        # Create a comprehensive fingerprint with many features
        fingerprint = DPIFingerprint(
            target="complex-dpi.com:443",
            dpi_type=DPIType.COMMERCIAL_DPI,
            confidence=0.85,
            # TCP features
            rst_injection_detected=True,
            rst_source_analysis="middlebox",
            tcp_window_manipulation=True,
            sequence_number_anomalies=False,
            tcp_options_filtering=True,
            connection_reset_timing=75.0,
            handshake_anomalies=["window_anomaly", "option_anomaly"],
            fragmentation_handling="modified",
            mss_clamping_detected=True,
            tcp_timestamp_manipulation=False,
            # HTTP features
            http_header_filtering=True,
            content_inspection_depth=1500,
            user_agent_filtering=True,
            host_header_manipulation=False,
            http_method_restrictions=["POST", "PUT", "DELETE"],
            content_type_filtering=True,
            redirect_injection=False,
            http_response_modification=True,
            keep_alive_manipulation=True,
            chunked_encoding_handling="blocked",
            # DNS features
            dns_hijacking_detected=True,
            dns_response_modification=True,
            dns_query_filtering=False,
            doh_blocking=True,
            dot_blocking=False,
            dns_cache_poisoning=False,
            dns_timeout_manipulation=True,
            recursive_resolver_blocking=False,
            dns_over_tcp_blocking=True,
            edns_support=False,
            # Additional features
            supports_ipv6=False,
            ip_fragmentation_handling="blocked",
            packet_size_limitations=1200,
            protocol_whitelist=["http", "https"],
            geographic_restrictions=True,
            time_based_filtering=False,
            analysis_duration=3.5,
            reliability_score=0.9,
            analysis_methods_used=["tcp_analysis", "http_analysis", "dns_analysis"],
        )

        print("Sample DPI Fingerprint:")
        print(f"  Target: {fingerprint.target}")
        print(f"  Type: {fingerprint.dpi_type.value}")
        print(f"  Summary: {fingerprint.get_summary()}")
        print()

        # Extract ML features
        features = fingerprinter._extract_ml_features(fingerprint)

        print("Extracted ML Features:")
        print(f"  Total features: {len(features)}")
        print()

        # Group features by category
        feature_categories = {
            "TCP Features": [
                k
                for k in features.keys()
                if k.startswith(
                    ("tcp_", "rst_", "connection_", "handshake_", "mss_", "sequence_")
                )
            ],
            "HTTP Features": [
                k
                for k in features.keys()
                if k.startswith(
                    (
                        "http_",
                        "content_",
                        "user_agent",
                        "host_header",
                        "redirect_",
                        "keep_alive",
                        "chunked_",
                    )
                )
            ],
            "DNS Features": [
                k
                for k in features.keys()
                if k.startswith(("dns_", "doh_", "dot_", "edns_", "recursive_"))
            ],
            "General Features": [
                k
                for k in features.keys()
                if k.startswith(
                    (
                        "supports_",
                        "geographic_",
                        "time_based",
                        "packet_",
                        "protocol_",
                        "analysis_",
                    )
                )
            ],
        }

        for category, feature_names in feature_categories.items():
            if feature_names:
                print(f"{category}:")
                for feature_name in sorted(feature_names):
                    value = features[feature_name]
                    print(f"  {feature_name}: {value}")
                print()

        # Show reliability calculation
        reliability = fingerprinter._calculate_reliability_score(fingerprint)
        print(f"Calculated Reliability Score: {reliability:.3f}")

        # Show difficulty calculation
        difficulty = fingerprint.calculate_evasion_difficulty()
        print(f"Evasion Difficulty Score: {difficulty:.3f}")

        # Show recommended strategies
        strategies = fingerprint.get_recommended_strategies()
        print(f"Recommended Strategies ({len(strategies)}): {', '.join(strategies)}")

    finally:
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass


async def demo_cache_functionality():
    """Demonstrate cache functionality"""
    print("\n" + "=" * 60)
    print("ADVANCED FINGERPRINTER DEMO - CACHE FUNCTIONALITY")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
        cache_file = f.name

    try:
        config = FingerprintingConfig(
            cache_ttl=10, enable_cache=True  # Short TTL for demo
        )

        async with AdvancedFingerprinter(
            config=config, cache_file=cache_file
        ) as fingerprinter:
            if not fingerprinter.cache:
                print("Cache is not available for this demo")
                return

            print("Testing cache functionality...")

            # Create some test fingerprints
            test_fingerprints = [
                DPIFingerprint(
                    target="cache-test-1.com:443",
                    dpi_type=DPIType.ROSKOMNADZOR_TSPU,
                    confidence=0.9,
                ),
                DPIFingerprint(
                    target="cache-test-2.com:443",
                    dpi_type=DPIType.COMMERCIAL_DPI,
                    confidence=0.8,
                ),
                DPIFingerprint(
                    target="cache-test-3.com:443",
                    dpi_type=DPIType.ISP_TRANSPARENT_PROXY,
                    confidence=0.7,
                ),
            ]

            # Store fingerprints in cache
            print("\nStoring fingerprints in cache...")
            for fp in test_fingerprints:
                fingerprinter.cache.set(fp.target, fp)
                print(f"  Cached: {fp.target} -> {fp.dpi_type.value}")

            # Retrieve from cache
            print("\nRetrieving from cache...")
            for fp in test_fingerprints:
                cached = fingerprinter.get_cached_fingerprint(fp.target)
                if cached:
                    print(f"  Retrieved: {cached.target} -> {cached.dpi_type.value}")
                else:
                    print(f"  Not found: {fp.target}")

            # Show cache statistics
            cache_stats = fingerprinter.cache.get_stats()
            print("\nCache Statistics:")
            print(f"  Entries: {cache_stats['entries']}")
            print(f"  Hits: {cache_stats['hits']}")
            print(f"  Misses: {cache_stats['misses']}")
            print(f"  Hit Rate: {cache_stats['hit_rate_percent']:.1f}%")
            print(f"  Cache File Size: {cache_stats['cache_file_size']} bytes")

            # Test cache invalidation
            print(f"\nInvalidating cache for {test_fingerprints[0].target}...")
            fingerprinter.invalidate_cache(test_fingerprints[0].target)

            cached = fingerprinter.get_cached_fingerprint(test_fingerprints[0].target)
            if cached:
                print("  Still in cache (unexpected)")
            else:
                print("  Successfully invalidated")

            # Show updated stats
            cache_stats = fingerprinter.cache.get_stats()
            print(f"  Updated entries count: {cache_stats['entries']}")

    finally:
        try:
            os.unlink(cache_file)
        except FileNotFoundError:
            pass


async def main():
    """Run all demos"""
    print("ADVANCED DPI FINGERPRINTER DEMONSTRATION")
    print("Task 10 Implementation - Complete Fingerprinting Workflow")

    try:
        await demo_basic_fingerprinting()
        await demo_heuristic_classification()
        await demo_ml_feature_extraction()
        await demo_cache_functionality()

        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nThe AdvancedFingerprinter demonstrates:")
        print("✓ Async fingerprinting workflow with parallel metric collection")
        print("✓ Cache integration with automatic cache hits/misses handling")
        print("✓ Comprehensive error handling with graceful degradation")
        print("✓ ML feature extraction and heuristic classification")
        print("✓ Integration with specialized analyzers (TCP, HTTP, DNS)")
        print("✓ Statistics tracking and health monitoring")
        print("✓ Configurable components and fallback mechanisms")

    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
