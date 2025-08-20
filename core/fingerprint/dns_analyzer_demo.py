#!/usr/bin/env python3
"""
DNS Analyzer Demo - Task 6 Implementation
Demonstrates the DNS behavior analysis capabilities for DPI fingerprinting.
"""

import asyncio
import logging

from .dns_analyzer import DNSAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

LOG = logging.getLogger(__name__)


async def demo_dns_analysis():
    """Demonstrate DNS analysis capabilities"""
    print("=" * 60)
    print("DNS Behavior Analyzer Demo - Task 6 Implementation")
    print("=" * 60)

    # Create DNS analyzer
    analyzer = DNSAnalyzer(timeout=3.0, max_retries=2)

    # Test domains
    test_domains = [
        "google.com",
        "facebook.com",
        "twitter.com",
        "blocked-test-domain.example",
    ]

    print("\nAnalyzer Configuration:")
    print(f"- Timeout: {analyzer.timeout}s")
    print(f"- Max Retries: {analyzer.max_retries}")
    print(f"- DoH Servers: {list(analyzer.doh_servers.keys())}")
    print(f"- DoT Servers: {list(analyzer.dot_servers.keys())}")
    print(f"- Public Resolvers: {analyzer.public_resolvers}")

    for domain in test_domains:
        print(f"\n{'='*40}")
        print(f"Analyzing DNS behavior for: {domain}")
        print(f"{'='*40}")

        try:
            # Run DNS analysis
            results = await analyzer.analyze_dns_behavior(domain)

            # Display results
            print(f"\nAnalysis Results for {domain}:")
            print(f"- Analysis Duration: {results['analysis_duration']:.2f}s")
            print(f"- DNS Hijacking Detected: {results['dns_hijacking_detected']}")
            print(
                f"- DNS Response Modification: {results['dns_response_modification']}"
            )
            print(f"- DoH Blocking: {results['doh_blocking']}")
            print(f"- DoT Blocking: {results['dot_blocking']}")
            print(f"- DNS Cache Poisoning: {results['dns_cache_poisoning']}")
            print(f"- DNS over TCP Blocking: {results['dns_over_tcp_blocking']}")
            print(
                f"- Recursive Resolver Blocking: {results['recursive_resolver_blocking']}"
            )
            print(f"- DNS Timeout Manipulation: {results['dns_timeout_manipulation']}")
            print(f"- EDNS Support: {results['edns_support']}")

            # Count blocking indicators
            blocking_indicators = [
                results["dns_hijacking_detected"],
                results["dns_response_modification"],
                results["doh_blocking"],
                results["dot_blocking"],
                results["dns_cache_poisoning"],
                results["dns_over_tcp_blocking"],
                results["recursive_resolver_blocking"],
                results["dns_timeout_manipulation"],
            ]

            blocking_count = sum(blocking_indicators)
            total_indicators = len(blocking_indicators)

            print("\nBlocking Summary:")
            print(f"- Blocking Indicators: {blocking_count}/{total_indicators}")
            print(
                f"- Blocking Percentage: {(blocking_count/total_indicators)*100:.1f}%"
            )

            if blocking_count == 0:
                print("- Assessment: No DNS blocking detected")
            elif blocking_count <= 2:
                print("- Assessment: Minimal DNS blocking detected")
            elif blocking_count <= 5:
                print("- Assessment: Moderate DNS blocking detected")
            else:
                print("- Assessment: Comprehensive DNS blocking detected")

            # Show detailed results if available
            if "detailed_results" in results and results["detailed_results"]:
                print("\nDetailed Results:")
                for key, value in results["detailed_results"].items():
                    print(f"- {key}: {value}")

        except Exception as e:
            LOG.error(f"DNS analysis failed for {domain}: {e}")
            print(f"Error analyzing {domain}: {e}")

    print(f"\n{'='*60}")
    print("DNS Analysis Demo Complete")
    print(f"{'='*60}")


async def demo_individual_tests():
    """Demonstrate individual DNS test methods"""
    print(f"\n{'='*60}")
    print("Individual DNS Test Methods Demo")
    print(f"{'='*60}")

    analyzer = DNSAnalyzer(timeout=2.0)
    test_domain = "google.com"

    print(f"\nTesting individual methods for: {test_domain}")

    # Test DNS hijacking detection
    print("\n1. DNS Hijacking Detection:")
    try:
        result = await analyzer._detect_dns_hijacking(test_domain)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test response modification detection
    print("\n2. Response Modification Detection:")
    try:
        result = await analyzer._detect_response_modification(test_domain)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test DoH blocking
    print("\n3. DoH Blocking Test:")
    try:
        result = await analyzer._test_doh_blocking(test_domain)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test DoT blocking
    print("\n4. DoT Blocking Test:")
    try:
        result = await analyzer._test_dot_blocking(test_domain)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test EDNS support
    print("\n5. EDNS Support Test:")
    try:
        result = await analyzer._test_edns_support(test_domain)
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")


async def demo_query_methods():
    """Demonstrate different DNS query methods"""
    print(f"\n{'='*60}")
    print("DNS Query Methods Demo")
    print(f"{'='*60}")

    analyzer = DNSAnalyzer(timeout=2.0)
    test_domain = "google.com"
    resolver = "8.8.8.8"

    print(f"\nTesting query methods for: {test_domain}")

    # Test UDP query
    print("\n1. UDP DNS Query:")
    try:
        result = await analyzer._query_dns_udp(test_domain, resolver)
        if result:
            print(f"   Success: {result.answers}")
            print(f"   Response Time: {result.response_time:.3f}s")
            print(f"   Status Code: {result.status_code}")
        else:
            print("   Failed: No response")
    except Exception as e:
        print(f"   Error: {e}")

    # Test TCP query
    print("\n2. TCP DNS Query:")
    try:
        result = await analyzer._query_dns_tcp(test_domain, resolver)
        if result:
            print(f"   Success: {result.answers}")
        else:
            print("   Failed: No response")
    except Exception as e:
        print(f"   Error: {e}")

    # Test DoH query
    print("\n3. DoH Query:")
    try:
        doh_url = analyzer.doh_servers["cloudflare"]
        result = await analyzer._query_doh(test_domain, doh_url)
        if result:
            print(f"   Success: {result.answers}")
            print(f"   Status Code: {result.status_code}")
        else:
            print("   Failed: No response")
    except Exception as e:
        print(f"   Error: {e}")

    # Test DoT query
    print("\n4. DoT Query:")
    try:
        dot_host, dot_port = analyzer.dot_servers["cloudflare"]
        result = await analyzer._query_dot(test_domain, dot_host, dot_port)
        if result:
            print(f"   Success: {result.answers}")
        else:
            print("   Failed: No response")
    except Exception as e:
        print(f"   Error: {e}")


def demo_response_analysis():
    """Demonstrate DNS response analysis"""
    print(f"\n{'='*60}")
    print("DNS Response Analysis Demo")
    print(f"{'='*60}")

    analyzer = DNSAnalyzer()

    # Create test responses
    from .dns_analyzer import DNSResponse, DNSQuery, DNSRecordType
    import time

    test_query = DNSQuery(
        timestamp=time.time(),
        domain="test.com",
        record_type=DNSRecordType.A,
        query_id=12345,
        resolver="8.8.8.8",
    )

    # Normal response
    normal_response = DNSResponse(
        timestamp=time.time(),
        query=test_query,
        response_time=0.1,
        status_code=0,
        answers=["8.8.8.8"],
        flags={"qr": True, "aa": False},
    )

    # Suspicious response
    suspicious_response = DNSResponse(
        timestamp=time.time(),
        query=test_query,
        response_time=0.1,
        status_code=0,
        answers=["0.0.0.0"],  # Blocking IP
        flags={"qr": True, "aa": False},
    )

    # Private IP response
    private_response = DNSResponse(
        timestamp=time.time(),
        query=test_query,
        response_time=0.1,
        status_code=0,
        answers=["192.168.1.1"],  # Private IP
        flags={"qr": True, "aa": False},
    )

    print("\n1. Normal Response Analysis:")
    print(f"   Answers: {normal_response.answers}")
    print(f"   Suspicious: {analyzer._is_suspicious_response(normal_response)}")
    print(f"   Patterns: {analyzer._analyze_response_patterns(normal_response)}")

    print("\n2. Suspicious Response Analysis:")
    print(f"   Answers: {suspicious_response.answers}")
    print(f"   Suspicious: {analyzer._is_suspicious_response(suspicious_response)}")
    print(f"   Patterns: {analyzer._analyze_response_patterns(suspicious_response)}")

    print("\n3. Private IP Response Analysis:")
    print(f"   Answers: {private_response.answers}")
    print(f"   Suspicious: {analyzer._is_suspicious_response(private_response)}")
    print(f"   Patterns: {analyzer._analyze_response_patterns(private_response)}")


async def main():
    """Main demo function"""
    print("Starting DNS Analyzer Demo...")

    try:
        # Run main DNS analysis demo
        await demo_dns_analysis()

        # Run individual tests demo
        await demo_individual_tests()

        # Run query methods demo
        await demo_query_methods()

        # Run response analysis demo
        demo_response_analysis()

    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        LOG.error(f"Demo failed: {e}")
        print(f"Demo failed: {e}")

    print("\nDemo completed!")


if __name__ == "__main__":
    asyncio.run(main())
