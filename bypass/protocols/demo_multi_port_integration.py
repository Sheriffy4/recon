# recon/core/bypass/protocols/demo_multi_port_integration.py

"""
Demonstration of MultiPortHandler integration with the bypass engine.
Shows how multi-port and protocol support enhances bypass capabilities.
"""

import asyncio
import sys
import os
from typing import List

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

from recon.core.bypass.protocols.multi_port_handler import (
    MultiPortHandler,
    PortStrategy,
    ProtocolFamily,
    PortTestResult,
)
from recon.core.bypass.attacks.attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
)
from recon.core.bypass.types import BlockType


class MultiPortBypassDemo:
    """Demonstration class for multi-port bypass capabilities."""

    def __init__(self):
        """Initialize the demo with a multi-port handler and sample attacks."""
        self.handler = MultiPortHandler()
        self.attacks = self._create_comprehensive_attack_set()
        self.test_domains = [
            "example.com",
            "httpbin.org",
            "google.com",
            "youtube.com",
            "twitter.com",
        ]

    def _create_comprehensive_attack_set(self) -> List[AttackDefinition]:
        """Create a comprehensive set of attacks for different protocols and ports."""
        attacks = []

        # HTTP-specific attacks (port 80)
        http_attacks = [
            AttackDefinition(
                id="http_host_header_case",
                name="HTTP Host Header Case Manipulation",
                description="Change case of HTTP Host header",
                category=AttackCategory.HTTP_MANIPULATION,
                complexity=AttackComplexity.SIMPLE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[80, 443],
                effectiveness_score=0.8,
                stability_score=0.9,
            ),
            AttackDefinition(
                id="http_method_override",
                name="HTTP Method Override",
                description="Use alternative HTTP methods",
                category=AttackCategory.HTTP_MANIPULATION,
                complexity=AttackComplexity.SIMPLE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[80, 443],
                effectiveness_score=0.7,
                stability_score=0.9,
            ),
            AttackDefinition(
                id="http_chunked_encoding",
                name="HTTP Chunked Transfer Encoding",
                description="Use chunked encoding to bypass inspection",
                category=AttackCategory.HTTP_MANIPULATION,
                complexity=AttackComplexity.MODERATE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[80, 443],
                effectiveness_score=0.85,
                stability_score=0.8,
            ),
        ]
        attacks.extend(http_attacks)

        # HTTPS/TLS-specific attacks (port 443)
        tls_attacks = [
            AttackDefinition(
                id="tls_sni_fragmentation",
                name="TLS SNI Fragmentation",
                description="Fragment TLS SNI extension",
                category=AttackCategory.TLS_EVASION,
                complexity=AttackComplexity.MODERATE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[443],
                effectiveness_score=0.9,
                stability_score=0.8,
            ),
            AttackDefinition(
                id="tls_record_splitting",
                name="TLS Record Splitting",
                description="Split TLS records to evade inspection",
                category=AttackCategory.TLS_EVASION,
                complexity=AttackComplexity.ADVANCED,
                stability=AttackStability.MOSTLY_STABLE,
                supported_protocols=["tcp"],
                supported_ports=[443],
                effectiveness_score=0.85,
                stability_score=0.75,
            ),
            AttackDefinition(
                id="tls_handshake_split",
                name="TLS Handshake Splitting",
                description="Split TLS handshake messages",
                category=AttackCategory.TLS_EVASION,
                complexity=AttackComplexity.ADVANCED,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[443],
                effectiveness_score=0.8,
                stability_score=0.8,
            ),
        ]
        attacks.extend(tls_attacks)

        # DNS attacks (port 53)
        dns_attacks = [
            AttackDefinition(
                id="dns_fragmentation",
                name="DNS Query Fragmentation",
                description="Fragment DNS queries",
                category=AttackCategory.DNS_TUNNELING,
                complexity=AttackComplexity.SIMPLE,
                stability=AttackStability.STABLE,
                supported_protocols=["udp"],
                supported_ports=[53],
                effectiveness_score=0.7,
                stability_score=0.9,
            ),
            AttackDefinition(
                id="dns_case_randomization",
                name="DNS Case Randomization",
                description="Randomize case in DNS queries",
                category=AttackCategory.DNS_TUNNELING,
                complexity=AttackComplexity.SIMPLE,
                stability=AttackStability.STABLE,
                supported_protocols=["udp"],
                supported_ports=[53],
                effectiveness_score=0.6,
                stability_score=0.95,
            ),
        ]
        attacks.extend(dns_attacks)

        # Universal TCP attacks (multiple ports)
        tcp_attacks = [
            AttackDefinition(
                id="tcp_segment_fragmentation",
                name="TCP Segment Fragmentation",
                description="Fragment TCP segments",
                category=AttackCategory.TCP_FRAGMENTATION,
                complexity=AttackComplexity.MODERATE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[80, 443, 22, 25, 110, 143],
                effectiveness_score=0.75,
                stability_score=0.85,
            ),
            AttackDefinition(
                id="tcp_window_scaling",
                name="TCP Window Scaling",
                description="Manipulate TCP window size",
                category=AttackCategory.TCP_FRAGMENTATION,
                complexity=AttackComplexity.SIMPLE,
                stability=AttackStability.STABLE,
                supported_protocols=["tcp"],
                supported_ports=[80, 443, 22, 25, 110, 143],
                effectiveness_score=0.65,
                stability_score=0.9,
            ),
        ]
        attacks.extend(tcp_attacks)

        return attacks

    def demonstrate_port_strategy_configuration(self):
        """Demonstrate port strategy configuration and management."""
        print("=== Port Strategy Configuration Demo ===")

        # Show default port strategies
        print("Default Port Strategies:")
        for port in [80, 443, 53]:
            strategy = self.handler.get_port_strategy(port)
            print(f"  Port {port}:")
            print(f"    Protocol Family: {strategy.protocol_family.value}")
            print(f"    Requires TLS: {strategy.requires_tls}")
            print(f"    Supports SNI: {strategy.supports_sni}")
            print(f"    Validation Method: {strategy.validation_method}")
            print(f"    Preferred Attacks: {strategy.preferred_attacks[:3]}...")

        # Add custom port strategy for alternative HTTPS port
        print("\nAdding custom strategy for port 8443:")
        custom_strategy = PortStrategy(
            port=8443,
            protocol_family=ProtocolFamily.SECURE_FAMILY,
            preferred_attacks=["tls_sni_fragmentation", "tls_record_splitting"],
            blocked_attacks=["unsafe_experimental_attack"],
            default_timeout=45,
            requires_tls=True,
            supports_sni=True,
            custom_headers={"X-Bypass-Engine": "MultiPort-v1.0"},
        )

        self.handler.add_port_strategy(8443, custom_strategy)
        print("  ✓ Custom strategy added for port 8443")
        print(f"  ✓ Supported ports now: {self.handler.get_supported_ports()}")

        print()

    def demonstrate_attack_selection(self):
        """Demonstrate protocol-specific attack selection."""
        print("=== Protocol-Specific Attack Selection Demo ===")

        test_ports = [80, 443, 53, 8443]

        for port in test_ports:
            print(f"\nPort {port} Attack Selection:")
            selected_attacks = self.handler._select_attacks_for_port(port, self.attacks)

            if selected_attacks:
                print(f"  Selected {len(selected_attacks)} attacks:")
                for i, attack in enumerate(selected_attacks[:5], 1):  # Show top 5
                    print(f"    {i}. {attack.name}")
                    print(f"       Category: {attack.category.value}")
                    print(f"       Effectiveness: {attack.effectiveness_score:.2f}")
                    print(f"       Complexity: {attack.complexity.value}")

                if len(selected_attacks) > 5:
                    print(f"    ... and {len(selected_attacks) - 5} more attacks")
            else:
                print("  No suitable attacks found for this port")

        print()

    async def demonstrate_domain_testing(self):
        """Demonstrate domain accessibility testing across multiple ports."""
        print("=== Domain Accessibility Testing Demo ===")

        # Mock the testing methods to simulate different scenarios
        original_test_method = self.handler._test_single_port

        async def mock_test_scenarios(domain: str, port: int) -> PortTestResult:
            """Mock different testing scenarios for demonstration."""

            # Simulate different scenarios based on domain and port
            if "example.com" in domain:
                if port == 80:
                    return PortTestResult(
                        port=80,
                        accessible=True,
                        response_time_ms=120.0,
                        protocol_detected="http",
                        server_header="Apache/2.4.41",
                        block_type=BlockType.NONE,
                    )
                elif port == 443:
                    return PortTestResult(
                        port=443,
                        accessible=True,
                        response_time_ms=180.0,
                        protocol_detected="https",
                        tls_version="TLSv1.3",
                        block_type=BlockType.NONE,
                    )

            elif "blocked" in domain:
                return PortTestResult(
                    port=port,
                    accessible=False,
                    response_time_ms=5000.0,
                    error_message="Connection timeout",
                    block_type=BlockType.TIMEOUT,
                )

            elif "partial" in domain:
                if port == 80:
                    return PortTestResult(
                        port=80,
                        accessible=False,
                        response_time_ms=100.0,
                        error_message="Connection refused",
                        block_type=BlockType.CONNECTION_REFUSED,
                    )
                elif port == 443:
                    return PortTestResult(
                        port=443,
                        accessible=True,
                        response_time_ms=250.0,
                        protocol_detected="https",
                        tls_version="TLSv1.2",
                        block_type=BlockType.NONE,
                    )

            # Default case
            return PortTestResult(
                port=port,
                accessible=True,
                response_time_ms=200.0,
                protocol_detected="tcp",
                block_type=BlockType.NONE,
            )

        self.handler._test_single_port = mock_test_scenarios

        # Test different domain scenarios
        test_scenarios = [
            ("example.com", "Normal accessible domain"),
            ("blocked.example.com", "Completely blocked domain"),
            (
                "partial.example.com",
                "Partially blocked domain (HTTP blocked, HTTPS works)",
            ),
        ]

        for domain, description in test_scenarios:
            print(f"\nTesting: {domain} ({description})")

            results = await self.handler.test_domain_accessibility(domain, [80, 443])

            for port, result in results.items():
                status = "✓ Accessible" if result.accessible else "✗ Blocked"
                print(f"  Port {port}: {status} ({result.response_time_ms:.1f}ms)")

                if result.protocol_detected:
                    print(f"    Protocol: {result.protocol_detected}")
                if result.server_header:
                    print(f"    Server: {result.server_header}")
                if result.tls_version:
                    print(f"    TLS Version: {result.tls_version}")
                if result.error_message:
                    print(f"    Error: {result.error_message}")
                if result.block_type:
                    print(f"    Block Type: {result.block_type.value}")

            # Determine optimal port
            optimal_port = self.handler.get_optimal_port_for_domain(domain, results)
            print(f"  Optimal Port: {optimal_port}")

            # Detect protocol requirements
            required_ports = self.handler.detect_protocol_requirements(domain, results)
            print(f"  Required Ports: {required_ports}")

        # Restore original method
        self.handler._test_single_port = original_test_method
        print()

    async def demonstrate_strategy_application(self):
        """Demonstrate bypass strategy application with multi-port support."""
        print("=== Multi-Port Strategy Application Demo ===")

        # Mock successful bypass testing
        original_test_method = self.handler._test_single_port

        async def mock_bypass_success(domain: str, port: int) -> PortTestResult:
            """Mock successful bypass after strategy application."""
            return PortTestResult(
                port=port,
                accessible=True,
                response_time_ms=150.0,
                protocol_detected="https" if port == 443 else "http",
                block_type=BlockType.NONE,
            )

        self.handler._test_single_port = mock_bypass_success

        # Test strategy application on different ports
        test_cases = [
            ("social-media.com", 80, "http_manipulation_strategy"),
            ("video-platform.com", 443, "tls_evasion_strategy"),
            ("news-site.com", 443, "combined_bypass_strategy"),
        ]

        for domain, port, strategy_name in test_cases:
            print(f"\nApplying '{strategy_name}' to {domain}:{port}")

            result = await self.handler.apply_port_specific_strategy(
                domain, port, strategy_name, self.attacks
            )

            print(f"  Result: {'✓ Success' if result.success else '✗ Failed'}")
            print(f"  Execution Time: {result.execution_time_ms:.1f}ms")
            print(f"  Attacks Applied: {len(result.attacks_applied)}")

            for i, attack_id in enumerate(result.attacks_applied, 1):
                attack = next((a for a in self.attacks if a.id == attack_id), None)
                if attack:
                    print(f"    {i}. {attack.name}")

            if result.metadata:
                port_strategy = result.metadata.get("port_strategy", "unknown")
                print(f"  Port Strategy: {port_strategy}")

                test_result = result.metadata.get("test_result", {})
                if test_result:
                    print(f"  Post-bypass Test: {test_result}")

        # Restore original method
        self.handler._test_single_port = original_test_method
        print()

    def demonstrate_statistics_and_monitoring(self):
        """Demonstrate statistics tracking and monitoring capabilities."""
        print("=== Statistics and Monitoring Demo ===")

        # Show initial statistics
        initial_stats = self.handler.get_stats()
        print("Initial Statistics:")
        for key, value in initial_stats.items():
            print(f"  {key}: {value}")

        # Simulate some activity
        print("\nSimulating bypass engine activity...")
        self.handler.stats["ports_tested"] = 25
        self.handler.stats["strategies_applied"] = 12
        self.handler.stats["successful_bypasses"] = 9
        self.handler.stats["cache_hits"] = 8

        # Add cache entries
        from recon.core.bypass.protocols.multi_port_handler import PortTestResult

        cache_entries = [
            (
                "google.com:80",
                PortTestResult(port=80, accessible=True, response_time_ms=95.0),
            ),
            (
                "google.com:443",
                PortTestResult(port=443, accessible=True, response_time_ms=120.0),
            ),
            (
                "youtube.com:443",
                PortTestResult(port=443, accessible=True, response_time_ms=180.0),
            ),
            (
                "twitter.com:80",
                PortTestResult(port=80, accessible=False, response_time_ms=5000.0),
            ),
            (
                "twitter.com:443",
                PortTestResult(port=443, accessible=True, response_time_ms=200.0),
            ),
        ]

        for cache_key, result in cache_entries:
            self.handler.port_test_cache[cache_key] = result

        # Show updated statistics
        updated_stats = self.handler.get_stats()
        print("\nUpdated Statistics:")
        for key, value in updated_stats.items():
            print(f"  {key}: {value}")

        # Show cache information
        print("\nCache Information:")
        print(f"  Cache Size: {len(self.handler.port_test_cache)} entries")
        print("  Cache Entries:")
        for cache_key in list(self.handler.port_test_cache.keys())[:3]:
            result = self.handler.port_test_cache[cache_key]
            status = "accessible" if result.accessible else "blocked"
            print(f"    {cache_key}: {status} ({result.response_time_ms:.1f}ms)")

        if len(self.handler.port_test_cache) > 3:
            print(f"    ... and {len(self.handler.port_test_cache) - 3} more entries")

        print()

    def demonstrate_advanced_features(self):
        """Demonstrate advanced multi-port handler features."""
        print("=== Advanced Features Demo ===")

        # Protocol family attack mapping
        print("Protocol Family Attack Mappings:")
        for family, attacks in self.handler.protocol_attacks.items():
            print(f"  {family.value}:")
            for attack in attacks[:3]:  # Show first 3
                print(f"    - {attack}")
            if len(attacks) > 3:
                print(f"    ... and {len(attacks) - 3} more")

        # Port strategy management
        print(f"\nSupported Ports: {self.handler.get_supported_ports()}")

        # Cache management
        print("\nCache Management:")
        print(f"  Current cache size: {len(self.handler.port_test_cache)}")
        print(f"  Cache TTL: {self.handler.cache_ttl} seconds")

        # Clear cache demonstration
        self.handler.clear_cache()
        print(f"  Cache cleared, new size: {len(self.handler.port_test_cache)}")

        # Statistics reset
        print("\nStatistics Management:")
        print(f"  Current success rate: {self.handler.get_stats()['success_rate']:.2%}")

        self.handler.reset_stats()
        print("  Statistics reset")
        print(f"  New success rate: {self.handler.get_stats()['success_rate']:.2%}")

        print()

    async def run_complete_demo(self):
        """Run the complete multi-port handler demonstration."""
        print("Multi-Port Handler Integration Demo")
        print("=" * 60)
        print("Demonstrating enhanced bypass capabilities with multi-port support")
        print("=" * 60)

        try:
            # Run all demonstration sections
            self.demonstrate_port_strategy_configuration()
            self.demonstrate_attack_selection()
            await self.demonstrate_domain_testing()
            await self.demonstrate_strategy_application()
            self.demonstrate_statistics_and_monitoring()
            self.demonstrate_advanced_features()

            print("=" * 60)
            print("✓ Multi-Port Handler Demo completed successfully!")
            print("\nKey Features Demonstrated:")
            print("  ✓ Port-specific strategy configuration")
            print("  ✓ Protocol-aware attack selection")
            print("  ✓ Multi-port domain accessibility testing")
            print("  ✓ Intelligent optimal port selection")
            print("  ✓ Bypass strategy application with port specialization")
            print("  ✓ Comprehensive statistics and monitoring")
            print("  ✓ Cache management for performance optimization")
            print("  ✓ HTTP (80) and HTTPS (443) specialized handling")
            print("  ✓ Automatic protocol detection and requirements")

        except Exception as e:
            print(f"✗ Demo failed with error: {e}")
            import traceback

            traceback.print_exc()
            return 1

        return 0


async def main():
    """Run the multi-port handler integration demo."""
    demo = MultiPortBypassDemo()
    return await demo.run_complete_demo()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
