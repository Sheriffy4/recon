# recon/core/bypass/protocols/simple_multi_port_test.py

"""
Simple test script for MultiPortHandler functionality.
Demonstrates basic multi-port and protocol support features.
"""

import asyncio
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

from recon.core.bypass.protocols.multi_port_handler import (
    MultiPortHandler,
    ProtocolFamily,
    PortStrategy,
)
from recon.core.bypass.attacks.attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
)


def create_sample_attacks():
    """Create sample attack definitions for testing."""
    attacks = []

    # HTTP manipulation attack
    http_attack = AttackDefinition(
        id="http_host_header_case",
        name="HTTP Host Header Case Manipulation",
        description="Manipulate the case of HTTP Host header to bypass DPI",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        effectiveness_score=0.8,
        stability_score=0.9,
    )
    attacks.append(http_attack)

    # TLS evasion attack
    tls_attack = AttackDefinition(
        id="tls_sni_fragmentation",
        name="TLS SNI Fragmentation",
        description="Fragment TLS SNI extension to bypass DPI inspection",
        category=AttackCategory.TLS_EVASION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        supported_protocols=["tcp"],
        supported_ports=[443],
        effectiveness_score=0.9,
        stability_score=0.8,
    )
    attacks.append(tls_attack)

    # DNS tunneling attack
    dns_attack = AttackDefinition(
        id="dns_fragmentation",
        name="DNS Query Fragmentation",
        description="Fragment DNS queries to bypass filtering",
        category=AttackCategory.DNS_TUNNELING,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        supported_protocols=["udp"],
        supported_ports=[53],
        effectiveness_score=0.7,
        stability_score=0.9,
    )
    attacks.append(dns_attack)

    # TCP fragmentation attack (works on multiple ports)
    tcp_attack = AttackDefinition(
        id="tcp_segment_fragmentation",
        name="TCP Segment Fragmentation",
        description="Fragment TCP segments to evade DPI",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        supported_protocols=["tcp"],
        supported_ports=[80, 443, 22, 25],
        effectiveness_score=0.75,
        stability_score=0.85,
    )
    attacks.append(tcp_attack)

    return attacks


def test_handler_initialization():
    """Test MultiPortHandler initialization."""
    print("=== Testing MultiPortHandler Initialization ===")

    handler = MultiPortHandler()

    print("✓ Handler initialized successfully")
    print(f"✓ Configured ports: {handler.get_supported_ports()}")
    print(f"✓ Protocol families: {list(handler.protocol_attacks.keys())}")

    # Test port strategies
    for port in [80, 443, 53]:
        strategy = handler.get_port_strategy(port)
        print(
            f"✓ Port {port}: {strategy.protocol_family.value} family, "
            f"TLS: {strategy.requires_tls}, SNI: {strategy.supports_sni}"
        )

    print()


def test_attack_selection():
    """Test attack selection for different ports."""
    print("=== Testing Attack Selection ===")

    handler = MultiPortHandler()
    attacks = create_sample_attacks()

    # Test attack selection for different ports
    test_ports = [80, 443, 53, 22]

    for port in test_ports:
        selected_attacks = handler._select_attacks_for_port(port, attacks)
        attack_names = [attack.name for attack in selected_attacks]

        print(f"✓ Port {port} selected attacks:")
        for attack in selected_attacks:
            print(
                f"  - {attack.name} (effectiveness: {attack.effectiveness_score:.1f})"
            )

        if not selected_attacks:
            print(f"  - No suitable attacks found for port {port}")
        print()


def test_port_strategy_management():
    """Test port strategy management functionality."""
    print("=== Testing Port Strategy Management ===")

    handler = MultiPortHandler()

    # Add custom port strategy
    custom_strategy = PortStrategy(
        port=8443,
        protocol_family=ProtocolFamily.SECURE_FAMILY,
        preferred_attacks=["tls_sni_fragmentation", "tcp_segment_fragmentation"],
        blocked_attacks=["unsafe_attack"],
        default_timeout=45,
        requires_tls=True,
        supports_sni=True,
        custom_headers={"X-Custom-Header": "bypass-test"},
    )

    handler.add_port_strategy(8443, custom_strategy)
    print("✓ Added custom strategy for port 8443")

    # Verify the strategy was added
    retrieved_strategy = handler.get_port_strategy(8443)
    assert retrieved_strategy.port == 8443
    assert retrieved_strategy.requires_tls is True
    print(f"✓ Custom strategy verified: {retrieved_strategy.protocol_family.value}")

    # Test supported ports
    supported_ports = handler.get_supported_ports()
    assert 8443 in supported_ports
    print(f"✓ Port 8443 now in supported ports: {supported_ports}")

    # Remove custom strategy
    removed = handler.remove_port_strategy(8443)
    assert removed is True
    print("✓ Custom strategy removed successfully")

    # Verify removal
    final_ports = handler.get_supported_ports()
    assert 8443 not in final_ports
    print("✓ Port 8443 no longer in supported ports")

    print()


async def test_domain_accessibility():
    """Test domain accessibility testing (mock version)."""
    print("=== Testing Domain Accessibility (Mock) ===")

    handler = MultiPortHandler()

    # Since we can't make real network connections in this test,
    # we'll test the logic with mock data

    # Simulate test results
    from recon.core.bypass.protocols.multi_port_handler import PortTestResult
    from recon.core.bypass.types import BlockType

    mock_results = {
        80: PortTestResult(
            port=80,
            accessible=True,
            response_time_ms=120.0,
            protocol_detected="http",
            server_header="nginx/1.18.0",
            block_type=BlockType.NONE,
        ),
        443: PortTestResult(
            port=443,
            accessible=True,
            response_time_ms=180.0,
            protocol_detected="https",
            tls_version="TLSv1.3",
            block_type=BlockType.NONE,
        ),
        53: PortTestResult(
            port=53,
            accessible=False,
            response_time_ms=5000.0,
            error_message="Connection timeout",
            block_type=BlockType.TIMEOUT,
        ),
    }

    print("✓ Mock test results created:")
    for port, result in mock_results.items():
        status = "✓ Accessible" if result.accessible else "✗ Blocked"
        print(f"  Port {port}: {status} ({result.response_time_ms:.1f}ms)")
        if result.protocol_detected:
            print(f"    Protocol: {result.protocol_detected}")
        if result.server_header:
            print(f"    Server: {result.server_header}")
        if result.tls_version:
            print(f"    TLS: {result.tls_version}")
        if result.error_message:
            print(f"    Error: {result.error_message}")

    # Test optimal port selection
    optimal_port = handler.get_optimal_port_for_domain("example.com", mock_results)
    print(f"✓ Optimal port selected: {optimal_port} (HTTPS preferred)")

    # Test protocol requirements detection
    required_ports = handler.detect_protocol_requirements("example.com", mock_results)
    print(f"✓ Required ports detected: {required_ports}")

    print()


async def test_strategy_application():
    """Test strategy application (mock version)."""
    print("=== Testing Strategy Application (Mock) ===")

    handler = MultiPortHandler()
    attacks = create_sample_attacks()

    # Mock the port testing to simulate successful bypass
    original_test_method = handler._test_single_port

    async def mock_test_single_port(domain, port):
        from recon.core.bypass.protocols.multi_port_handler import PortTestResult
        from recon.core.bypass.types import BlockType

        # Simulate successful bypass after strategy application
        return PortTestResult(
            port=port,
            accessible=True,
            response_time_ms=150.0,
            protocol_detected="https" if port == 443 else "http",
            block_type=BlockType.NONE,
        )

    handler._test_single_port = mock_test_single_port

    # Test strategy application on HTTPS port
    result = await handler.apply_port_specific_strategy(
        "example.com", 443, "test_tls_strategy", attacks
    )

    print("✓ Strategy application result:")
    print(f"  Success: {result.success}")
    print(f"  Port: {result.port}")
    print(f"  Strategy: {result.strategy_used}")
    print(f"  Execution time: {result.execution_time_ms:.1f}ms")
    print(f"  Attacks applied: {result.attacks_applied}")

    if result.metadata:
        print(f"  Metadata: {result.metadata}")

    # Restore original method
    handler._test_single_port = original_test_method

    print()


def test_statistics_and_cache():
    """Test statistics tracking and cache functionality."""
    print("=== Testing Statistics and Cache ===")

    handler = MultiPortHandler()

    # Test initial statistics
    initial_stats = handler.get_stats()
    print("✓ Initial statistics:")
    for key, value in initial_stats.items():
        print(f"  {key}: {value}")

    # Simulate some activity
    handler.stats["ports_tested"] = 15
    handler.stats["strategies_applied"] = 8
    handler.stats["successful_bypasses"] = 6
    handler.stats["cache_hits"] = 3

    # Add some cache entries
    from recon.core.bypass.protocols.multi_port_handler import PortTestResult
    from recon.core.bypass.types import BlockType

    handler.port_test_cache["example.com:80"] = PortTestResult(
        port=80, accessible=True, response_time_ms=100.0, block_type=BlockType.NONE
    )
    handler.port_test_cache["example.com:443"] = PortTestResult(
        port=443, accessible=True, response_time_ms=150.0, block_type=BlockType.NONE
    )

    # Test updated statistics
    updated_stats = handler.get_stats()
    print("\n✓ Updated statistics:")
    for key, value in updated_stats.items():
        print(f"  {key}: {value}")

    print(f"\n✓ Cache size: {len(handler.port_test_cache)} entries")

    # Test cache clearing
    handler.clear_cache()
    print(f"✓ Cache cleared, new size: {len(handler.port_test_cache)} entries")

    # Test statistics reset
    handler.reset_stats()
    reset_stats = handler.get_stats()
    print("\n✓ Statistics reset:")
    for key, value in reset_stats.items():
        print(f"  {key}: {value}")

    print()


async def main():
    """Run all tests."""
    print("Multi-Port Handler Test Suite")
    print("=" * 50)

    try:
        # Run synchronous tests
        test_handler_initialization()
        test_attack_selection()
        test_port_strategy_management()
        test_statistics_and_cache()

        # Run asynchronous tests
        await test_domain_accessibility()
        await test_strategy_application()

        print("=" * 50)
        print("✓ All tests completed successfully!")

    except Exception as e:
        print(f"✗ Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
