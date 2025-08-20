# recon/core/bypass/attacks/demo_attack_registry.py

"""
Demonstration of the modernized attack registry infrastructure.
Shows how to register attacks, manage them, and use the comprehensive metadata system.
"""

import logging

from .attack_definition import (
    AttackDefinition,
    AttackCategory,
    AttackComplexity,
    AttackStability,
    CompatibilityMode,
    TestCase,
)
from .modern_registry import ModernAttackRegistry
from .base import BaseAttack, AttackResult, AttackContext, AttackStatus

# Configure logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("AttackRegistryDemo")


class DemoTCPFragmentationAttack(BaseAttack):
    """Demo TCP fragmentation attack for demonstration purposes."""

    def __init__(self):
        self.name = "demo_tcp_fragmentation"
        self.category = "tcp_fragmentation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute the demo attack."""
        LOG.info(f"Executing TCP fragmentation attack on {context.domain}")

        # Simulate attack execution
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="tcp_fragmentation",
            latency_ms=25.5,
            packets_sent=3,
            bytes_sent=len(context.payload) * 3,
        )


class DemoHTTPManipulationAttack(BaseAttack):
    """Demo HTTP manipulation attack for demonstration purposes."""

    def __init__(self):
        self.name = "demo_http_manipulation"
        self.category = "http_manipulation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute the demo attack."""
        LOG.info(f"Executing HTTP manipulation attack on {context.domain}")

        # Simulate attack execution
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used="http_header_modification",
            latency_ms=15.2,
            packets_sent=2,
            bytes_sent=len(context.payload) * 2,
        )


def create_demo_attack_definitions():
    """Create demo attack definitions with comprehensive metadata."""

    # TCP Fragmentation Attack Definition
    tcp_attack = AttackDefinition(
        id="demo_tcp_fragmentation",
        name="Demo TCP Fragmentation",
        description="Demonstrates TCP packet fragmentation to bypass DPI inspection",
        category=AttackCategory.TCP_FRAGMENTATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        # Parameters
        parameters={
            "fragment_size": 64,
            "fragment_delay_ms": 10,
            "randomize_order": False,
        },
        default_parameters={
            "fragment_size": 64,
            "fragment_delay_ms": 10,
            "randomize_order": False,
        },
        required_parameters=["fragment_size"],
        # Compatibility
        compatibility=[CompatibilityMode.ZAPRET, CompatibilityMode.NATIVE],
        external_tool_mappings={
            "zapret": "--dpi-desync=split --dpi-desync-split-pos=64",
            "goodbyedpi": "-f 64",
        },
        # Scores
        stability_score=0.9,
        effectiveness_score=0.8,
        performance_score=0.85,
        # Protocol support
        supported_protocols=["tcp"],
        supported_ports=[80, 443, 8080],
        requires_handshake=True,
        # Documentation
        documentation_url="https://example.com/tcp-fragmentation-docs",
        examples=[
            {
                "name": "Basic fragmentation",
                "parameters": {"fragment_size": 64, "fragment_delay_ms": 10},
                "description": "Basic TCP fragmentation with 64-byte fragments",
            },
            {
                "name": "Aggressive fragmentation",
                "parameters": {
                    "fragment_size": 32,
                    "fragment_delay_ms": 5,
                    "randomize_order": True,
                },
                "description": "Aggressive fragmentation with randomized packet order",
            },
        ],
        # Metadata
        author="Demo System",
        version="1.2.0",
    )

    # Add tags
    tcp_attack.add_tag("tcp")
    tcp_attack.add_tag("fragmentation")
    tcp_attack.add_tag("stable")
    tcp_attack.add_tag("recommended")

    # Add test cases
    tcp_test_basic = TestCase(
        id="tcp_basic_test",
        name="Basic TCP Fragmentation Test",
        description="Test basic TCP fragmentation functionality",
        target_domain="httpbin.org",
        expected_success=True,
        test_parameters={"fragment_size": 64},
        timeout_seconds=30,
        validation_criteria=["http_response", "content_check", "timing_analysis"],
    )

    tcp_test_aggressive = TestCase(
        id="tcp_aggressive_test",
        name="Aggressive TCP Fragmentation Test",
        description="Test aggressive TCP fragmentation with small fragments",
        target_domain="example.com",
        expected_success=True,
        test_parameters={"fragment_size": 32, "randomize_order": True},
        timeout_seconds=45,
    )

    tcp_attack.add_test_case(tcp_test_basic)
    tcp_attack.add_test_case(tcp_test_aggressive)

    # HTTP Manipulation Attack Definition
    http_attack = AttackDefinition(
        id="demo_http_manipulation",
        name="Demo HTTP Header Manipulation",
        description="Demonstrates HTTP header modification to bypass DPI inspection",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.MOSTLY_STABLE,
        # Parameters
        parameters={
            "header_case": "mixed",
            "add_fake_headers": True,
            "host_header_split": False,
        },
        default_parameters={
            "header_case": "mixed",
            "add_fake_headers": True,
            "host_header_split": False,
        },
        required_parameters=["header_case"],
        # Compatibility
        compatibility=[CompatibilityMode.GOODBYEDPI, CompatibilityMode.NATIVE],
        external_tool_mappings={
            "goodbyedpi": "-m --fake-gen 10",
            "byebyedpi": "--fake-gen 10 --mod-http",
        },
        # Scores
        stability_score=0.75,
        effectiveness_score=0.85,
        performance_score=0.9,
        # Protocol support
        supported_protocols=["tcp"],
        supported_ports=[80, 8080],
        requires_handshake=False,
        # Dependencies and conflicts
        conflicts_with=["demo_tcp_fragmentation"],  # Example conflict
        # Documentation
        examples=[
            {
                "name": "Mixed case headers",
                "parameters": {"header_case": "mixed", "add_fake_headers": False},
                "description": "Use mixed case HTTP headers",
            }
        ],
        # Metadata
        author="Demo System",
        version="1.0.1",
    )

    # Add tags
    http_attack.add_tag("http")
    http_attack.add_tag("headers")
    http_attack.add_tag("simple")

    # Add test case
    http_test = TestCase(
        id="http_basic_test",
        name="Basic HTTP Manipulation Test",
        description="Test basic HTTP header manipulation",
        target_domain="httpbin.org",
        expected_success=True,
        test_parameters={"header_case": "mixed"},
        timeout_seconds=20,
    )

    http_attack.add_test_case(http_test)

    return tcp_attack, http_attack


def demonstrate_registry_operations():
    """Demonstrate various registry operations."""

    LOG.info("=== Attack Registry Infrastructure Demo ===")

    # Create registry (in real usage, you'd use get_modern_registry())
    registry = ModernAttackRegistry()
    registry._auto_save = False  # Disable auto-save for demo

    # Create demo attack definitions
    tcp_attack, http_attack = create_demo_attack_definitions()

    # Create demo attack classes
    tcp_class = DemoTCPFragmentationAttack
    http_class = DemoHTTPManipulationAttack

    LOG.info("\n1. Registering attacks...")

    # Register attacks
    success1 = registry.register_attack(tcp_attack, tcp_class)
    success2 = registry.register_attack(http_attack, http_class)

    LOG.info(f"TCP attack registration: {'SUCCESS' if success1 else 'FAILED'}")
    LOG.info(f"HTTP attack registration: {'SUCCESS' if success2 else 'FAILED'}")

    LOG.info("\n2. Listing all attacks...")
    all_attacks = registry.list_attacks()
    for attack_id in all_attacks:
        definition = registry.get_attack_definition(attack_id)
        LOG.info(
            f"  - {attack_id}: {definition.name} (Category: {definition.category.value}, "
            f"Complexity: {definition.complexity.value}, Overall Score: {definition.get_overall_score():.2f})"
        )

    LOG.info("\n3. Filtering attacks by category...")
    tcp_attacks = registry.list_attacks(category=AttackCategory.TCP_FRAGMENTATION)
    http_attacks = registry.list_attacks(category=AttackCategory.HTTP_MANIPULATION)

    LOG.info(f"TCP attacks: {tcp_attacks}")
    LOG.info(f"HTTP attacks: {http_attacks}")

    LOG.info("\n4. Searching attacks...")
    search_results = registry.search_attacks("fragmentation")
    LOG.info(f"Search for 'fragmentation': {search_results}")

    search_results = registry.search_attacks("http")
    LOG.info(f"Search for 'http': {search_results}")

    LOG.info("\n5. Getting attacks by complexity...")
    simple_attacks = registry.get_attacks_by_complexity(AttackComplexity.SIMPLE)
    moderate_attacks = registry.get_attacks_by_complexity(AttackComplexity.MODERATE)

    LOG.info(f"Simple attacks: {list(simple_attacks.keys())}")
    LOG.info(f"Moderate attacks: {list(moderate_attacks.keys())}")

    LOG.info("\n6. Getting attacks by tags...")
    stable_attacks = registry.get_attacks_by_tag("stable")
    recommended_attacks = registry.get_attacks_by_tag("recommended")

    LOG.info(f"Stable attacks: {list(stable_attacks.keys())}")
    LOG.info(f"Recommended attacks: {list(recommended_attacks.keys())}")

    LOG.info("\n7. Checking compatibility...")
    zapret_attacks = registry.get_compatible_attacks(CompatibilityMode.ZAPRET)
    goodbyedpi_attacks = registry.get_compatible_attacks(CompatibilityMode.GOODBYEDPI)

    LOG.info(f"Zapret compatible: {list(zapret_attacks.keys())}")
    LOG.info(f"GoodbyeDPI compatible: {list(goodbyedpi_attacks.keys())}")

    LOG.info("\n8. Attack details...")
    tcp_def = registry.get_attack_definition("demo_tcp_fragmentation")
    if tcp_def:
        LOG.info("TCP Attack Details:")
        LOG.info(f"  Name: {tcp_def.name}")
        LOG.info(f"  Description: {tcp_def.description}")
        LOG.info(f"  Stability Score: {tcp_def.stability_score}")
        LOG.info(f"  Effectiveness Score: {tcp_def.effectiveness_score}")
        LOG.info(f"  Performance Score: {tcp_def.performance_score}")
        LOG.info(f"  Overall Score: {tcp_def.get_overall_score():.2f}")
        LOG.info(f"  Supported Protocols: {tcp_def.supported_protocols}")
        LOG.info(f"  Supported Ports: {tcp_def.supported_ports}")
        LOG.info(f"  Test Cases: {len(tcp_def.test_cases)}")
        LOG.info(f"  Tags: {list(tcp_def.tags)}")
        LOG.info(f"  External Tool Mappings: {tcp_def.external_tool_mappings}")

    LOG.info("\n9. Registry statistics...")
    stats = registry.get_stats()
    LOG.info(f"Total attacks: {stats['total_attacks']}")
    LOG.info(f"Enabled attacks: {stats['enabled_attacks']}")
    LOG.info(f"Deprecated attacks: {stats['deprecated_attacks']}")

    LOG.info("\n10. Attack enable/disable...")
    # Disable an attack
    registry.disable_attack("demo_http_manipulation", "Demo disable for testing")
    stats_after_disable = registry.get_stats()
    LOG.info(f"Enabled attacks after disable: {stats_after_disable['enabled_attacks']}")

    # Re-enable the attack
    registry.enable_attack("demo_http_manipulation")
    stats_after_enable = registry.get_stats()
    LOG.info(
        f"Enabled attacks after re-enable: {stats_after_enable['enabled_attacks']}"
    )

    LOG.info("\n11. Creating attack instances...")
    # Create attack instances
    tcp_instance = registry.create_attack_instance("demo_tcp_fragmentation")
    http_instance = registry.create_attack_instance("demo_http_manipulation")

    if tcp_instance:
        LOG.info(f"Created TCP attack instance: {type(tcp_instance).__name__}")
    if http_instance:
        LOG.info(f"Created HTTP attack instance: {type(http_instance).__name__}")

    LOG.info("\n=== Demo completed successfully! ===")


def demonstrate_attack_definition_features():
    """Demonstrate AttackDefinition features."""

    LOG.info("\n=== Attack Definition Features Demo ===")

    # Create a comprehensive attack definition
    attack = AttackDefinition(
        id="feature_demo_attack",
        name="Feature Demo Attack",
        description="Demonstrates all AttackDefinition features",
        category=AttackCategory.EXPERIMENTAL,
        complexity=AttackComplexity.EXPERT,
        stability=AttackStability.EXPERIMENTAL,
        stability_score=0.6,
        effectiveness_score=0.9,
        performance_score=0.7,
    )

    LOG.info(f"Created attack: {attack}")
    LOG.info(f"Overall score: {attack.get_overall_score():.2f}")

    # Test tag management
    LOG.info("\nTag management:")
    attack.add_tag("experimental")
    attack.add_tag("advanced")
    attack.add_tag("research")
    LOG.info(f"Added tags: {list(attack.tags)}")

    LOG.info(f"Has 'experimental' tag: {attack.has_tag('experimental')}")
    LOG.info(f"Has 'simple' tag: {attack.has_tag('simple')}")

    attack.remove_tag("research")
    LOG.info(f"After removing 'research': {list(attack.tags)}")

    # Test compatibility
    LOG.info("\nCompatibility testing:")
    attack.compatibility = [CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET]
    LOG.info(
        f"Compatible with NATIVE: {attack.is_compatible_with(CompatibilityMode.NATIVE)}"
    )
    LOG.info(
        f"Compatible with ZAPRET: {attack.is_compatible_with(CompatibilityMode.ZAPRET)}"
    )
    LOG.info(
        f"Compatible with GOODBYEDPI: {attack.is_compatible_with(CompatibilityMode.GOODBYEDPI)}"
    )

    # Test protocol and port support
    LOG.info("\nProtocol and port support:")
    attack.supported_protocols = ["tcp", "udp"]
    attack.supported_ports = [80, 443, 8080, 53]

    LOG.info(f"Supports TCP: {attack.supports_protocol('tcp')}")
    LOG.info(f"Supports ICMP: {attack.supports_protocol('icmp')}")
    LOG.info(f"Supports port 443: {attack.supports_port(443)}")
    LOG.info(f"Supports port 22: {attack.supports_port(22)}")

    # Test deprecation
    LOG.info("\nDeprecation testing:")
    LOG.info(f"Initially deprecated: {attack.deprecated}")
    LOG.info(f"Initially enabled: {attack.enabled}")

    attack.deprecate("Replaced by better attack", "new_attack_v2")
    LOG.info(f"After deprecation - deprecated: {attack.deprecated}")
    LOG.info(f"After deprecation - enabled: {attack.enabled}")
    LOG.info(f"Deprecation reason: {attack.deprecation_reason}")
    LOG.info(f"Replacement attack: {attack.replacement_attack}")

    # Test serialization
    LOG.info("\nSerialization testing:")
    data = attack.to_dict()
    LOG.info(f"Serialized keys: {list(data.keys())}")

    # Restore from serialization
    restored = AttackDefinition.from_dict(data)
    LOG.info(f"Restored attack: {restored}")
    LOG.info(f"Restored tags: {list(restored.tags)}")
    LOG.info(f"Restored overall score: {restored.get_overall_score():.2f}")

    LOG.info("\n=== Attack Definition Demo completed! ===")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_attack_definition_features()
    demonstrate_registry_operations()
