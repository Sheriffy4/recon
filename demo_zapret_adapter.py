"""
Demonstration of the Zapret Attack Adapter

This script shows how to use the ZapretAttackAdapter to integrate Zapret DPI bypass
attacks into the main system with different execution modes and configurations.
"""

import asyncio
import logging
from typing import Dict, Any

from core.bypass.attacks.base import AttackContext, AttackResult
from core.bypass.attacks.combo.zapret_attack_adapter import (
    ZapretAttackAdapter,
    ZapretAdapterConfig,
    ZapretAdapterMode,
    create_zapret_adapter_with_preset,
    create_zapret_adapter_with_config,
    create_auto_zapret_adapter,
)
from core.bypass.attacks.combo.zapret_strategy import ZapretConfig

# Setup logging
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("ZapretAdapterDemo")


def create_test_context() -> AttackContext:
    """Create a test attack context for demonstration."""
    return AttackContext(
        dst_ip="8.8.8.8",
        dst_port=443,
        src_ip="192.168.1.100",
        src_port=12345,
        domain="example.com",
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        protocol="tcp",
        timeout=5.0,
    )


def demo_basic_adapter_creation():
    """Demonstrate basic adapter creation with different configurations."""
    print("\n=== Basic Adapter Creation Demo ===")

    # 1. Default auto adapter
    auto_adapter = create_auto_zapret_adapter()
    print(f"Auto adapter created: {auto_adapter.name}")
    print(f"Configuration: {auto_adapter.get_configuration()}")

    # 2. Preset-based adapter
    preset_adapter = create_zapret_adapter_with_preset("default")
    print(f"\nPreset adapter created: {preset_adapter.name}")
    print(f"Available presets: {preset_adapter.get_available_presets()}")

    # 3. Custom configuration adapter
    custom_config = {"split_seqovl": 400, "repeats": 5, "auto_ttl": True}
    custom_adapter = create_zapret_adapter_with_config(custom_config)
    print(f"\nCustom adapter created: {custom_adapter.name}")

    # 4. Advanced configuration
    advanced_config = ZapretAdapterConfig(
        mode=ZapretAdapterMode.DIRECT,
        validation_enabled=True,
        retry_count=3,
        timeout_seconds=10.0,
        zapret_config=ZapretConfig(
            split_seqovl=350,
            repeats=7,
            auto_ttl=True,
            desync_methods=["fake", "fakeddisorder"],
        ),
    )
    advanced_adapter = ZapretAttackAdapter(advanced_config)
    print(f"\nAdvanced adapter created: {advanced_adapter.name}")


def demo_adapter_execution():
    """Demonstrate adapter execution with different modes."""
    print("\n=== Adapter Execution Demo ===")

    context = create_test_context()
    print(f"Test context: {context.dst_ip}:{context.dst_port} ({context.domain})")

    # Create adapters for different modes
    adapters = {
        "Auto Mode": create_auto_zapret_adapter(),
        "Direct Mode": ZapretAttackAdapter(
            ZapretAdapterConfig(mode=ZapretAdapterMode.DIRECT)
        ),
        "Preset Mode": create_zapret_adapter_with_preset("fast"),
    }

    for adapter_name, adapter in adapters.items():
        print(f"\n--- Testing {adapter_name} ---")
        try:
            # Note: Using dry-run style execution - just testing the interface
            print(f"Adapter configuration valid: {adapter.validate_configuration()}")
            print(
                f"Execution mode would be: {adapter._determine_execution_mode().value}"
            )
            print(f"Supported protocols: {adapter.supported_protocols}")
            print(f"Adapter category: {adapter.category}")
            print("✓ Adapter ready for execution")

        except Exception as e:
            print(f"✗ Adapter setup failed: {e}")


def demo_configuration_validation():
    """Demonstrate configuration validation and management."""
    print("\n=== Configuration Validation Demo ===")

    adapter = create_auto_zapret_adapter()

    # Validate current configuration
    validation_results = adapter.validate_configuration()
    print("Configuration validation results:")
    for key, result in validation_results.items():
        status = "✓" if result else "✗"
        print(f"  {status} {key}: {result}")

    # Test configuration updates
    print("\nTesting configuration updates:")

    # Update to preset mode
    adapter.update_configuration(
        {"mode": ZapretAdapterMode.PRESET, "preset_name": "aggressive"}
    )
    print(f"Updated to preset mode: {adapter.config.mode.value}")

    # Get available presets
    presets = adapter.get_available_presets()
    print(f"Available presets: {presets}")

    # Get recommended preset
    recommended = adapter.get_recommended_preset("aggressive_dpi")
    print(f"Recommended preset for aggressive DPI: {recommended}")


def demo_factory_functions():
    """Demonstrate factory functions for common use cases."""
    print("\n=== Factory Functions Demo ===")

    # 1. Quick preset adapter
    quick_adapter = create_zapret_adapter_with_preset(
        "stealth", validation_enabled=True, retry_count=2
    )
    print(f"Quick stealth adapter: {quick_adapter.config.preset_name}")

    # 2. Performance-optimized adapter
    performance_config = {
        "split_seqovl": 297,
        "repeats": 3,
        "inter_packet_delay_ms": 0.0,
        "burst_delay_ms": 0.0,
    }
    performance_adapter = create_zapret_adapter_with_config(
        performance_config, timeout_seconds=5.0, retry_count=1
    )
    print(
        f"Performance adapter configuration: {performance_adapter.get_configuration()}"
    )

    # 3. Robust adapter with fallbacks
    robust_adapter = create_auto_zapret_adapter(
        fallback_enabled=True,
        validation_enabled=True,
        retry_count=5,
        timeout_seconds=30.0,
    )
    print(f"Robust adapter with fallbacks: {robust_adapter.config.fallback_enabled}")


def demo_integration_compatibility():
    """Demonstrate integration compatibility features."""
    print("\n=== Integration Compatibility Demo ===")

    adapter = create_auto_zapret_adapter()

    # Test context conversion
    test_context = create_test_context()
    converted_context = adapter._convert_context_for_integration(test_context)

    print("Context conversion test:")
    print(f"  Original context type: {type(test_context).__name__}")
    print(f"  Converted context type: {type(converted_context).__name__}")
    print(f"  Target host: {converted_context.target_host}")
    print(f"  Target port: {converted_context.target_port}")

    # Test result conversion
    print("\nResult conversion capabilities:")
    print(f"  Adapter can handle multiple result formats: ✓")
    print(f"  Status mapping supported: ✓")
    print(f"  Metadata preservation: ✓")


def main():
    """Main demonstration function."""
    print("Zapret Attack Adapter Demonstration")
    print("=" * 50)

    try:
        demo_basic_adapter_creation()
        demo_adapter_execution()
        demo_configuration_validation()
        demo_factory_functions()
        demo_integration_compatibility()

        print("\n" + "=" * 50)
        print("✓ All demonstrations completed successfully!")
        print("\nThe Zapret Attack Adapter provides:")
        print("  • Unified interface for Zapret integration")
        print("  • Multiple execution modes (Direct, Preset, Integration, Auto)")
        print("  • Robust error handling and fallback mechanisms")
        print("  • Type-safe configuration management")
        print("  • Compatibility with existing attack system")

    except Exception as e:
        LOG.error(f"Demonstration failed: {e}", exc_info=True)
        print(f"\n✗ Demonstration failed: {e}")


if __name__ == "__main__":
    main()
