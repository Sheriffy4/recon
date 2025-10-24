"""
Example demonstrating lazy loading functionality in the attack registry.

Lazy loading allows the attack registry to defer loading of external attack
modules until they are actually needed, which can significantly improve
startup time for applications with many attack modules.
"""

import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bypass.attacks.attack_registry import (
    AttackRegistry,
    get_attack_registry,
    configure_lazy_loading,
    get_lazy_loading_config,
    clear_registry,
)


def example_eager_loading():
    """Example of eager loading (default behavior)."""
    print("=" * 60)
    print("Example 1: Eager Loading (Default)")
    print("=" * 60)

    # Clear any existing registry
    clear_registry(clear_config=True)

    # Measure initialization time
    start_time = time.time()
    registry = AttackRegistry(lazy_loading=False)
    init_time = time.time() - start_time

    print(f"Initialization time: {init_time*1000:.2f}ms")
    print(f"Attacks loaded: {len(registry.attacks)}")
    print(
        f"Builtin attacks: {len([a for a in registry.attacks.values() if 'primitives' in a.source_module])}"
    )

    # Get lazy loading stats
    stats = registry.get_lazy_loading_stats()
    print(f"\nLazy loading enabled: {stats['lazy_loading_enabled']}")
    print(f"Total discovered modules: {stats['total_discovered_modules']}")
    print(f"Loaded modules: {stats['loaded_modules']}")

    print("\nAll attacks are loaded immediately at startup.")
    print()


def example_lazy_loading():
    """Example of lazy loading."""
    print("=" * 60)
    print("Example 2: Lazy Loading")
    print("=" * 60)

    # Clear any existing registry
    clear_registry(clear_config=True)

    # Measure initialization time
    start_time = time.time()
    registry = AttackRegistry(lazy_loading=True)
    init_time = time.time() - start_time

    print(f"Initialization time: {init_time*1000:.2f}ms")
    print(f"Attacks loaded: {len(registry.attacks)}")
    print(
        f"Builtin attacks: {len([a for a in registry.attacks.values() if 'primitives' in a.source_module])}"
    )

    # Get lazy loading stats
    stats = registry.get_lazy_loading_stats()
    print(f"\nLazy loading enabled: {stats['lazy_loading_enabled']}")
    print(f"Total discovered modules: {stats['total_discovered_modules']}")
    print(f"Loaded modules: {stats['loaded_modules']}")
    print(f"Unloaded modules: {stats['unloaded_modules']}")

    print("\nOnly builtin attacks are loaded at startup.")
    print("External attacks will be loaded on-demand when first accessed.")
    print()


def example_global_configuration():
    """Example of configuring lazy loading globally."""
    print("=" * 60)
    print("Example 3: Global Configuration")
    print("=" * 60)

    # Clear any existing registry
    clear_registry(clear_config=True)

    # Configure lazy loading before creating registry
    print("Configuring lazy loading globally...")
    configure_lazy_loading(True)

    # Check configuration
    config = get_lazy_loading_config()
    print(f"Lazy loading config: {config}")

    # Create registry - will use global configuration
    registry = get_attack_registry()
    print(f"Registry lazy loading: {registry._lazy_loading}")

    # Get stats
    stats = registry.get_lazy_loading_stats()
    print(f"\nLazy loading enabled: {stats['lazy_loading_enabled']}")
    print(f"Attacks loaded: {stats['loaded_attacks']}")

    print("\nGlobal configuration allows setting lazy loading once")
    print("and having it apply to all registry instances.")
    print()


def example_accessing_attacks():
    """Example of accessing attacks with lazy loading."""
    print("=" * 60)
    print("Example 4: Accessing Attacks with Lazy Loading")
    print("=" * 60)

    # Clear and setup lazy loading
    clear_registry(clear_config=True)
    registry = AttackRegistry(lazy_loading=True)

    print("Initial state:")
    stats = registry.get_lazy_loading_stats()
    print(f"  Loaded attacks: {stats['loaded_attacks']}")
    print(f"  Loaded modules: {stats['loaded_modules']}")

    # Access a builtin attack (already loaded)
    print("\nAccessing builtin attack 'fakeddisorder'...")
    handler = registry.get_attack_handler("fakeddisorder")
    print(f"  Handler found: {handler is not None}")

    # Check stats again
    stats = registry.get_lazy_loading_stats()
    print(f"  Loaded attacks: {stats['loaded_attacks']}")
    print(f"  Loaded modules: {stats['loaded_modules']}")

    print("\nBuiltin attacks are always available immediately.")
    print("External attacks would be loaded on first access.")
    print()


def example_performance_comparison():
    """Example comparing performance of eager vs lazy loading."""
    print("=" * 60)
    print("Example 5: Performance Comparison")
    print("=" * 60)

    # Test eager loading
    clear_registry(clear_config=True)
    start = time.time()
    registry_eager = AttackRegistry(lazy_loading=False)
    time_eager = time.time() - start

    # Test lazy loading
    clear_registry(clear_config=True)
    start = time.time()
    registry_lazy = AttackRegistry(lazy_loading=True)
    time_lazy = time.time() - start

    print(f"Eager loading initialization: {time_eager*1000:.2f}ms")
    print(f"Lazy loading initialization:  {time_lazy*1000:.2f}ms")
    print(f"Speedup: {time_eager/time_lazy:.2f}x")

    # Compare attack counts
    print(f"\nEager loading attacks: {len(registry_eager.attacks)}")
    print(f"Lazy loading attacks:  {len(registry_lazy.attacks)}")

    print("\nLazy loading provides faster startup by deferring")
    print("the loading of external attack modules until needed.")
    print()


def example_configuration_warning():
    """Example showing warning when configuring after initialization."""
    print("=" * 60)
    print("Example 6: Configuration Warning")
    print("=" * 60)

    # Clear registry
    clear_registry(clear_config=True)

    # Create registry first
    print("Creating registry with default settings...")
    registry = get_attack_registry()
    print(f"Registry lazy loading: {registry._lazy_loading}")

    # Try to configure after initialization
    print("\nAttempting to configure lazy loading after initialization...")
    configure_lazy_loading(True)

    # Check if it took effect
    print(f"Registry lazy loading: {registry._lazy_loading}")
    print("\nWarning: Configuration must be done before first registry access!")
    print("Use clear_registry() to reset if needed.")
    print()


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("LAZY LOADING EXAMPLES")
    print("=" * 60 + "\n")

    try:
        example_eager_loading()
        example_lazy_loading()
        example_global_configuration()
        example_accessing_attacks()
        example_performance_comparison()
        example_configuration_warning()

        print("=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)

    finally:
        # Clean up
        clear_registry(clear_config=True)


if __name__ == "__main__":
    main()
