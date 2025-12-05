"""
Comprehensive Logging Demo

This script demonstrates the comprehensive logging and diagnostics
implemented for Task 9 of the strategy-application-bugs spec.

It shows:
- Strategy application logging (9.1)
- Parameter transformation logging (9.2)
- Fake packet logging (9.3)
- Segment ordering logging (9.4)
- Parameter mismatch logging (9.5)
"""

import logging
import sys

# Configure logging to show all messages
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)-8s | %(name)-40s | %(message)s',
    stream=sys.stdout
)

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.strategy.combo_builder import ComboAttackBuilder
from core.strategy.normalizer import ParameterNormalizer


def demo_strategy_application_logging():
    """
    Demo Requirement 9.1: Strategy application logging.
    
    Shows comprehensive logging when a strategy is applied.
    """
    print("\n" + "=" * 100)
    print("DEMO 1: Strategy Application Logging (Requirement 9.1)")
    print("=" * 100)
    
    dispatcher = UnifiedAttackDispatcher()
    builder = ComboAttackBuilder()
    
    # Create a complex recipe
    attacks = ['fake', 'split', 'disorder']
    params = {
        'ttl': 1,
        'fooling': 'badseq',
        'split_count': 4,
        'disorder_method': 'reverse',
        'fake_mode': 'per_fragment'
    }
    
    recipe = builder.build_recipe(attacks, params)
    
    # Apply recipe
    payload = b'GET / HTTP/1.1\r\nHost: nnmclub.to\r\n\r\n'
    packet_info = {
        'mode': 'BYPASS',
        'domain': 'nnmclub.to',
        'src_addr': '192.168.1.100',
        'dst_addr': '185.25.118.200',
        'src_port': 54321,
        'dst_port': 443
    }
    
    segments = dispatcher.apply_recipe(recipe, payload, packet_info)
    
    print(f"\n✅ Generated {len(segments)} segments")


def demo_parameter_transformation_logging():
    """
    Demo Requirement 9.2: Parameter transformation logging.
    
    Shows logging of parameter transformations and defaults.
    """
    print("\n" + "=" * 100)
    print("DEMO 2: Parameter Transformation Logging (Requirement 9.2)")
    print("=" * 100)
    
    normalizer = ParameterNormalizer()
    
    print("\n--- Example 1: Alias resolution ---")
    params1 = {
        'fooling': 'badseq',
        'fake_ttl': 2
    }
    normalized1 = normalizer.normalize(params1)
    print(f"Result: {normalized1}")
    
    print("\n--- Example 2: Type conversion ---")
    params2 = {
        'fooling_methods': 'badsum'  # String instead of list
    }
    normalized2 = normalizer.normalize(params2)
    print(f"Result: {normalized2}")
    
    print("\n--- Example 3: Default application ---")
    params3 = {
        'ttl': 1
        # No fooling specified
    }
    normalized3 = normalizer.normalize(params3)
    print(f"Result: {normalized3}")


def demo_fake_packet_logging():
    """
    Demo Requirement 9.3: Fake packet logging.
    
    Shows detailed logging of fake packet creation.
    """
    print("\n" + "=" * 100)
    print("DEMO 3: Fake Packet Logging (Requirement 9.3)")
    print("=" * 100)
    
    dispatcher = UnifiedAttackDispatcher()
    builder = ComboAttackBuilder()
    
    print("\n--- Example 1: Single fake packet ---")
    attacks1 = ['fake']
    params1 = {
        'ttl': 1,
        'fooling': 'badsum'
    }
    recipe1 = builder.build_recipe(attacks1, params1)
    payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    packet_info = {'mode': 'TEST', 'domain': 'example.com'}
    segments1 = dispatcher.apply_recipe(recipe1, payload, packet_info)
    
    print("\n--- Example 2: Per-fragment fake packets ---")
    attacks2 = ['fake', 'split']
    params2 = {
        'ttl': 1,
        'fooling': 'badseq',
        'split_count': 3,
        'fake_mode': 'per_fragment'
    }
    recipe2 = builder.build_recipe(attacks2, params2)
    segments2 = dispatcher.apply_recipe(recipe2, payload, packet_info)


def demo_segment_ordering_logging():
    """
    Demo Requirement 9.4: Segment ordering logging.
    
    Shows logging of segment ordering and disorder application.
    """
    print("\n" + "=" * 100)
    print("DEMO 4: Segment Ordering Logging (Requirement 9.4)")
    print("=" * 100)
    
    dispatcher = UnifiedAttackDispatcher()
    builder = ComboAttackBuilder()
    
    print("\n--- Example: Split + Disorder ---")
    attacks = ['split', 'disorder']
    params = {
        'split_count': 5,
        'disorder_method': 'reverse'
    }
    recipe = builder.build_recipe(attacks, params)
    
    payload = b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
    packet_info = {'mode': 'TEST', 'domain': 'example.com'}
    
    segments = dispatcher.apply_recipe(recipe, payload, packet_info)


def demo_parameter_mismatch_logging():
    """
    Demo Requirement 9.5: Parameter mismatch logging.
    
    Shows logging when parameters don't propagate correctly.
    """
    print("\n" + "=" * 100)
    print("DEMO 5: Parameter Mismatch Logging (Requirement 9.5)")
    print("=" * 100)
    
    dispatcher = UnifiedAttackDispatcher()
    
    print("\n--- Example: TTL mismatch ---")
    params = {'ttl': 1, 'fooling': 'badsum'}
    
    # Create segments with wrong TTL
    segments = [
        (b'fake_data', 0, {'ttl': 128, 'fooling': 'badsum', 'is_fake': True})
    ]
    
    dispatcher._validate_parameter_propagation(params, segments, 'fake')
    
    print("\n--- Example: Split count mismatch ---")
    params2 = {'split_count': 6}
    
    # Create only 2 segments instead of 6
    segments2 = [
        (b'part1', 0, {}),
        (b'part2', 5, {})
    ]
    
    dispatcher._validate_parameter_propagation(params2, segments2, 'multisplit')


def main():
    """Run all demos."""
    print("\n" + "=" * 100)
    print("COMPREHENSIVE LOGGING AND DIAGNOSTICS DEMO")
    print("Task 9: strategy-application-bugs spec")
    print("=" * 100)
    
    demo_strategy_application_logging()
    demo_parameter_transformation_logging()
    demo_fake_packet_logging()
    demo_segment_ordering_logging()
    demo_parameter_mismatch_logging()
    
    print("\n" + "=" * 100)
    print("✅ DEMO COMPLETE")
    print("=" * 100)
    print("\nAll logging requirements from Requirement 9 have been demonstrated:")
    print("  ✅ 9.1: Strategy application logging")
    print("  ✅ 9.2: Parameter transformation logging")
    print("  ✅ 9.3: Fake packet logging")
    print("  ✅ 9.4: Segment ordering logging")
    print("  ✅ 9.5: Parameter mismatch logging")
    print()


if __name__ == '__main__':
    main()
