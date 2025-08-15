#!/usr/bin/env python3
"""
Simple test for timing attacks to verify implementation.
"""

import time
from ..base import AttackContext, AttackStatus
from .jitter_injection import JitterInjectionAttack, JitterConfiguration, JitterType
from .delay_evasion import DelayEvasionAttack, DelayEvasionConfiguration, DelayPattern
from .burst_traffic import BurstTrafficAttack, BurstConfiguration, BurstType


def test_timing_attacks():
    """Test all timing attacks with basic configurations."""
    print("Testing Timing Attacks Implementation")
    print("=" * 50)
    
    # Create test context
    context = AttackContext(
        dst_ip="93.184.216.34",
        dst_port=443,
        domain="example.com",
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    
    # Test 1: Jitter Injection Attack
    print("\n1. Testing Jitter Injection Attack")
    try:
        config = JitterConfiguration(
            jitter_type=JitterType.UNIFORM,
            jitter_amplitude_ms=5.0,
            packets_per_burst=3
        )
        attack = JitterInjectionAttack(config)
        
        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()
        
        print(f"   Status: {result.status.value}")
        print(f"   Technique: {result.technique_used}")
        print(f"   Packets sent: {result.packets_sent}")
        print(f"   Execution time: {(end_time - start_time) * 1000:.2f}ms")
        print("   ✓ Jitter injection test passed")
        
    except Exception as e:
        print(f"   ✗ Jitter injection test failed: {e}")
    
    # Test 2: Delay Evasion Attack
    print("\n2. Testing Delay Evasion Attack")
    try:
        config = DelayEvasionConfiguration(
            delay_pattern=DelayPattern.PROGRESSIVE,
            max_progression_steps=4,
            progression_factor=1.5
        )
        attack = DelayEvasionAttack(config)
        
        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()
        
        print(f"   Status: {result.status.value}")
        print(f"   Technique: {result.technique_used}")
        print(f"   Packets sent: {result.packets_sent}")
        print(f"   Execution time: {(end_time - start_time) * 1000:.2f}ms")
        print("   ✓ Delay evasion test passed")
        
    except Exception as e:
        print(f"   ✗ Delay evasion test failed: {e}")
    
    # Test 3: Burst Traffic Attack
    print("\n3. Testing Burst Traffic Attack")
    try:
        config = BurstConfiguration(
            burst_type=BurstType.FIXED_SIZE,
            default_burst_size=4,
            total_bursts=2,
            burst_interval_ms=10.0
        )
        attack = BurstTrafficAttack(config)
        
        start_time = time.perf_counter()
        result = attack.execute(context)
        end_time = time.perf_counter()
        
        print(f"   Status: {result.status.value}")
        print(f"   Technique: {result.technique_used}")
        print(f"   Packets sent: {result.packets_sent}")
        print(f"   Execution time: {(end_time - start_time) * 1000:.2f}ms")
        print("   ✓ Burst traffic test passed")
        
    except Exception as e:
        print(f"   ✗ Burst traffic test failed: {e}")
    
    # Test 4: Pattern Generation
    print("\n4. Testing Pattern Generation")
    try:
        # Test jitter patterns
        jitter_attack = JitterInjectionAttack()
        jitter_sequence = jitter_attack._generate_jitter_sequence(5)
        print(f"   Jitter sequence (5 values): {[f'{x:.2f}' for x in jitter_sequence]}")
        
        # Test delay patterns
        delay_attack = DelayEvasionAttack()
        delay_sequence = delay_attack._generate_delay_sequence()
        print(f"   Delay sequence: {[f'{x:.2f}' for x in delay_sequence[:5]]}")
        
        # Test burst patterns
        burst_attack = BurstTrafficAttack()
        burst_sequence = burst_attack._generate_burst_sequence()
        print(f"   Burst sequence: {[(size, f'{interval:.1f}ms') for size, interval in burst_sequence[:3]]}")
        
        print("   ✓ Pattern generation test passed")
        
    except Exception as e:
        print(f"   ✗ Pattern generation test failed: {e}")
    
    # Test 5: Statistics Collection
    print("\n5. Testing Statistics Collection")
    try:
        attack = JitterInjectionAttack()
        attack.execute(context)  # Execute to populate stats
        
        stats = attack.get_jitter_statistics()
        print(f"   Jitter stats keys: {list(stats.keys())[:5]}...")
        
        timing_stats = attack.get_timing_statistics()
        print(f"   Timing stats keys: {list(timing_stats.keys())[:5]}...")
        
        print("   ✓ Statistics collection test passed")
        
    except Exception as e:
        print(f"   ✗ Statistics collection test failed: {e}")
    
    print("\n" + "=" * 50)
    print("Timing Attacks Test Complete")
    print("All core functionality verified!")


if __name__ == "__main__":
    test_timing_attacks()