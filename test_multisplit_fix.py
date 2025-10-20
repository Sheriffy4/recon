#!/usr/bin/env python3
"""
Test script to verify the multisplit parameter fix.
"""

import sys
import os

# Add the combo directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.engine.attack_dispatcher import AttackDispatcher


def test_multisplit_dispatch():
    """Test that multisplit dispatch works without split_count parameter error."""
    print("Testing multisplit dispatch fix...")
    
    # Create components
    techniques = BypassTechniques()
    registry = AttackRegistry()
    dispatcher = AttackDispatcher(techniques, registry)
    
    # Test payload (simple HTTP request)
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Packet info
    packet_info = {
        'src_addr': '192.168.1.1',
        'dst_addr': '93.184.216.34',
        'src_port': 12345,
        'dst_port': 80
    }
    
    # Parameters that would cause the error before the fix
    # This matches the exact parameters from the error message
    params = {
        'split_count': 3,
        'overlap_size': 10,
        'fooling': ['badsum'],
        'repeats': 1,
        'positions': [1, 7, 13],
        'tcp_flags': {'psh': True, 'ack': True},
        'window_div': 2,
        'ipid_step': 2048
    }
    
    try:
        # This should work now without the "unexpected keyword argument 'split_count'" error
        result = dispatcher.dispatch_attack("multisplit", params, payload, packet_info)
        print(f"✅ SUCCESS: Multisplit dispatch worked correctly!")
        print(f"   Generated {len(result)} segments")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


def test_multisplit_dispatch_with_fooling_methods():
    """Test that multisplit dispatch works with fooling_methods parameter."""
    print("Testing multisplit dispatch with fooling_methods...")
    
    # Create components
    techniques = BypassTechniques()
    registry = AttackRegistry()
    dispatcher = AttackDispatcher(techniques, registry)
    
    # Test payload (simple HTTP request)
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Packet info
    packet_info = {
        'src_addr': '192.168.1.1',
        'dst_addr': '93.184.216.34',
        'src_port': 12345,
        'dst_port': 80
    }
    
    # Parameters with fooling_methods instead of fooling
    params = {
        'positions': [3, 8, 15],
        'fooling_methods': ['badsum']
    }
    
    try:
        # This should work now with parameter name mapping
        result = dispatcher.dispatch_attack("multisplit", params, payload, packet_info)
        print(f"✅ SUCCESS: Multisplit dispatch with fooling_methods worked correctly!")
        print(f"   Generated {len(result)} segments")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


if __name__ == "__main__":
    success1 = test_multisplit_dispatch()
    success2 = test_multisplit_dispatch_with_fooling_methods()
    sys.exit(0 if (success1 and success2) else 1)