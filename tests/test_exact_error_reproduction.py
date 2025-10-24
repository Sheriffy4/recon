#!/usr/bin/env python3
"""
Test script to reproduce and verify the exact error from the user's log.
"""

import sys
import os

# Add the combo directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.engine.attack_dispatcher import AttackDispatcher


def test_exact_error_reproduction():
    """Test that reproduces the exact error from the user's log and verifies it's fixed."""
    print("Testing exact error reproduction from user's log...")

    # Create components
    techniques = BypassTechniques()
    registry = AttackRegistry()
    dispatcher = AttackDispatcher(techniques, registry)

    # Test payload (simple HTTP request)
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    # Packet info
    packet_info = {
        "src_addr": "192.168.1.1",
        "dst_addr": "216.58.207.206",  # This matches the IP from the error log
        "src_port": 12345,
        "dst_port": 443,  # This matches the port from the error log
    }

    # These are the exact parameters from the error log:
    # "params={'split_count': 3, 'overlap_size': 10, 'fooling': ['badsum'], 'repeats': 1, 'positions': [1, 7, 13], 'tcp_flags': {'psh': True, 'ack': True}, 'window_div': 2, 'ipid_step': 2048}"
    params = {
        "split_count": 3,
        "overlap_size": 10,
        "fooling": ["badsum"],
        "repeats": 1,
        "positions": [1, 7, 13],
        "tcp_flags": {"psh": True, "ack": True},
        "window_div": 2,
        "ipid_step": 2048,
    }

    try:
        # This should work now without the "unexpected keyword argument 'split_count'" error
        result = dispatcher.dispatch_attack("multisplit", params, payload, packet_info)
        print(
            "✅ SUCCESS: Multisplit dispatch worked correctly with exact error parameters!"
        )
        print(f"   Generated {len(result)} segments")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False


if __name__ == "__main__":
    success = test_exact_error_reproduction()
    sys.exit(0 if success else 1)
