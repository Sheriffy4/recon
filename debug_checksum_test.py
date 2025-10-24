#!/usr/bin/env python3
"""
Debug script to understand why the checksum fooler test is failing.
"""

import sys
import os

# Add the combo directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from core.bypass.strategies.config_models import TCPPacketInfo, FoolingConfig
from core.bypass.strategies.checksum_fooler import ChecksumFooler


def debug_test():
    """Debug the failing test."""
    print("Debugging checksum fooler test...")

    # Create the same TCP info as in the test
    tcp_info = TCPPacketInfo(
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",  # example.com
        src_port=54321,
        dst_port=443,  # HTTPS
        seq_num=1000,
        ack_num=2000,
        flags=0x18,  # PSH+ACK
        window_size=65535,
        checksum=0x1234,
        payload=b"TLS handshake data",
    )

    print(f"TCP Info: src_port={tcp_info.src_port}, dst_port={tcp_info.dst_port}")
    print(f"Is HTTPS traffic: {tcp_info.is_https_traffic()}")

    # Create fooler with badsum enabled
    config = FoolingConfig(badsum=True)
    fooler = ChecksumFooler(config)

    print(f"Config badsum enabled: {config.badsum}")
    print(f"Should apply badsum: {config.should_apply_badsum()}")

    # Test the should_apply_badsum method
    result = fooler.should_apply_badsum(tcp_info, is_first_part=True)
    print(f"Should apply badsum result: {result}")

    # Check individual conditions manually
    print("\n--- Manual condition checks ---")
    print(f"Config should apply: {fooler.config.should_apply_badsum()}")
    print("Is first part: True")
    print(f"Has payload: {tcp_info.has_payload()}")
    print(f"Is HTTPS: {tcp_info.is_https_traffic()}")

    # Check packet context
    packet_context = {"packet_size": len(b"TLS handshake data")}
    print(f"Packet size: {packet_context['packet_size']}")
    print(f"Packet size >= 40: {packet_context['packet_size'] >= 40}")

    # Let's trace through the actual method
    print("\n--- Tracing through should_apply_badsum method ---")

    # Check if badsum is enabled in configuration
    if not fooler.config.should_apply_badsum():
        print("FAILED: Badsum not enabled in configuration")
        return False

    # Only apply to first part of split packets
    if not True:  # is_first_part
        print("FAILED: Not first part")
        return False

    # Only apply to packets with payload (avoid applying to control packets)
    if not tcp_info.has_payload():
        print("FAILED: No payload")
        return False

    # Only apply to HTTPS traffic for DPI bypass
    if not tcp_info.is_https_traffic():
        print("FAILED: Not HTTPS traffic")
        return False

    # Additional checks based on packet context
    if (
        packet_context.get("packet_size", 0) < 40
    ):  # Minimum size for meaningful TLS packet
        print("FAILED: Packet too small")
        return False

    print("All conditions passed - should return True")


if __name__ == "__main__":
    debug_test()
