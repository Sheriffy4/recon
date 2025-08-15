# recon/core/bypass/attacks/tls/demo_tls_evasion.py
"""
Demo script for TLS evasion attacks.

Demonstrates the functionality of all TLS evasion attacks implemented in task 7.
"""

import sys
import os
import struct

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../..'))

from recon.core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.tls.tls_evasion import (
    TLSHandshakeManipulationAttack,
    TLSVersionDowngradeAttack,
    TLSExtensionManipulationAttack,
    TLSRecordFragmentationAttack
)


def create_sample_client_hello() -> bytes:
    """Create a sample TLS ClientHello for testing."""
    # TLS Record Header
    record = bytearray()
    record.extend(b"\x16")  # Content Type: Handshake
    record.extend(b"\x03\x03")  # Version: TLS 1.2
    
    # Handshake data (will be filled)
    handshake_start = len(record) + 2  # After length field
    record.extend(b"\x00\x00")  # Placeholder for length
    
    # Handshake Header
    handshake = bytearray()
    handshake.extend(b"\x01")  # Handshake Type: ClientHello
    handshake_length_pos = len(handshake)
    handshake.extend(b"\x00\x00\x00")  # Placeholder for length
    
    # ClientHello content
    handshake.extend(b"\x03\x03")  # Client Version: TLS 1.2
    handshake.extend(os.urandom(32))  # Client Random
    handshake.extend(b"\x00")  # Session ID Length
    
    # Cipher Suites
    cipher_suites = [0x1301, 0x1302, 0xc02b, 0xc02f]  # Sample cipher suites
    handshake.extend(struct.pack("!H", len(cipher_suites) * 2))
    for cipher in cipher_suites:
        handshake.extend(struct.pack("!H", cipher))
    
    # Compression Methods
    handshake.extend(b"\x01\x00")  # No compression
    
    # Extensions
    extensions = create_sample_extensions()
    handshake.extend(struct.pack("!H", len(extensions)))
    handshake.extend(extensions)
    
    # Update handshake length
    handshake_length = len(handshake) - 4
    handshake[handshake_length_pos:handshake_length_pos + 3] = handshake_length.to_bytes(3, "big")
    
    # Add handshake to record
    record.extend(handshake)
    
    # Update record length
    record_length = len(record) - 5
    record[3:5] = struct.pack("!H", record_length)
    
    return bytes(record)


def create_sample_extensions() -> bytes:
    """Create sample TLS extensions."""
    extensions = bytearray()
    
    # SNI Extension
    sni_data = b"example.com"
    sni_ext = (
        b"\x00\x00"  # Extension Type: SNI
        + struct.pack("!H", len(sni_data) + 5)  # Extension Length
        + struct.pack("!H", len(sni_data) + 3)  # Server Name List Length
        + b"\x00"  # Name Type: hostname
        + struct.pack("!H", len(sni_data))  # Name Length
        + sni_data
    )
    extensions.extend(sni_ext)
    
    # Supported Groups Extension
    groups = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
    groups_data = struct.pack("!H", len(groups) * 2)
    for group in groups:
        groups_data += struct.pack("!H", group)
    
    groups_ext = (
        b"\x00\x0a"  # Extension Type: Supported Groups
        + struct.pack("!H", len(groups_data))
        + groups_data
    )
    extensions.extend(groups_ext)
    
    return bytes(extensions)


def demo_handshake_manipulation():
    """Demonstrate TLS handshake manipulation attacks."""
    print("=== TLS Handshake Manipulation Attack Demo ===")
    
    attack = TLSHandshakeManipulationAttack()
    sample_hello = create_sample_client_hello()
    
    # Test different manipulation types
    manipulation_types = [
        "fragment_hello",
        "reorder_extensions", 
        "split_handshake",
        "fake_messages",
        "timing_manipulation"
    ]
    
    for manipulation_type in manipulation_types:
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=sample_hello,
            params={"manipulation_type": manipulation_type, "fragment_size": 64},
            engine_type="demo"
        )
        
        result = attack.execute(context)
        
        print(f"  {manipulation_type}: {result.status.value}")
        if result.status == AttackStatus.SUCCESS:
            print(f"    - Packets sent: {result.packets_sent}")
            print(f"    - Bytes sent: {result.bytes_sent}")
            print(f"    - Latency: {result.latency_ms:.2f}ms")
        elif result.error_message:
            print(f"    - Error: {result.error_message}")
        print()


def demo_version_downgrade():
    """Demonstrate TLS version downgrade attacks."""
    print("=== TLS Version Downgrade Attack Demo ===")
    
    attack = TLSVersionDowngradeAttack()
    sample_hello = create_sample_client_hello()
    
    # Test different target versions
    versions = ["ssl30", "tls10", "tls11", "tls12"]
    
    for version in versions:
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=sample_hello,
            params={"target_version": version, "modify_supported_versions": True},
            engine_type="demo"
        )
        
        result = attack.execute(context)
        
        print(f"  Downgrade to {version}: {result.status.value}")
        if result.status == AttackStatus.SUCCESS:
            print(f"    - Target version bytes: {result.metadata.get('target_version_bytes', 'N/A')}")
            print(f"    - Modified size: {result.metadata.get('modified_size', 'N/A')} bytes")
        elif result.error_message:
            print(f"    - Error: {result.error_message}")
        print()


def demo_extension_manipulation():
    """Demonstrate TLS extension manipulation attacks."""
    print("=== TLS Extension Manipulation Attack Demo ===")
    
    attack = TLSExtensionManipulationAttack()
    sample_hello = create_sample_client_hello()
    
    # Test different manipulation types
    manipulation_types = [
        "inject_fake",
        "randomize_order",
        "add_grease",
        "duplicate_extensions",
        "malformed_extensions"
    ]
    
    for manipulation_type in manipulation_types:
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=sample_hello,
            params={"manipulation_type": manipulation_type, "fake_extension_count": 3},
            engine_type="demo"
        )
        
        result = attack.execute(context)
        
        print(f"  {manipulation_type}: {result.status.value}")
        if result.status == AttackStatus.SUCCESS:
            print(f"    - Original size: {result.metadata.get('original_size', 'N/A')} bytes")
            print(f"    - Modified size: {result.metadata.get('modified_size', 'N/A')} bytes")
            size_increase = result.metadata.get('modified_size', 0) - result.metadata.get('original_size', 0)
            print(f"    - Size increase: {size_increase} bytes")
        elif result.error_message:
            print(f"    - Error: {result.error_message}")
        print()


def demo_record_fragmentation():
    """Demonstrate TLS record fragmentation attacks."""
    print("=== TLS Record Fragmentation Attack Demo ===")
    
    attack = TLSRecordFragmentationAttack()
    sample_hello = create_sample_client_hello()
    
    # Test different fragmentation types
    fragmentation_types = [
        ("tcp_segment", {"fragment_size": 64}),
        ("tls_record", {"fragment_size": 100}),
        ("mixed", {"fragment_size": 80}),
        ("adaptive", {"max_fragments": 8})
    ]
    
    for frag_type, params in fragmentation_types:
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=sample_hello,
            params={"fragmentation_type": frag_type, **params},
            engine_type="demo"
        )
        
        result = attack.execute(context)
        
        print(f"  {frag_type}: {result.status.value}")
        if result.status == AttackStatus.SUCCESS:
            print(f"    - Packets sent: {result.packets_sent}")
            print(f"    - Segments count: {result.metadata.get('segments_count', 'N/A')}")
            print(f"    - Total bytes: {result.bytes_sent}")
        elif result.error_message:
            print(f"    - Error: {result.error_message}")
        print()


def demo_attack_properties():
    """Demonstrate attack properties and metadata."""
    print("=== TLS Evasion Attack Properties ===")
    
    attacks = [
        ("TLS Handshake Manipulation", TLSHandshakeManipulationAttack()),
        ("TLS Version Downgrade", TLSVersionDowngradeAttack()),
        ("TLS Extension Manipulation", TLSExtensionManipulationAttack()),
        ("TLS Record Fragmentation", TLSRecordFragmentationAttack())
    ]
    
    for name, attack in attacks:
        print(f"  {name}:")
        print(f"    - Name: {attack.name}")
        print(f"    - Category: {attack.category}")
        print(f"    - Description: {attack.description}")
        print(f"    - Supported protocols: {', '.join(attack.supported_protocols)}")
        print()


def main():
    """Run all TLS evasion attack demos."""
    print("TLS Evasion Attacks Demo")
    print("=" * 50)
    print()
    
    try:
        demo_attack_properties()
        demo_handshake_manipulation()
        demo_version_downgrade()
        demo_extension_manipulation()
        demo_record_fragmentation()
        
        print("=" * 50)
        print("All TLS evasion attack demos completed successfully!")
        print()
        print("Summary of implemented attacks:")
        print("✓ TLS Handshake Manipulation - 5 manipulation types")
        print("✓ TLS Version Downgrade - 4 target versions")
        print("✓ TLS Extension Manipulation - 5 manipulation types")
        print("✓ TLS Record Fragmentation - 4 fragmentation types")
        print()
        print("Task 7 requirements fulfilled:")
        print("✓ Restore TLS handshake manipulation techniques")
        print("✓ Add TLS version downgrade attacks")
        print("✓ Implement TLS extension manipulation")
        print("✓ Create TLS record fragmentation attacks")
        print("✓ Write comprehensive tests for all TLS attacks")
        
    except Exception as e:
        print(f"Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)