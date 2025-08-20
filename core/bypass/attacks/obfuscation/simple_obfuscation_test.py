#!/usr/bin/env python3
"""
Simple test script for obfuscation attacks to verify implementation.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

from recon.core.bypass.attacks.base import AttackContext, AttackStatus
from recon.core.bypass.attacks.obfuscation.protocol_tunneling import (
    HTTPTunnelingObfuscationAttack,
    DNSOverHTTPSTunnelingAttack,
    WebSocketTunnelingObfuscationAttack,
    SSHTunnelingObfuscationAttack,
    VPNTunnelingObfuscationAttack,
)
from recon.core.bypass.attacks.obfuscation.payload_encryption import (
    XORPayloadEncryptionAttack,
    AESPayloadEncryptionAttack,
    ChaCha20PayloadEncryptionAttack,
    MultiLayerEncryptionAttack,
)
from recon.core.bypass.attacks.obfuscation.protocol_mimicry import (
    HTTPProtocolMimicryAttack,
    TLSProtocolMimicryAttack,
)
from recon.core.bypass.attacks.obfuscation.traffic_obfuscation import (
    TrafficPatternObfuscationAttack,
    PacketSizeObfuscationAttack,
    TimingObfuscationAttack,
    FlowObfuscationAttack,
)
from recon.core.bypass.attacks.obfuscation.icmp_obfuscation import (
    ICMPDataTunnelingObfuscationAttack,
    ICMPTimestampTunnelingObfuscationAttack,
    ICMPRedirectTunnelingObfuscationAttack,
    ICMPCovertChannelObfuscationAttack,
)
from recon.core.bypass.attacks.obfuscation.quic_obfuscation import (
    QUICFragmentationObfuscationAttack,
)


def create_test_context(payload: bytes = b"test data", **params) -> AttackContext:
    """Create test attack context."""
    return AttackContext(
        dst_ip="192.168.1.100",
        dst_port=443,
        src_ip="192.168.1.1",
        src_port=12345,
        domain="example.com",
        payload=payload,
        params=params,
    )


def test_protocol_tunneling():
    """Test protocol tunneling attacks."""
    print("Testing Protocol Tunneling Attacks...")

    # Test HTTP tunneling
    attack = HTTPTunnelingObfuscationAttack()
    context = create_test_context(b"secret data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ HTTP Tunneling")

    # Test DNS over HTTPS tunneling
    attack = DNSOverHTTPSTunnelingAttack()
    context = create_test_context(b"dns data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ DNS over HTTPS Tunneling")

    # Test WebSocket tunneling
    attack = WebSocketTunnelingObfuscationAttack()
    context = create_test_context(b"ws data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ WebSocket Tunneling")

    # Test SSH tunneling
    attack = SSHTunnelingObfuscationAttack()
    context = create_test_context(b"ssh data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ SSH Tunneling")

    # Test VPN tunneling
    attack = VPNTunnelingObfuscationAttack()
    context = create_test_context(b"vpn data", vpn_type="openvpn")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ VPN Tunneling")


def test_payload_encryption():
    """Test payload encryption attacks."""
    print("\nTesting Payload Encryption Attacks...")

    # Test XOR encryption
    attack = XORPayloadEncryptionAttack()
    context = create_test_context(b"encrypt me")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ XOR Encryption")

    # Test AES encryption
    attack = AESPayloadEncryptionAttack()
    context = create_test_context(b"aes data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ AES Encryption")

    # Test ChaCha20 encryption
    attack = ChaCha20PayloadEncryptionAttack()
    context = create_test_context(b"chacha data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ ChaCha20 Encryption")

    # Test Multi-layer encryption
    attack = MultiLayerEncryptionAttack()
    context = create_test_context(b"multi layer", layers=["xor", "aes"])
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ Multi-layer Encryption")


def test_protocol_mimicry():
    """Test protocol mimicry attacks."""
    print("\nTesting Protocol Mimicry Attacks...")

    # Test HTTP mimicry
    attack = HTTPProtocolMimicryAttack()
    context = create_test_context(b"http mimic")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ HTTP Protocol Mimicry")

    # Test TLS mimicry
    attack = TLSProtocolMimicryAttack()
    context = create_test_context(b"tls mimic")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ TLS Protocol Mimicry")


def test_traffic_obfuscation():
    """Test traffic obfuscation attacks."""
    print("\nTesting Traffic Obfuscation Attacks...")

    # Test traffic pattern obfuscation
    attack = TrafficPatternObfuscationAttack()
    context = create_test_context(b"pattern data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ Traffic Pattern Obfuscation")

    # Test packet size obfuscation
    attack = PacketSizeObfuscationAttack()
    context = create_test_context(b"size data" * 10)
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ Packet Size Obfuscation")

    # Test timing obfuscation
    attack = TimingObfuscationAttack()
    context = create_test_context(b"timing data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ Timing Obfuscation")

    # Test flow obfuscation
    attack = FlowObfuscationAttack()
    context = create_test_context(b"flow data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ Flow Obfuscation")


def test_icmp_obfuscation():
    """Test ICMP obfuscation attacks."""
    print("\nTesting ICMP Obfuscation Attacks...")

    # Test ICMP data tunneling
    attack = ICMPDataTunnelingObfuscationAttack()
    context = create_test_context(b"icmp data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ ICMP Data Tunneling")

    # Test ICMP timestamp tunneling
    attack = ICMPTimestampTunnelingObfuscationAttack()
    context = create_test_context(b"timestamp")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ ICMP Timestamp Tunneling")

    # Test ICMP redirect tunneling
    attack = ICMPRedirectTunnelingObfuscationAttack()
    context = create_test_context(b"redirect")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ ICMP Redirect Tunneling")

    # Test ICMP covert channel
    attack = ICMPCovertChannelObfuscationAttack()
    context = create_test_context(b"covert", channel_type="timing")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ ICMP Covert Channel")


def test_quic_obfuscation():
    """Test QUIC obfuscation attacks."""
    print("\nTesting QUIC Obfuscation Attacks...")

    # Test QUIC fragmentation
    attack = QUICFragmentationObfuscationAttack()
    context = create_test_context(b"quic data")
    result = attack.execute(context)
    assert result.status == AttackStatus.SUCCESS
    print("✓ QUIC Fragmentation")


def test_error_handling():
    """Test error handling."""
    print("\nTesting Error Handling...")

    # Test invalid VPN type
    attack = VPNTunnelingObfuscationAttack()
    context = create_test_context(b"test", vpn_type="invalid")
    result = attack.execute(context)
    assert result.status == AttackStatus.ERROR
    print("✓ Invalid VPN type handled")

    # Test invalid XOR key strategy
    attack = XORPayloadEncryptionAttack()
    context = create_test_context(b"test", key_strategy="invalid")
    result = attack.execute(context)
    assert result.status == AttackStatus.ERROR
    print("✓ Invalid XOR key strategy handled")

    # Test invalid traffic pattern strategy
    attack = TrafficPatternObfuscationAttack()
    context = create_test_context(b"test", obfuscation_strategy="invalid")
    result = attack.execute(context)
    assert result.status == AttackStatus.ERROR
    print("✓ Invalid traffic pattern strategy handled")

    # Test invalid ICMP covert channel type
    attack = ICMPCovertChannelObfuscationAttack()
    context = create_test_context(b"test", channel_type="invalid")
    result = attack.execute(context)
    assert result.status == AttackStatus.ERROR
    print("✓ Invalid ICMP channel type handled")


def main():
    """Run all tests."""
    print("Running Protocol Obfuscation Attack Tests...")
    print("=" * 50)

    try:
        test_protocol_tunneling()
        test_payload_encryption()
        test_protocol_mimicry()
        test_traffic_obfuscation()
        test_icmp_obfuscation()
        test_quic_obfuscation()
        test_error_handling()

        print("\n" + "=" * 50)
        print("🎉 All Protocol Obfuscation Attack tests passed successfully!")
        print("\nImplemented attacks:")
        print("- Protocol Tunneling: HTTP, DNS-over-HTTPS, WebSocket, SSH, VPN")
        print("- Payload Encryption: XOR, AES, ChaCha20, Multi-layer")
        print("- Protocol Mimicry: HTTP, TLS, SMTP, FTP")
        print("- Traffic Obfuscation: Pattern, Size, Timing, Flow")
        print(
            "- ICMP Obfuscation: Data tunneling, Timestamp, Redirect, Covert channels"
        )
        print("- QUIC Obfuscation: Fragmentation")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
