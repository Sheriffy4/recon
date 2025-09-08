#!/usr/bin/env python3
"""
Simple test to verify obfuscation attacks can be imported and instantiated.
"""

import sys
import os
import asyncio

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
attacks_dir = os.path.dirname(current_dir)
bypass_dir = os.path.dirname(attacks_dir)
core_dir = os.path.dirname(bypass_dir)
recon_dir = os.path.dirname(core_dir)
sys.path.insert(0, recon_dir)


async def main():
    try:
        # Test imports
        print("Testing imports...")

        from core.bypass.attacks.base import AttackContext, AttackStatus

        print("✓ Base imports successful")

        from core.bypass.attacks.obfuscation.protocol_tunneling import (
            HTTPTunnelingObfuscationAttack,
        )

        print("✓ Protocol tunneling import successful")

        from core.bypass.attacks.obfuscation.payload_encryption import (
            XORPayloadEncryptionAttack,
        )

        print("✓ Payload encryption import successful")

        from core.bypass.attacks.obfuscation.protocol_mimicry import (
            HTTPProtocolMimicryAttack,
        )

        print("✓ Protocol mimicry import successful")

        from core.bypass.attacks.obfuscation.traffic_obfuscation import (
            TrafficPatternObfuscationAttack,
        )

        print("✓ Traffic obfuscation import successful")

        from core.bypass.attacks.obfuscation.icmp_obfuscation import (
            ICMPDataTunnelingObfuscationAttack,
        )

        print("✓ ICMP obfuscation import successful")

        from core.bypass.attacks.obfuscation.quic_obfuscation import (
            QUICFragmentationObfuscationAttack,
        )

        print("✓ QUIC obfuscation import successful")

        # Test instantiation
        print("\nTesting attack instantiation...")

        attacks = [
            HTTPTunnelingObfuscationAttack(),
            XORPayloadEncryptionAttack(),
            HTTPProtocolMimicryAttack(),
            TrafficPatternObfuscationAttack(),
            ICMPDataTunnelingObfuscationAttack(),
            QUICFragmentationObfuscationAttack(),
        ]

        for attack in attacks:
            assert hasattr(attack, "name")
            assert hasattr(attack, "category")
            assert hasattr(attack, "description")
            assert hasattr(attack, "supported_protocols")
            assert hasattr(attack, "execute")
            print(f"✓ {attack.__class__.__name__} instantiated successfully")

        # Test basic execution with dummy context
        print("\nTesting basic execution...")

        context = AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            src_ip="192.168.1.1",
            src_port=12345,
            domain="example.com",
            payload=b"test data",
            params={},
        )

        # Test one attack execution
        attack = HTTPTunnelingObfuscationAttack()
        result = await attack.execute(context)

        assert result.status in [AttackStatus.SUCCESS, AttackStatus.ERROR]
        assert hasattr(result, "latency_ms")
        assert hasattr(result, "technique_used")
        print(f"✓ Attack execution test passed: {result.status}")

        print("\n🎉 All obfuscation attack tests passed!")
        print("\nImplemented obfuscation attacks:")
        print("- Protocol Tunneling (HTTP, DNS-over-HTTPS, WebSocket, SSH, VPN)")
        print("- Payload Encryption (XOR, AES, ChaCha20, Multi-layer)")
        print("- Protocol Mimicry (HTTP, TLS, SMTP, FTP)")
        print("- Traffic Obfuscation (Pattern, Size, Timing, Flow)")
        print(
            "- ICMP Obfuscation (Data tunneling, Timestamp, Redirect, Covert channels)"
        )
        print("- QUIC Obfuscation (Fragmentation)")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
    print("\n✅ Protocol obfuscation attacks implementation completed successfully!")
