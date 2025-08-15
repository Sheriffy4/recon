# recon/core/bypass/attacks/obfuscation/test_obfuscation_attacks.py
"""
Comprehensive Tests for Protocol Obfuscation Attacks

Tests all obfuscation attack implementations to ensure they work correctly
and provide the expected obfuscation capabilities.
"""

import pytest
import time
from typing import Dict, Any

from ..base import AttackContext, AttackStatus
from .protocol_tunneling import (
    HTTPTunnelingObfuscationAttack,
    DNSOverHTTPSTunnelingAttack,
    WebSocketTunnelingObfuscationAttack,
    SSHTunnelingObfuscationAttack,
    VPNTunnelingObfuscationAttack
)
from .payload_encryption import (
    XORPayloadEncryptionAttack,
    AESPayloadEncryptionAttack,
    ChaCha20PayloadEncryptionAttack,
    MultiLayerEncryptionAttack
)
from .protocol_mimicry import (
    HTTPProtocolMimicryAttack,
    TLSProtocolMimicryAttack,
    SMTPProtocolMimicryAttack,
    FTPProtocolMimicryAttack
)
from .icmp_obfuscation import (
    ICMPDataTunnelingObfuscationAttack,
    ICMPTimestampTunnelingObfuscationAttack,
    ICMPRedirectTunnelingObfuscationAttack,
    ICMPCovertChannelObfuscationAttack
)
from .quic_obfuscation import QUICFragmentationObfuscationAttack
from .traffic_obfuscation import (
    TrafficPatternObfuscationAttack,
    PacketSizeObfuscationAttack,
    TimingObfuscationAttack,
    FlowObfuscationAttack
)


class TestProtocolTunnelingAttacks:
    """Test protocol tunneling obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"test data", **params) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            src_ip="192.168.1.1",
            src_port=12345,
            domain="example.com",
            payload=payload,
            params=params
        )

    def test_http_tunneling_obfuscation_basic(self):
        """Test basic HTTP tunneling obfuscation."""
        attack = HTTPTunnelingObfuscationAttack()
        context = self.create_test_context(b"secret data")
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 1
        assert result.bytes_sent > len(context.payload)
        assert result.technique_used == "http_tunneling_obfuscation"
        assert "segments" in result.metadata

    def test_http_tunneling_different_methods(self):
        """Test HTTP tunneling with different methods."""
        attack = HTTPTunnelingObfuscationAttack()
        methods = ["POST", "GET", "PUT"]
        
        for method in methods:
            context = self.create_test_context(
                b"test payload",
                method=method,
                obfuscation_level="high"
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["method"] == method
            assert result.bytes_sent > 0

    def test_dns_over_https_tunneling(self):
        """Test DNS over HTTPS tunneling."""
        attack = DNSOverHTTPSTunnelingAttack()
        context = self.create_test_context(
            b"dns tunneled data",
            doh_server="cloudflare-dns.com",
            encoding_method="base32"
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 1
        assert result.metadata["doh_server"] == "cloudflare-dns.com"
        assert result.metadata["encoding_method"] == "base32"

    def test_websocket_tunneling_obfuscation(self):
        """Test WebSocket tunneling obfuscation."""
        attack = WebSocketTunnelingObfuscationAttack()
        context = self.create_test_context(
            b"websocket data",
            obfuscation_method="fragmentation"
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 2  # Handshake + data
        assert result.metadata["obfuscation_method"] == "fragmentation"

    def test_ssh_tunneling_obfuscation(self):
        """Test SSH tunneling obfuscation."""
        attack = SSHTunnelingObfuscationAttack()
        context = self.create_test_context(
            b"ssh tunneled payload",
            obfuscation_level="high",
            encryption_method="aes256-ctr"
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 3  # ID + KEX + Data
        assert result.metadata["encryption_method"] == "aes256-ctr"

    def test_vpn_tunneling_obfuscation_types(self):
        """Test VPN tunneling with different VPN types."""
        attack = VPNTunnelingObfuscationAttack()
        vpn_types = ["openvpn", "wireguard", "ipsec"]

        for vpn_type in vpn_types:
            context = self.create_test_context(
                b"vpn test data",
                vpn_type=vpn_type
            )

            result = attack.execute(context)

            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["vpn_type"] == vpn_type
            assert result.bytes_sent > len(context.payload)

    def test_vpn_tunneling_invalid_type(self):
        """Test that VPN tunneling handles invalid type."""
        attack = VPNTunnelingObfuscationAttack()
        context = self.create_test_context(
            b"vpn test data",
            vpn_type="invalid_vpn"
        )

        result = attack.execute(context)

        assert result.status == AttackStatus.ERROR
        assert "Invalid vpn_type" in result.error_message


class TestPayloadEncryptionAttacks:
    """Test payload encryption obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"test data", **params) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            payload=payload,
            params=params
        )

    def test_xor_payload_encryption_basic(self):
        """Test basic XOR payload encryption."""
        attack = XORPayloadEncryptionAttack()
        context = self.create_test_context(b"sensitive data")
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.bytes_sent > len(context.payload)
        assert result.technique_used == "xor_payload_encryption"
        assert "key_strategy" in result.metadata

    def test_xor_encryption_key_strategies(self):
        """Test XOR encryption with different key strategies."""
        attack = XORPayloadEncryptionAttack()
        strategies = ["random", "time_based", "domain_based", "sequence_based"]
        
        for strategy in strategies:
            context = self.create_test_context(
                b"test data",
                key_strategy=strategy,
                key_length=32
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["key_strategy"] == strategy

    def test_xor_encryption_invalid_strategy(self):
        """Test that XOR encryption handles invalid strategy."""
        attack = XORPayloadEncryptionAttack()
        context = self.create_test_context(
            b"test data",
            key_strategy="invalid_strategy"
        )

        result = attack.execute(context)

        assert result.status == AttackStatus.ERROR
        assert result.error_message is not None
        assert "Invalid key_strategy" in result.error_message

    def test_aes_payload_encryption(self):
        """Test AES payload encryption."""
        attack = AESPayloadEncryptionAttack()
        context = self.create_test_context(
            b"aes encrypted data",
            mode="CTR",
            key_size=256
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["mode"] == "CTR"
        assert result.metadata["key_size"] == 256

    def test_chacha20_payload_encryption(self):
        """Test ChaCha20 payload encryption."""
        attack = ChaCha20PayloadEncryptionAttack()
        context = self.create_test_context(
            b"chacha20 data",
            use_poly1305=True,
            nonce_strategy="timestamp"
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["use_poly1305"] == True
        assert result.metadata["nonce_strategy"] == "timestamp"

    def test_multi_layer_encryption(self):
        """Test multi-layer encryption."""
        attack = MultiLayerEncryptionAttack()
        context = self.create_test_context(
            b"multi layer data",
            layers=["xor", "aes", "chacha20"],
            randomize_order=True,
            add_noise=True
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["layer_count"] == 3
        assert result.metadata["randomize_order"] == True
        assert result.metadata["expansion_ratio"] > 1.0


class TestProtocolMimicryAttacks:
    """Test protocol mimicry obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"test data", **params) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            domain="example.com",
            payload=payload,
            params=params
        )

    def test_http_protocol_mimicry_basic(self):
        """Test basic HTTP protocol mimicry."""
        attack = HTTPProtocolMimicryAttack()
        context = self.create_test_context(b"http mimicry data")
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 1
        assert result.technique_used == "http_protocol_mimicry"

    def test_http_mimicry_different_types(self):
        """Test HTTP mimicry with different types."""
        attack = HTTPProtocolMimicryAttack()
        types = ["web_browsing", "api_call", "file_download", "form_submission"]
        
        for mimicry_type in types:
            context = self.create_test_context(
                b"test data",
                mimicry_type=mimicry_type,
                include_response=True
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["mimicry_type"] == mimicry_type

    def test_tls_protocol_mimicry(self):
        """Test TLS protocol mimicry."""
        attack = TLSProtocolMimicryAttack()
        context = self.create_test_context(
            b"tls mimicry data",
            tls_version="1.3",
            include_handshake=True
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 4  # Handshake + data
        assert result.metadata["tls_version"] == "1.3"

    def test_smtp_protocol_mimicry(self):
        """Test SMTP protocol mimicry."""
        attack = SMTPProtocolMimicryAttack()
        context = self.create_test_context(
            b"email data",
            sender_email="test@example.com",
            recipient_email="recipient@example.com",
            use_tls=True
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 10  # Full SMTP conversation
        assert result.metadata["use_tls"] == True

    def test_ftp_protocol_mimicry(self):
        """Test FTP protocol mimicry."""
        attack = FTPProtocolMimicryAttack()
        context = self.create_test_context(
            b"file data",
            username="testuser",
            transfer_mode="binary"
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 8  # FTP conversation
        assert result.metadata["transfer_mode"] == "binary"


class TestTrafficObfuscationAttacks:
    """Test traffic obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"test data", **params) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            payload=payload,
            params=params
        )

    def test_traffic_pattern_obfuscation_basic(self):
        """Test basic traffic pattern obfuscation."""
        attack = TrafficPatternObfuscationAttack()
        context = self.create_test_context(b"pattern data")
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 1
        assert result.technique_used == "traffic_pattern_obfuscation"
        assert "expansion_ratio" in result.metadata

    def test_traffic_pattern_strategies(self):
        """Test different traffic pattern strategies."""
        attack = TrafficPatternObfuscationAttack()
        strategies = ["timing_randomization", "size_padding", "burst_shaping", "flow_mimicry", "mixed"]
        
        for strategy in strategies:
            context = self.create_test_context(
                b"test data" * 10,  # Larger payload
                obfuscation_strategy=strategy,
                intensity_level="medium"
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["obfuscation_strategy"] == strategy

    def test_traffic_pattern_invalid_strategy(self):
        """Test that traffic pattern attack handles invalid strategy."""
        attack = TrafficPatternObfuscationAttack()
        context = self.create_test_context(
            b"test data",
            obfuscation_strategy="invalid_strategy"
        )

        result = attack.execute(context)

        assert result.status == AttackStatus.ERROR
        assert result.error_message is not None
        assert "Invalid obfuscation_strategy" in result.error_message

    def test_packet_size_obfuscation(self):
        """Test packet size obfuscation."""
        attack = PacketSizeObfuscationAttack()
        context = self.create_test_context(
            b"size test data" * 20,
            size_strategy="normalize",
            target_size=1200
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["size_strategy"] == "normalize"
        assert result.metadata["size_expansion"] >= 1.0

    def test_timing_obfuscation(self):
        """Test timing obfuscation."""
        attack = TimingObfuscationAttack()
        context = self.create_test_context(
            b"timing data",
            timing_strategy="jitter",
            base_delay=50,
            jitter_range=20
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["timing_strategy"] == "jitter"
        assert result.metadata["total_delay_ms"] > 0

    def test_flow_obfuscation(self):
        """Test flow obfuscation."""
        attack = FlowObfuscationAttack()
        context = self.create_test_context(
            b"flow data" * 5,
            flow_strategy="bidirectional",
            fake_responses=True
        )
        
        result = attack.execute(context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["flow_strategy"] == "bidirectional"
        assert result.metadata["fake_responses"] == True


class TestICMPObfuscationAttacks:
    """Test ICMP obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"test data", **params) -> AttackContext:
        """Create test attack context."""
        return AttackContext(
            dst_ip="8.8.8.8",
            dst_port=0, # ICMP doesn't use ports
            src_ip="192.168.1.1",
            src_port=0,
            payload=payload,
            params=params
        )

    def test_icmp_data_tunneling(self):
        """Test basic ICMP data tunneling."""
        attack = ICMPDataTunnelingObfuscationAttack()
        context = self.create_test_context(
            b"some secret data here",
            packet_size=128
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "icmp_data_tunneling_obfuscation"
        assert result.packets_sent > 0
        assert result.bytes_sent > len(context.payload)

    def test_icmp_timestamp_tunneling(self):
        """Test ICMP timestamp tunneling."""
        attack = ICMPTimestampTunnelingObfuscationAttack()
        context = self.create_test_context(b"hide this")
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "icmp_timestamp_tunneling_obfuscation"
        # 3 packets for 9 bytes of data (4 bytes per packet)
        assert result.packets_sent == 3

    def test_icmp_redirect_tunneling(self):
        """Test ICMP redirect tunneling."""
        attack = ICMPRedirectTunnelingObfuscationAttack()
        context = self.create_test_context(
            b"redirect this data",
            gateway_ip="192.168.1.1"
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "icmp_redirect_tunneling_obfuscation"
        assert result.metadata["gateway_ip"] == "192.168.1.1"

    def test_icmp_covert_channel_types(self):
        """Test ICMP covert channel with different channel types."""
        attack = ICMPCovertChannelObfuscationAttack()
        channel_types = ["timing", "size", "sequence"]
        for channel_type in channel_types:
            context = self.create_test_context(
                b"covert",
                channel_type=channel_type
            )
            result = attack.execute(context)
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata["channel_type"] == channel_type

    def test_icmp_covert_channel_invalid_type(self):
        """Test ICMP covert channel with an invalid type."""
        attack = ICMPCovertChannelObfuscationAttack()
        context = self.create_test_context(
            b"covert",
            channel_type="invalid_type"
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.ERROR
        assert "Invalid channel_type" in result.error_message


class TestQUICObfuscationAttacks:
    """Test QUIC obfuscation attacks."""

    def create_test_context(self, payload: bytes = b"", **params) -> AttackContext:
        """Create test attack context for QUIC."""
        return AttackContext(
            dst_ip="8.8.8.8",
            dst_port=443,
            src_ip="192.168.1.1",
            src_port=12345,
            domain="google.com",
            payload=payload,
            params=params
        )

    def test_quic_fragmentation_basic(self):
        """Test basic QUIC fragmentation."""
        attack = QUICFragmentationObfuscationAttack()
        context = self.create_test_context(fragment_size=200)

        result = attack.execute(context)

        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == "quic_fragmentation_obfuscation"
        assert result.metadata["fragment_count"] > 1
        assert result.metadata["fragment_size"] == 200

    def test_quic_fragmentation_with_vn(self):
        """Test QUIC fragmentation with a version negotiation packet."""
        attack = QUICFragmentationObfuscationAttack()
        context = self.create_test_context(add_version_negotiation=True)

        result = attack.execute(context)

        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["version_negotiation_added"] is True
        assert result.packets_sent == result.metadata["fragment_count"] + 1

    def test_quic_fragmentation_with_payload(self):
        """Test QUIC fragmentation with data tunneling."""
        attack = QUICFragmentationObfuscationAttack()
        payload = b"this is my secret data to tunnel"
        context = self.create_test_context(payload=payload)

        result = attack.execute(context)

        assert result.status == AttackStatus.SUCCESS
        # The total bytes sent should be much larger than the payload due to QUIC packet structure
        assert result.bytes_sent > len(payload) * 2


class TestObfuscationIntegration:
    """Test integration and edge cases for obfuscation attacks."""

    def test_empty_payload_handling(self):
        """Test handling of empty payloads."""
        attacks = [
            HTTPTunnelingObfuscationAttack(),
            XORPayloadEncryptionAttack(),
            HTTPProtocolMimicryAttack(),
            TrafficPatternObfuscationAttack()
        ]
        
        context = AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            payload=b""
        )
        
        for attack in attacks:
            result = attack.execute(context)
            # Should handle empty payload gracefully
            assert result.status in [AttackStatus.SUCCESS, AttackStatus.ERROR]

    def test_large_payload_handling(self):
        """Test handling of large payloads."""
        large_payload = b"x" * 10000  # 10KB payload
        
        attacks = [
            HTTPTunnelingObfuscationAttack(),
            MultiLayerEncryptionAttack(),
            TrafficPatternObfuscationAttack()
        ]
        
        for attack in attacks:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                payload=large_payload
            )
            
            result = attack.execute(context)
            assert result.status == AttackStatus.SUCCESS
            assert result.bytes_sent >= len(large_payload)

    def test_attack_metadata_completeness(self):
        """Test that all attacks provide complete metadata."""
        attacks = [
            (HTTPTunnelingObfuscationAttack(), {}),
            (XORPayloadEncryptionAttack(), {"key_strategy": "random"}),
            (TLSProtocolMimicryAttack(), {"tls_version": "1.2"}),
            (PacketSizeObfuscationAttack(), {"size_strategy": "normalize"})
        ]
        
        for attack, params in attacks:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                payload=b"test data",
                params=params
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert result.technique_used is not None
            assert result.metadata is not None
            assert "segments" in result.metadata
            assert result.latency_ms >= 0

    def test_attack_performance_metrics(self):
        """Test that attacks provide accurate performance metrics."""
        attack = MultiLayerEncryptionAttack()
        context = AttackContext(
            dst_ip="192.168.1.100",
            dst_port=443,
            payload=b"performance test data" * 100,
            params={"layers": ["xor", "aes"]}
        )
        
        start_time = time.time()
        result = attack.execute(context)
        end_time = time.time()
        
        assert result.status == AttackStatus.SUCCESS
        assert result.latency_ms > 0
        assert result.latency_ms <= (end_time - start_time) * 1000 + 100  # Allow some margin
        assert result.packets_sent > 0
        assert result.bytes_sent > 0

    def test_segment_format_consistency(self):
        """Test that all attacks produce consistent segment formats."""
        attacks = [
            HTTPTunnelingObfuscationAttack(),
            XORPayloadEncryptionAttack(),
            HTTPProtocolMimicryAttack(),
            TrafficPatternObfuscationAttack()
        ]
        
        for attack in attacks:
            context = AttackContext(
                dst_ip="192.168.1.100",
                dst_port=443,
                payload=b"segment test data"
            )
            
            result = attack.execute(context)
            
            assert result.status == AttackStatus.SUCCESS
            assert "segments" in result.metadata
            
            segments = result.metadata["segments"]
            assert isinstance(segments, list)
            
            for segment in segments:
                assert isinstance(segment, tuple)
                assert len(segment) == 3  # (data, delay, metadata)
                assert isinstance(segment[0], bytes)  # data
                assert isinstance(segment[1], int)    # delay
                assert isinstance(segment[2], dict)   # metadata


def run_obfuscation_tests():
    """Run all obfuscation attack tests."""
    print("Running Protocol Obfuscation Attack Tests...")
    
    # Test protocol tunneling
    print("\n=== Testing Protocol Tunneling Attacks ===")
    tunneling_tests = TestProtocolTunnelingAttacks()
    tunneling_tests.test_http_tunneling_obfuscation_basic()
    tunneling_tests.test_http_tunneling_different_methods()
    tunneling_tests.test_dns_over_https_tunneling()
    tunneling_tests.test_websocket_tunneling_obfuscation()
    tunneling_tests.test_ssh_tunneling_obfuscation()
    print("✓ Protocol tunneling tests passed")
    
    # Test payload encryption
    print("\n=== Testing Payload Encryption Attacks ===")
    encryption_tests = TestPayloadEncryptionAttacks()
    encryption_tests.test_xor_payload_encryption_basic()
    encryption_tests.test_xor_encryption_key_strategies()
    encryption_tests.test_aes_payload_encryption()
    encryption_tests.test_chacha20_payload_encryption()
    encryption_tests.test_multi_layer_encryption()
    print("✓ Payload encryption tests passed")
    
    # Test protocol mimicry
    print("\n=== Testing Protocol Mimicry Attacks ===")
    mimicry_tests = TestProtocolMimicryAttacks()
    mimicry_tests.test_http_protocol_mimicry_basic()
    mimicry_tests.test_http_mimicry_different_types()
    mimicry_tests.test_tls_protocol_mimicry()
    mimicry_tests.test_smtp_protocol_mimicry()
    mimicry_tests.test_ftp_protocol_mimicry()
    print("✓ Protocol mimicry tests passed")
    
    # Test traffic obfuscation
    print("\n=== Testing Traffic Obfuscation Attacks ===")
    traffic_tests = TestTrafficObfuscationAttacks()
    traffic_tests.test_traffic_pattern_obfuscation_basic()
    traffic_tests.test_traffic_pattern_strategies()
    traffic_tests.test_packet_size_obfuscation()
    traffic_tests.test_timing_obfuscation()
    traffic_tests.test_flow_obfuscation()
    print("✓ Traffic obfuscation tests passed")
    
    # Test integration
    print("\n=== Testing Integration and Edge Cases ===")
    integration_tests = TestObfuscationIntegration()
    integration_tests.test_empty_payload_handling()
    integration_tests.test_large_payload_handling()
    integration_tests.test_attack_metadata_completeness()
    integration_tests.test_attack_performance_metrics()
    integration_tests.test_segment_format_consistency()
    print("✓ Integration tests passed")
    
    print("\n🎉 All Protocol Obfuscation Attack tests passed successfully!")


if __name__ == "__main__":
    run_obfuscation_tests()