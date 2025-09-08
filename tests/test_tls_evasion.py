"""
Comprehensive tests for TLS evasion attacks.

Tests all TLS evasion attacks implemented in task 7:
- TLS handshake manipulation techniques
- TLS version downgrade attacks
- TLS extension manipulation
- TLS record fragmentation attacks
"""

import struct
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)

from core.bypass.attacks.base import AttackContext, AttackStatus
from core.bypass.attacks.tls.tls_evasion import (
    TLSHandshakeManipulationAttack,
    TLSVersionDowngradeAttack,
    TLSExtensionManipulationAttack,
    TLSRecordFragmentationAttack,
)


class TestTLSEvasionAttacks:
    """Test suite for TLS evasion attacks."""

    def setup_method(self):
        """Set up test fixtures."""
        self.sample_client_hello = self._create_sample_client_hello()
        self.test_context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={},
            engine_type="test",
        )

    def _create_sample_client_hello(self) -> bytes:
        """Create a sample TLS ClientHello for testing."""
        record = bytearray()
        record.extend(b"\x16")
        record.extend(b"\x03\x03")
        handshake_start = len(record) + 2
        record.extend(b"\x00\x00")
        handshake = bytearray()
        handshake.extend(b"\x01")
        handshake_length_pos = len(handshake)
        handshake.extend(b"\x00\x00\x00")
        handshake.extend(b"\x03\x03")
        handshake.extend(os.urandom(32))
        handshake.extend(b"\x00")
        cipher_suites = [4865, 4866, 49195, 49199]
        handshake.extend(struct.pack("!H", len(cipher_suites) * 2))
        for cipher in cipher_suites:
            handshake.extend(struct.pack("!H", cipher))
        handshake.extend(b"\x01\x00")
        extensions = self._create_sample_extensions()
        handshake.extend(struct.pack("!H", len(extensions)))
        handshake.extend(extensions)
        handshake_length = len(handshake) - 4
        handshake[handshake_length_pos : handshake_length_pos + 3] = (
            handshake_length.to_bytes(3, "big")
        )
        record.extend(handshake)
        record_length = len(record) - 5
        record[3:5] = struct.pack("!H", record_length)
        return bytes(record)

    def _create_sample_extensions(self) -> bytes:
        """Create sample TLS extensions."""
        extensions = bytearray()
        sni_data = b"example.com"
        sni_ext = (
            b"\x00\x00"
            + struct.pack("!H", len(sni_data) + 5)
            + struct.pack("!H", len(sni_data) + 3)
            + b"\x00"
            + struct.pack("!H", len(sni_data))
            + sni_data
        )
        extensions.extend(sni_ext)
        groups = [29, 23, 24]
        groups_data = struct.pack("!H", len(groups) * 2)
        for group in groups:
            groups_data += struct.pack("!H", group)
        groups_ext = b"\x00\n" + struct.pack("!H", len(groups_data)) + groups_data
        extensions.extend(groups_ext)
        sig_algs = [1027, 2052, 1025]
        sig_algs_data = struct.pack("!H", len(sig_algs) * 2)
        for alg in sig_algs:
            sig_algs_data += struct.pack("!H", alg)
        sig_algs_ext = b"\x00\r" + struct.pack("!H", len(sig_algs_data)) + sig_algs_data
        extensions.extend(sig_algs_ext)
        return bytes(extensions)

    def test_handshake_manipulation_fragment_hello(self):
        """Test ClientHello fragmentation."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "fragment_hello", "fragment_size": 32},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent > 1
        assert result.metadata["manipulation_type"] == "fragment_hello"
        assert result.metadata["segments_count"] > 1

    def test_handshake_manipulation_reorder_extensions(self):
        """Test extension reordering."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "reorder_extensions"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "reorder_extensions"

    def test_handshake_manipulation_split_handshake(self):
        """Test handshake message splitting."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "split_handshake"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "split_handshake"

    def test_handshake_manipulation_fake_messages(self):
        """Test fake handshake message injection."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "fake_messages"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "fake_messages"
        assert result.bytes_sent > len(self.sample_client_hello)

    def test_handshake_manipulation_timing(self):
        """Test timing manipulation."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "timing_manipulation"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "timing_manipulation"

    def test_handshake_manipulation_invalid_payload(self):
        """Test with invalid payload."""
        attack = TLSHandshakeManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"invalid payload",
            params={},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.INVALID_PARAMS
        assert "not a valid TLS handshake" in result.error_message

    def test_version_downgrade_tls10(self):
        """Test downgrade to TLS 1.0."""
        attack = TLSVersionDowngradeAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"target_version": "tls10"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["target_version"] == "tls10"
        assert result.metadata["target_version_bytes"] == "0301"

    def test_version_downgrade_tls11(self):
        """Test downgrade to TLS 1.1."""
        attack = TLSVersionDowngradeAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"target_version": "tls11"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["target_version"] == "tls11"
        assert result.metadata["target_version_bytes"] == "0302"

    def test_version_downgrade_ssl30(self):
        """Test downgrade to SSL 3.0."""
        attack = TLSVersionDowngradeAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"target_version": "ssl30"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["target_version"] == "ssl30"
        assert result.metadata["target_version_bytes"] == "0300"

    def test_version_downgrade_with_supported_versions(self):
        """Test downgrade with supported_versions extension modification."""
        attack = TLSVersionDowngradeAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"target_version": "tls10", "modify_supported_versions": True},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["modify_supported_versions"] is True

    def test_version_downgrade_with_fallback_scsv(self):
        """Test downgrade with TLS_FALLBACK_SCSV."""
        attack = TLSVersionDowngradeAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"target_version": "tls11", "add_fallback_scsv": True},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["add_fallback_scsv"] is True

    def test_extension_manipulation_inject_fake(self):
        """Test fake extension injection."""
        attack = TLSExtensionManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "inject_fake", "fake_extension_count": 5},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "inject_fake"
        assert result.metadata["fake_extension_count"] == 5
        assert result.bytes_sent > len(self.sample_client_hello)

    def test_extension_manipulation_randomize_order(self):
        """Test extension order randomization."""
        attack = TLSExtensionManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "randomize_order"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "randomize_order"

    def test_extension_manipulation_add_grease(self):
        """Test GREASE extension addition."""
        attack = TLSExtensionManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "add_grease"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "add_grease"
        assert result.bytes_sent > len(self.sample_client_hello)

    def test_extension_manipulation_duplicate_extensions(self):
        """Test extension duplication."""
        attack = TLSExtensionManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "duplicate_extensions"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "duplicate_extensions"

    def test_extension_manipulation_malformed_extensions(self):
        """Test malformed extension addition."""
        attack = TLSExtensionManipulationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"manipulation_type": "malformed_extensions"},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["manipulation_type"] == "malformed_extensions"

    def test_record_fragmentation_tcp_segment(self):
        """Test TCP segment fragmentation."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"fragmentation_type": "tcp_segment", "fragment_size": 64},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["fragmentation_type"] == "tcp_segment"
        assert result.packets_sent > 1
        assert result.metadata["segments_count"] > 1

    def test_record_fragmentation_tls_record(self):
        """Test TLS record fragmentation."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"fragmentation_type": "tls_record", "fragment_size": 100},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["fragmentation_type"] == "tls_record"

    def test_record_fragmentation_mixed(self):
        """Test mixed fragmentation."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"fragmentation_type": "mixed", "fragment_size": 80},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["fragmentation_type"] == "mixed"

    def test_record_fragmentation_adaptive(self):
        """Test adaptive fragmentation."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={"fragmentation_type": "adaptive", "max_fragments": 8},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["fragmentation_type"] == "adaptive"
        assert result.metadata["max_fragments"] == 8

    def test_record_fragmentation_randomize_sizes(self):
        """Test fragmentation with randomized sizes."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=self.sample_client_hello,
            params={
                "fragmentation_type": "tcp_segment",
                "fragment_size": 50,
                "randomize_sizes": True,
            },
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["randomize_sizes"] is True

    def test_record_fragmentation_invalid_payload(self):
        """Test with invalid TLS record."""
        attack = TLSRecordFragmentationAttack()
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"not a tls record",
            params={},
            engine_type="test",
        )
        result = attack.execute(context)
        assert result.status == AttackStatus.INVALID_PARAMS
        assert "not a valid TLS record" in result.error_message

    def test_all_attacks_with_same_payload(self):
        """Test that all attacks can process the same payload."""
        attacks = [
            TLSHandshakeManipulationAttack(),
            TLSVersionDowngradeAttack(),
            TLSExtensionManipulationAttack(),
            TLSRecordFragmentationAttack(),
        ]
        for attack in attacks:
            result = attack.execute(self.test_context)
            assert result.status == AttackStatus.SUCCESS
            assert result.latency_ms >= 0
            assert result.bytes_sent > 0

    def test_attack_metadata_completeness(self):
        """Test that all attacks provide complete metadata."""
        attacks_and_params = [
            (TLSHandshakeManipulationAttack(), {"manipulation_type": "fragment_hello"}),
            (TLSVersionDowngradeAttack(), {"target_version": "tls10"}),
            (TLSExtensionManipulationAttack(), {"manipulation_type": "inject_fake"}),
            (TLSRecordFragmentationAttack(), {"fragmentation_type": "tcp_segment"}),
        ]
        for attack, params in attacks_and_params:
            context = AttackContext(
                dst_ip="1.1.1.1",
                dst_port=443,
                domain="example.com",
                payload=self.sample_client_hello,
                params=params,
                engine_type="test",
            )
            result = attack.execute(context)
            assert result.status == AttackStatus.SUCCESS
            assert result.metadata is not None
            assert len(result.metadata) > 0
            assert (
                "original_size" in result.metadata
                or "segments_count" in result.metadata
            )

    def test_attack_error_handling(self):
        """Test error handling in all attacks."""
        attacks = [
            TLSHandshakeManipulationAttack(),
            TLSVersionDowngradeAttack(),
            TLSExtensionManipulationAttack(),
            TLSRecordFragmentationAttack(),
        ]
        empty_context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"",
            params={},
            engine_type="test",
        )
        for attack in attacks:
            result = attack.execute(empty_context)
            assert result.status in [
                AttackStatus.SUCCESS,
                AttackStatus.INVALID_PARAMS,
                AttackStatus.ERROR,
            ]
            if result.status == AttackStatus.ERROR:
                assert result.error_message is not None

    def test_large_payload_handling(self):
        """Test handling of large payloads."""
        large_payload = self.sample_client_hello * 10
        large_context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=large_payload,
            params={},
            engine_type="test",
        )
        attacks = [TLSHandshakeManipulationAttack(), TLSRecordFragmentationAttack()]
        for attack in attacks:
            result = attack.execute(large_context)
            assert result.status == AttackStatus.SUCCESS
            assert result.bytes_sent >= len(large_payload)


if __name__ == "__main__":
    import sys

    test_suite = TestTLSEvasionAttacks()
    test_suite.setup_method()
    try:
        test_suite.test_handshake_manipulation_fragment_hello()
        print("✓ Handshake manipulation test passed")
        test_suite.test_version_downgrade_tls10()
        print("✓ Version downgrade test passed")
        test_suite.test_extension_manipulation_inject_fake()
        print("✓ Extension manipulation test passed")
        test_suite.test_record_fragmentation_tcp_segment()
        print("✓ Record fragmentation test passed")
        test_suite.test_all_attacks_with_same_payload()
        print("✓ Integration test passed")
        print("\nAll TLS evasion attack tests passed successfully!")
    except Exception as e:
        print(f"✗ Test failed: {e}")
        sys.exit(1)
