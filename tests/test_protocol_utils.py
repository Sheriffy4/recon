"""
Tests for protocol detection utilities.

This test suite validates protocol detection functions extracted from base_engine.py.
"""

import pytest
from core.bypass.engine.protocol_utils import (
    is_tls_clienthello,
    is_tls_serverhello,
    get_protocol,
    is_tcp,
    is_udp,
)


class TestTLSDetection:
    """Test TLS protocol detection functions."""

    def test_is_tls_clienthello_valid(self):
        """Test detection of valid TLS ClientHello."""
        # Minimal valid ClientHello: 0x16 (Handshake), version, length, 0x01 (ClientHello)
        payload = b"\x16\x03\x01\x00\x30" + b"\x01" + b"\x00" * 40
        assert is_tls_clienthello(payload) is True

    def test_is_tls_clienthello_invalid_content_type(self):
        """Test rejection of non-handshake packets."""
        payload = b"\x17\x03\x01\x00\x30" + b"\x01" + b"\x00" * 40
        assert is_tls_clienthello(payload) is False

    def test_is_tls_clienthello_invalid_handshake_type(self):
        """Test rejection of non-ClientHello handshake packets."""
        payload = b"\x16\x03\x01\x00\x30" + b"\x02" + b"\x00" * 40
        assert is_tls_clienthello(payload) is False

    def test_is_tls_clienthello_too_short(self):
        """Test rejection of too-short packets."""
        payload = b"\x16\x03\x01"
        assert is_tls_clienthello(payload) is False

    def test_is_tls_clienthello_none(self):
        """Test handling of None payload."""
        assert is_tls_clienthello(None) is False

    def test_is_tls_serverhello_valid(self):
        """Test detection of valid TLS ServerHello."""
        payload = b"\x16\x03\x01\x00\x30" + b"\x02" + b"\x00" * 40
        assert is_tls_serverhello(payload) is True

    def test_is_tls_serverhello_invalid(self):
        """Test rejection of non-ServerHello packets."""
        payload = b"\x16\x03\x01\x00\x30" + b"\x01" + b"\x00" * 40
        assert is_tls_serverhello(payload) is False


class TestTransportProtocolDetection:
    """Test transport protocol detection functions."""

    def test_get_protocol_tcp(self):
        """Test TCP protocol detection."""

        class MockPacket:
            protocol = 6

        assert get_protocol(MockPacket()) == 6

    def test_get_protocol_udp(self):
        """Test UDP protocol detection."""

        class MockPacket:
            protocol = 17

        assert get_protocol(MockPacket()) == 17

    def test_get_protocol_tuple(self):
        """Test protocol extraction from tuple."""

        class MockPacket:
            protocol = (6, "extra")

        assert get_protocol(MockPacket()) == 6

    def test_get_protocol_none(self):
        """Test handling of missing protocol."""

        class MockPacket:
            pass

        assert get_protocol(MockPacket()) == 0

    def test_is_tcp_true(self):
        """Test TCP detection returns True for TCP packets."""

        class MockPacket:
            protocol = 6

        assert is_tcp(MockPacket()) is True

    def test_is_tcp_false(self):
        """Test TCP detection returns False for non-TCP packets."""

        class MockPacket:
            protocol = 17

        assert is_tcp(MockPacket()) is False

    def test_is_udp_true(self):
        """Test UDP detection returns True for UDP packets."""

        class MockPacket:
            protocol = 17

        assert is_udp(MockPacket()) is True

    def test_is_udp_false(self):
        """Test UDP detection returns False for non-UDP packets."""

        class MockPacket:
            protocol = 6

        assert is_udp(MockPacket()) is False


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that functions can be imported from base_engine.py."""
        from core.bypass.engine.base_engine import (
            is_tls_clienthello as base_is_tls_clienthello,
            is_tcp as base_is_tcp,
            is_udp as base_is_udp,
        )

        # Verify they're the same functions
        assert base_is_tls_clienthello is is_tls_clienthello
        assert base_is_tcp is is_tcp
        assert base_is_udp is is_udp

    def test_engine_methods_use_utils(self):
        """Test that WindowsBypassEngine methods delegate to protocol_utils."""
        from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

        # This will fail if pydivert is not available, but that's expected
        try:
            engine = WindowsBypassEngine(EngineConfig(debug=False))

            # Test that methods exist and work
            payload = b"\x16\x03\x01\x00\x30" + b"\x01" + b"\x00" * 40
            assert engine._is_tls_clienthello(payload) is True

            class MockPacket:
                protocol = 6

            assert engine._is_tcp(MockPacket()) is True
            assert engine._is_udp(MockPacket()) is False
        except ImportError:
            pytest.skip("pydivert not available")
