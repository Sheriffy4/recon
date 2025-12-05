"""
Property-based tests for PayloadSerializer.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
"""

import pytest
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume

from core.payload.serializer import (
    PayloadSerializer,
    InvalidHexError,
    InvalidPlaceholderError,
)
from core.payload.types import PayloadType


class TestHexSerializationRoundTrip:
    """
    Property-based tests for hex serialization round-trip.
    
    **Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
    **Validates: Requirements 4.2, 4.5**
    
    Property: For any valid payload bytes, serializing to hex (0x...) and 
    deserializing back MUST produce identical bytes.
    """
    
    @pytest.fixture
    def serializer(self):
        """Create a PayloadSerializer instance."""
        return PayloadSerializer()
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_hex_roundtrip_preserves_data(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
        **Validates: Requirements 4.2, 4.5**
        
        Property: For any valid payload bytes, to_hex() followed by from_hex()
        MUST produce identical bytes.
        """
        serializer = PayloadSerializer()
        
        # Serialize to hex
        hex_str = serializer.to_hex(payload_bytes)
        
        # Deserialize back
        result = serializer.from_hex(hex_str)
        
        # Must be identical
        assert result == payload_bytes, (
            f"Round-trip failed: original {len(payload_bytes)} bytes, "
            f"result {len(result)} bytes"
        )
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_to_hex_produces_valid_format(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
        **Validates: Requirements 4.2, 4.5**
        
        Property: to_hex() MUST produce a string starting with "0x" followed
        by valid hex characters.
        """
        serializer = PayloadSerializer()
        
        hex_str = serializer.to_hex(payload_bytes)
        
        # Must start with 0x
        assert hex_str.startswith("0x"), "Hex string must start with '0x'"
        
        # Rest must be valid hex characters
        hex_part = hex_str[2:]
        assert all(c in "0123456789abcdef" for c in hex_part), (
            "Hex string must contain only valid hex characters"
        )
        
        # Length must be even (2 chars per byte)
        assert len(hex_part) == len(payload_bytes) * 2, (
            f"Hex string length mismatch: expected {len(payload_bytes) * 2}, "
            f"got {len(hex_part)}"
        )
    
    @given(
        hex_chars=st.text(
            alphabet="0123456789abcdefABCDEF",
            min_size=2,
            max_size=200
        ).filter(lambda x: len(x) % 2 == 0)
    )
    @settings(max_examples=100)
    def test_from_hex_accepts_valid_hex(self, hex_chars):
        """
        **Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
        **Validates: Requirements 4.2, 4.5**
        
        Property: from_hex() MUST accept any valid hex string (with or without 0x prefix).
        """
        serializer = PayloadSerializer()
        
        # Test with 0x prefix
        result_with_prefix = serializer.from_hex("0x" + hex_chars)
        assert isinstance(result_with_prefix, bytes)
        assert len(result_with_prefix) == len(hex_chars) // 2
        
        # Test without prefix (should also work)
        result_without_prefix = serializer.from_hex(hex_chars)
        assert result_with_prefix == result_without_prefix
    
    @given(
        hex_chars=st.text(
            alphabet="0123456789abcdefABCDEF",
            min_size=1,
            max_size=199
        ).filter(lambda x: len(x) % 2 == 1)
    )
    @settings(max_examples=50)
    def test_from_hex_rejects_odd_length(self, hex_chars):
        """
        **Feature: fake-payload-generation, Property 2: Hex Serialization Round-Trip**
        **Validates: Requirements 4.2, 4.5**
        
        Property: from_hex() MUST reject hex strings with odd length.
        """
        serializer = PayloadSerializer()
        
        with pytest.raises(InvalidHexError):
            serializer.from_hex("0x" + hex_chars)


class TestPayloadParamParsing:
    """Tests for parse_payload_param functionality."""
    
    @pytest.fixture
    def serializer(self):
        """Create a PayloadSerializer instance."""
        return PayloadSerializer()
    
    @given(payload_bytes=st.binary(min_size=1, max_size=500))
    @settings(max_examples=50)
    def test_parse_hex_param_returns_bytes(self, payload_bytes):
        """
        Property: parse_payload_param() with hex string should return bytes.
        
        Requirements: 4.2
        """
        serializer = PayloadSerializer()
        
        hex_str = "0x" + payload_bytes.hex()
        result = serializer.parse_payload_param(hex_str)
        
        assert isinstance(result, bytes)
        assert result == payload_bytes
    
    def test_parse_placeholder_returns_string(self, serializer):
        """
        Property: parse_payload_param() with placeholder should return string.
        
        Requirements: 4.3
        """
        for placeholder in ["PAYLOADTLS", "PAYLOADHTTP", "PAYLOADQUIC"]:
            result = serializer.parse_payload_param(placeholder)
            assert isinstance(result, str)
            assert result == placeholder.upper()
    
    def test_parse_file_path_returns_path(self, serializer):
        """
        Property: parse_payload_param() with file path should return Path.
        
        Requirements: 4.1
        """
        result = serializer.parse_payload_param("/path/to/payload.bin")
        assert isinstance(result, Path)
        # Compare Path objects to handle platform differences
        assert result == Path("/path/to/payload.bin")
    
    def test_parse_special_value_returns_string(self, serializer):
        """
        Property: parse_payload_param() with "!" should return "!".
        """
        result = serializer.parse_payload_param("!")
        assert result == "!"


class TestPlaceholderHandling:
    """Tests for placeholder functionality."""
    
    @pytest.fixture
    def serializer(self):
        """Create a PayloadSerializer instance."""
        return PayloadSerializer()
    
    def test_is_placeholder_recognizes_valid(self, serializer):
        """Test that valid placeholders are recognized."""
        assert serializer.is_placeholder("PAYLOADTLS")
        assert serializer.is_placeholder("PAYLOADHTTP")
        assert serializer.is_placeholder("PAYLOADQUIC")
        # Case insensitive
        assert serializer.is_placeholder("payloadtls")
    
    def test_is_placeholder_rejects_invalid(self, serializer):
        """Test that invalid placeholders are rejected."""
        assert not serializer.is_placeholder("INVALID")
        assert not serializer.is_placeholder("0x1234")
        assert not serializer.is_placeholder("/path/to/file")
    
    def test_get_placeholder_type_returns_correct_type(self, serializer):
        """Test placeholder to PayloadType mapping."""
        assert serializer.get_placeholder_type("PAYLOADTLS") == PayloadType.TLS
        assert serializer.get_placeholder_type("PAYLOADHTTP") == PayloadType.HTTP
        assert serializer.get_placeholder_type("PAYLOADQUIC") == PayloadType.QUIC
    
    def test_get_placeholder_type_raises_for_invalid(self, serializer):
        """Test that invalid placeholder raises error."""
        with pytest.raises(InvalidPlaceholderError):
            serializer.get_placeholder_type("INVALID")


class TestZapretFormatting:
    """Tests for zapret-compatible formatting."""
    
    @pytest.fixture
    def serializer(self):
        """Create a PayloadSerializer instance."""
        return PayloadSerializer()
    
    @given(payload_bytes=st.binary(min_size=1, max_size=100))
    @settings(max_examples=50)
    def test_format_for_zapret_hex(self, payload_bytes):
        """
        Property: format_for_zapret with use_file=False should produce valid hex format.
        
        Requirements: 4.5
        """
        serializer = PayloadSerializer()
        
        result = serializer.format_for_zapret(
            payload_bytes,
            PayloadType.TLS,
            use_file=False
        )
        
        assert result.startswith("--dpi-desync-fake-tls=0x")
        # Extract hex part and verify round-trip
        hex_part = result.split("=")[1]
        decoded = serializer.from_hex(hex_part)
        assert decoded == payload_bytes
    
    def test_format_for_zapret_file(self, serializer):
        """
        Property: format_for_zapret with use_file=True should produce file path format.
        
        Requirements: 4.5
        """
        result = serializer.format_for_zapret(
            b"\x16\x03\x01",
            PayloadType.TLS,
            use_file=True,
            file_path="/path/to/payload.bin"
        )
        
        assert result == "--dpi-desync-fake-tls=/path/to/payload.bin"
    
    def test_format_for_zapret_http_type(self, serializer):
        """Test HTTP payload type uses correct parameter."""
        result = serializer.format_for_zapret(
            b"GET / HTTP/1.1",
            PayloadType.HTTP,
            use_file=False
        )
        
        assert result.startswith("--dpi-desync-fake-http=")
    
    def test_format_for_zapret_quic_type(self, serializer):
        """Test QUIC payload type uses correct parameter."""
        result = serializer.format_for_zapret(
            b"\xc0\x00\x00\x01",
            PayloadType.QUIC,
            use_file=False
        )
        
        assert result.startswith("--dpi-desync-fake-quic=")
