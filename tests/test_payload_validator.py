"""
Property-based tests for PayloadValidator.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from core.payload.validator import PayloadValidator, ValidationResult
from core.payload.types import PayloadType


class TestTLSClientHelloValidation:
    """
    Property-based tests for TLS ClientHello validation.
    
    **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
    **Validates: Requirements 1.2, 2.5**
    
    Property: For any byte sequence, if PayloadValidator identifies it as a 
    valid TLS ClientHello, then the sequence MUST start with bytes 0x16 0x03 
    and contain a handshake header at offset 5 with type 0x01.
    """
    
    @pytest.fixture
    def validator(self):
        """Create a PayloadValidator instance."""
        return PayloadValidator()
    
    @given(data=st.binary(min_size=0, max_size=2000))
    @settings(max_examples=100)
    def test_valid_tls_implies_correct_header_structure(self, data):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: If PayloadValidator.validate_tls_clienthello() returns valid=True,
        then the data MUST:
        1. Start with 0x16 (TLS Handshake content type)
        2. Have 0x03 at byte 1 (TLS version major)
        3. Have 0x01 at byte 5 (ClientHello handshake type)
        """
        validator = PayloadValidator()
        result = validator.validate_tls_clienthello(data)
        
        if result.valid:
            # Property 1: Must start with 0x16 (Handshake)
            assert len(data) >= 6, "Valid TLS must have at least 6 bytes"
            assert data[0] == 0x16, "Valid TLS must start with 0x16"
            
            # Property 2: Must have 0x03 at byte 1 (version major)
            assert data[1] == 0x03, "Valid TLS must have 0x03 at byte 1"
            
            # Property 3: Must have 0x01 at byte 5 (ClientHello)
            assert data[5] == 0x01, "Valid TLS ClientHello must have 0x01 at byte 5"
    
    @given(
        version_minor=st.sampled_from([0x01, 0x02, 0x03]),
        record_length=st.integers(min_value=38, max_value=500),
        random_bytes=st.binary(min_size=32, max_size=32),
        extra_data=st.binary(min_size=0, max_size=200)
    )
    @settings(max_examples=100)
    def test_well_formed_clienthello_is_valid(
        self, version_minor, record_length, random_bytes, extra_data
    ):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: Any well-formed TLS ClientHello structure should be validated
        as valid by the validator.
        """
        validator = PayloadValidator()
        
        # Build a minimal valid ClientHello structure
        # TLS Record Header (5 bytes)
        tls_header = bytes([
            0x16,           # Content type: Handshake
            0x03,           # Version major
            version_minor,  # Version minor
            (record_length >> 8) & 0xFF,  # Length high byte
            record_length & 0xFF,         # Length low byte
        ])
        
        # Handshake Header (4 bytes)
        handshake_length = record_length - 4
        handshake_header = bytes([
            0x01,  # Handshake type: ClientHello
            0x00,  # Length high byte (24-bit)
            (handshake_length >> 8) & 0xFF,  # Length mid byte
            handshake_length & 0xFF,         # Length low byte
        ])
        
        # ClientHello body (minimal)
        client_version = bytes([0x03, 0x03])  # TLS 1.2
        
        # Pad to match declared length
        body_so_far = client_version + random_bytes
        padding_needed = max(0, record_length - 4 - len(body_so_far))
        padding = extra_data[:padding_needed] if extra_data else b'\x00' * padding_needed
        
        payload = tls_header + handshake_header + body_so_far + padding
        
        result = validator.validate_tls_clienthello(payload)
        
        assert result.valid, f"Well-formed ClientHello should be valid: {result.errors}"
        assert result.payload_type == PayloadType.TLS
    
    @given(first_byte=st.integers(min_value=0, max_value=255).filter(lambda x: x != 0x16))
    @settings(max_examples=50)
    def test_wrong_content_type_is_invalid(self, first_byte):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: Any payload not starting with 0x16 should be invalid TLS.
        """
        validator = PayloadValidator()
        
        # Create payload with wrong content type
        payload = bytes([first_byte, 0x03, 0x03, 0x00, 0x30, 0x01]) + b'\x00' * 48
        
        result = validator.validate_tls_clienthello(payload)
        
        assert not result.valid, "Wrong content type should be invalid"
    
    @given(version_major=st.integers(min_value=0, max_value=255).filter(lambda x: x != 0x03))
    @settings(max_examples=50)
    def test_wrong_version_major_is_invalid(self, version_major):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: Any payload without 0x03 at byte 1 should be invalid TLS.
        """
        validator = PayloadValidator()
        
        # Create payload with wrong version major
        payload = bytes([0x16, version_major, 0x03, 0x00, 0x30, 0x01]) + b'\x00' * 48
        
        result = validator.validate_tls_clienthello(payload)
        
        assert not result.valid, "Wrong version major should be invalid"
    
    @given(handshake_type=st.integers(min_value=0, max_value=255).filter(lambda x: x != 0x01))
    @settings(max_examples=50)
    def test_wrong_handshake_type_is_invalid(self, handshake_type):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: Any payload without 0x01 at byte 5 should not be valid ClientHello.
        """
        validator = PayloadValidator()
        
        # Create payload with wrong handshake type
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x30, handshake_type]) + b'\x00' * 48
        
        result = validator.validate_tls_clienthello(payload)
        
        assert not result.valid, "Wrong handshake type should be invalid ClientHello"
    
    @given(size=st.integers(min_value=0, max_value=4))
    @settings(max_examples=20)
    def test_too_short_payload_is_invalid(self, size):
        """
        **Feature: fake-payload-generation, Property 1: TLS ClientHello Validation**
        **Validates: Requirements 1.2, 2.5**
        
        Property: Payloads shorter than minimum TLS record size should be invalid.
        """
        validator = PayloadValidator()
        
        # Create too-short payload
        payload = b'\x16\x03\x03\x00\x30'[:size]
        
        result = validator.validate_tls_clienthello(payload)
        
        assert not result.valid, f"Payload of {size} bytes should be invalid"


class TestAutoDetection:
    """Tests for automatic payload type detection."""
    
    @given(data=st.binary(min_size=0, max_size=100))
    @settings(max_examples=50)
    def test_validate_returns_consistent_type(self, data):
        """
        Property: validate() should return consistent payload type detection.
        """
        validator = PayloadValidator()
        result = validator.validate(data)
        
        # Result should always have a payload_type
        assert result.payload_type in PayloadType
        
        # If valid, type should not be UNKNOWN
        if result.valid:
            assert result.payload_type != PayloadType.UNKNOWN
