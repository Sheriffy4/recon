"""
Tests for SNI extraction utilities.

This test suite validates SNI extraction from TLS ClientHello messages.
"""

import pytest
from core.bypass.engine.sni_utils import extract_sni_from_clienthello


class TestSNIExtraction:
    """Test SNI extraction from TLS ClientHello packets."""

    def test_extract_sni_none_payload(self):
        """Test handling of None payload."""
        assert extract_sni_from_clienthello(None) is None

    def test_extract_sni_empty_payload(self):
        """Test handling of empty payload."""
        assert extract_sni_from_clienthello(b"") is None

    def test_extract_sni_too_short(self):
        """Test handling of too-short payload."""
        payload = b"\x16\x03\x01\x00\x10"
        assert extract_sni_from_clienthello(payload) is None

    def test_extract_sni_not_handshake(self):
        """Test rejection of non-handshake packets."""
        # Application Data (0x17) instead of Handshake (0x16)
        payload = b"\x17\x03\x01\x00\x30" + b"\x01" + b"\x00" * 40
        assert extract_sni_from_clienthello(payload) is None

    def test_extract_sni_not_clienthello(self):
        """Test rejection of non-ClientHello handshake packets."""
        # ServerHello (0x02) instead of ClientHello (0x01)
        payload = b"\x16\x03\x01\x00\x30" + b"\x02" + b"\x00" * 40
        assert extract_sni_from_clienthello(payload) is None

    def test_extract_sni_no_extensions(self):
        """Test ClientHello without extensions."""
        # Minimal ClientHello without extensions
        payload = (
            b"\x16\x03\x01\x00\x28"  # TLS record header
            b"\x01\x00\x00\x24"  # Handshake header (ClientHello, length 36)
            b"\x03\x03"  # TLS version 1.2
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID length (0)
            + b"\x00\x02"  # Cipher suites length (2)
            + b"\x00\x00"  # Cipher suite
            + b"\x01"  # Compression methods length (1)
            + b"\x00"  # Compression method (null)
        )
        # No extensions, so no SNI
        assert extract_sni_from_clienthello(payload) is None

    def test_extract_sni_malformed_extension(self):
        """Test handling of malformed SNI extension."""
        payload = (
            b"\x16\x03\x01\x00\x40"  # TLS record header
            b"\x01\x00\x00\x3c"  # Handshake header
            b"\x03\x03"  # TLS version 1.2
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID length (0)
            + b"\x00\x02"  # Cipher suites length (2)
            + b"\x00\x00"  # Cipher suite
            + b"\x01"  # Compression methods length (1)
            + b"\x00"  # Compression method (null)
            + b"\x00\x08"  # Extensions length (8 bytes)
            # Malformed SNI Extension (too short)
            + b"\x00\x00"  # Extension type: Server Name (0)
            + b"\x00\x04"  # Extension length (4 bytes) - too short for valid SNI
            + b"\x00\x02"  # Server Name List length
            + b"\x00\x00"  # Incomplete data
        )

        # Should return None for malformed extension
        result = extract_sni_from_clienthello(payload)
        assert result is None


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that extract_sni_from_clienthello can be imported from base_engine."""
        from core.bypass.engine.base_engine import (
            extract_sni_from_clienthello as base_extract_sni,
        )

        # Verify it's the same function
        assert base_extract_sni is extract_sni_from_clienthello

    def test_investigate_script_compatibility(self):
        """Test that investigate_sni_extraction_issues.py can use the shared function."""
        # This test verifies the import works as expected in the investigation script
        from core.bypass.engine.sni_utils import extract_sni_from_clienthello

        # Test with None - should not crash
        result = extract_sni_from_clienthello(None)
        assert result is None

        # Test with invalid packet - should return None gracefully
        result = extract_sni_from_clienthello(b"\x00" * 100)
        assert result is None
