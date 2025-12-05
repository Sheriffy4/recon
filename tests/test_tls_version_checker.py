"""
Unit tests for TLS version checker.
"""

import pytest
import struct
from core.validation.tls_version_checker import TLSVersionChecker


class TestTLSVersionExtraction:
    """Test TLS version extraction from ClientHello."""
    
    def test_extract_tls_12_version(self):
        """Test extracting TLS 1.2 version."""
        # Create minimal TLS 1.2 ClientHello
        # 0x16 = Handshake, 0x0303 = TLS 1.2
        payload = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version == "TLS 1.2"
    
    def test_extract_tls_13_version(self):
        """Test extracting TLS 1.3 version."""
        # Create minimal TLS 1.3 ClientHello
        # 0x16 = Handshake, 0x0304 = TLS 1.3
        payload = b'\x16\x03\x04\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version == "TLS 1.3"
    
    def test_extract_tls_10_version(self):
        """Test extracting TLS 1.0 version."""
        payload = b'\x16\x03\x01\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version == "TLS 1.0"
    
    def test_extract_tls_11_version(self):
        """Test extracting TLS 1.1 version."""
        payload = b'\x16\x03\x02\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version == "TLS 1.1"
    
    def test_extract_unknown_version(self):
        """Test extracting unknown TLS version."""
        payload = b'\x16\x03\xFF\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version == "Unknown (0x03FF)"
    
    def test_extract_version_too_short(self):
        """Test with payload too short."""
        payload = b'\x16\x03'
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version is None
    
    def test_extract_version_not_handshake(self):
        """Test with non-handshake content type."""
        # 0x17 = Application Data
        payload = b'\x17\x03\x03\x00\x10' + b'\x00' * 16
        
        version = TLSVersionChecker.extract_tls_version(payload)
        assert version is None
    
    def test_extract_version_empty(self):
        """Test with empty payload."""
        version = TLSVersionChecker.extract_tls_version(b'')
        assert version is None


class TestClientHelloSize:
    """Test ClientHello size extraction."""
    
    def test_extract_size_small(self):
        """Test extracting size from small ClientHello."""
        # Record length = 16 bytes
        payload = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
        
        size = TLSVersionChecker.extract_clienthello_size(payload)
        # Total = 5 (header) + 16 (record) = 21
        assert size == 21
    
    def test_extract_size_large(self):
        """Test extracting size from large ClientHello."""
        # Record length = 1000 bytes
        payload = b'\x16\x03\x03\x03\xE8' + b'\x00' * 1000
        
        size = TLSVersionChecker.extract_clienthello_size(payload)
        # Total = 5 (header) + 1000 (record) = 1005
        assert size == 1005
    
    def test_extract_size_too_short(self):
        """Test with payload too short."""
        payload = b'\x16\x03'
        
        size = TLSVersionChecker.extract_clienthello_size(payload)
        assert size is None


class TestConsistencyCheck:
    """Test TLS version consistency checking."""
    
    def test_check_consistency_matching(self):
        """Test consistency check with matching versions."""
        test_hello = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
        bypass_hello = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
        
        is_consistent, details = TLSVersionChecker.check_consistency(
            test_hello, bypass_hello
        )
        
        assert is_consistent is True
        assert details['test_version'] == "TLS 1.2"
        assert details['bypass_version'] == "TLS 1.2"
        assert details['version_match'] is True
    
    def test_check_consistency_mismatch(self):
        """Test consistency check with mismatched versions."""
        test_hello = b'\x16\x03\x03\x00\x10' + b'\x00' * 16  # TLS 1.2
        bypass_hello = b'\x16\x03\x04\x00\x10' + b'\x00' * 16  # TLS 1.3
        
        is_consistent, details = TLSVersionChecker.check_consistency(
            test_hello, bypass_hello
        )
        
        assert is_consistent is False
        assert details['test_version'] == "TLS 1.2"
        assert details['bypass_version'] == "TLS 1.3"
        assert details['version_match'] is False
    
    def test_check_consistency_size_difference(self):
        """Test consistency check with large size difference."""
        # TEST: 21 bytes total
        test_hello = b'\x16\x03\x03\x00\x10' + b'\x00' * 16
        # BYPASS: 1005 bytes total (>50% difference)
        bypass_hello = b'\x16\x03\x03\x03\xE8' + b'\x00' * 1000
        
        is_consistent, details = TLSVersionChecker.check_consistency(
            test_hello, bypass_hello
        )
        
        # Versions match but sizes differ significantly
        assert is_consistent is True  # Version match
        assert details['test_size'] == 21
        assert details['bypass_size'] == 1005
        assert details['size_diff_percent'] > 50


class TestSplitPosValidation:
    """Test split_pos validation for different TLS versions."""
    
    def test_validate_split_pos_valid(self):
        """Test split_pos that works for both versions."""
        # split_pos=2 is valid for both 562 and 1893 byte ClientHellos
        result = TLSVersionChecker.validate_split_pos_for_versions(
            split_pos=2,
            tls12_size=562,
            tls13_size=1893
        )
        assert result is True
    
    def test_validate_split_pos_too_large(self):
        """Test split_pos that's too large for smaller version."""
        # split_pos=600 is too large for TLS 1.2 (562 bytes)
        result = TLSVersionChecker.validate_split_pos_for_versions(
            split_pos=600,
            tls12_size=562,
            tls13_size=1893
        )
        assert result is False
    
    def test_validate_split_pos_edge_case(self):
        """Test split_pos at the edge."""
        # split_pos=561 is just under TLS 1.2 size
        result = TLSVersionChecker.validate_split_pos_for_versions(
            split_pos=561,
            tls12_size=562,
            tls13_size=1893
        )
        assert result is True
        
        # split_pos=562 equals TLS 1.2 size (invalid)
        result = TLSVersionChecker.validate_split_pos_for_versions(
            split_pos=562,
            tls12_size=562,
            tls13_size=1893
        )
        assert result is False
