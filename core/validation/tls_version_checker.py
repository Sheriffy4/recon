"""
TLS Version Checker for diagnostics.

This module provides utilities to extract and compare TLS versions from ClientHello
messages to detect inconsistencies between TEST and BYPASS modes.
"""

import struct
import logging
from typing import Optional, Tuple

LOG = logging.getLogger(__name__)


class TLSVersionChecker:
    """
    Extracts and validates TLS versions from ClientHello messages.
    
    This is a diagnostic tool to detect TLS version mismatches between
    TEST and BYPASS modes that can cause inconsistent testing results.
    """
    
    # TLS version constants
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }
    
    @staticmethod
    def extract_tls_version(payload: bytes) -> Optional[str]:
        """
        Extract TLS version from ClientHello payload.
        
        Args:
            payload: Raw bytes of TLS ClientHello message
            
        Returns:
            TLS version string (e.g., "TLS 1.2", "TLS 1.3") or None if not found
            
        The TLS version is in the first 2 bytes of the TLS record:
        - Byte 0: Content Type (0x16 for Handshake)
        - Bytes 1-2: TLS version (0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
        """
        try:
            # Check minimum length and content type
            if len(payload) < 6:
                return None
            
            # Byte 0 should be 0x16 (Handshake)
            if payload[0] != 0x16:
                return None
            
            # Bytes 1-2 contain the TLS record version
            version_bytes = struct.unpack(">H", payload[1:3])[0]
            
            # Return human-readable version
            return TLSVersionChecker.TLS_VERSIONS.get(version_bytes, f"Unknown (0x{version_bytes:04X})")
            
        except Exception as e:
            LOG.debug(f"Failed to extract TLS version: {e}")
            return None
    
    @staticmethod
    def extract_clienthello_size(payload: bytes) -> Optional[int]:
        """
        Extract ClientHello message size from TLS record.
        
        Args:
            payload: Raw bytes of TLS ClientHello message
            
        Returns:
            Size of ClientHello in bytes, or None if not found
        """
        try:
            if len(payload) < 6:
                return None
            
            # Bytes 3-4 contain the TLS record length
            record_length = struct.unpack(">H", payload[3:5])[0]
            
            # Total size is header (5 bytes) + record length
            return 5 + record_length
            
        except Exception as e:
            LOG.debug(f"Failed to extract ClientHello size: {e}")
            return None
    
    @staticmethod
    def check_consistency(
        test_hello: bytes,
        bypass_hello: bytes
    ) -> Tuple[bool, dict]:
        """
        Compare TLS versions and sizes between TEST and BYPASS ClientHello.
        
        Args:
            test_hello: ClientHello from TEST mode
            bypass_hello: ClientHello from BYPASS mode
            
        Returns:
            Tuple of (is_consistent, details_dict)
            - is_consistent: True if versions match
            - details_dict: Contains version and size information
        """
        test_version = TLSVersionChecker.extract_tls_version(test_hello)
        bypass_version = TLSVersionChecker.extract_tls_version(bypass_hello)
        
        test_size = len(test_hello)
        bypass_size = len(bypass_hello)
        
        details = {
            'test_version': test_version,
            'bypass_version': bypass_version,
            'test_size': test_size,
            'bypass_size': bypass_size,
            'version_match': test_version == bypass_version,
            'size_diff_percent': abs(test_size - bypass_size) / max(test_size, bypass_size) * 100
        }
        
        # Check version consistency
        if test_version != bypass_version:
            LOG.warning(
                f"⚠️  TLS version mismatch detected!\n"
                f"   TEST mode:   {test_version}\n"
                f"   BYPASS mode: {bypass_version}\n"
                f"   This may cause inconsistent testing results!"
            )
            return False, details
        
        # Check size consistency (warn if >50% difference)
        if details['size_diff_percent'] > 50:
            LOG.warning(
                f"⚠️  ClientHello size differs significantly!\n"
                f"   TEST mode:   {test_size} bytes\n"
                f"   BYPASS mode: {bypass_size} bytes\n"
                f"   Difference:  {details['size_diff_percent']:.1f}%\n"
                f"   This may indicate TLS version mismatch."
            )
        
        return test_version == bypass_version, details
    
    @staticmethod
    def validate_split_pos_for_versions(
        split_pos: int,
        tls12_size: int,
        tls13_size: int
    ) -> bool:
        """
        Validate that split_pos works for both TLS 1.2 and TLS 1.3 ClientHello sizes.
        
        Args:
            split_pos: Configured split position
            tls12_size: Typical TLS 1.2 ClientHello size
            tls13_size: Typical TLS 1.3 ClientHello size
            
        Returns:
            True if split_pos is valid for both versions
        """
        min_size = min(tls12_size, tls13_size)
        
        if split_pos >= min_size:
            LOG.error(
                f"❌ split_pos={split_pos} is too large!\n"
                f"   TLS 1.2 size: {tls12_size} bytes\n"
                f"   TLS 1.3 size: {tls13_size} bytes\n"
                f"   Minimum:      {min_size} bytes\n"
                f"   split_pos must be less than the smallest ClientHello size."
            )
            return False
        
        LOG.info(
            f"✅ split_pos={split_pos} is valid for both TLS versions\n"
            f"   TLS 1.2 size: {tls12_size} bytes\n"
            f"   TLS 1.3 size: {tls13_size} bytes"
        )
        return True
