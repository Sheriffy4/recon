"""
SNI Extractor component for runtime packet filtering.

This module provides functionality to extract SNI (Server Name Indication)
information from TLS Client Hello packets with performance optimizations.
"""

import struct
from typing import Optional
from functools import lru_cache


class SNIExtractor:
    """
    Extracts SNI information from TLS packets for runtime filtering.
    
    This class provides optimized SNI extraction with fast-path processing
    for common cases and efficient parsing of TLS ClientHello packets.
    """
    
    # TLS record type constants
    TLS_HANDSHAKE = 0x16
    TLS_CLIENT_HELLO = 0x01
    
    # TLS version constants (network byte order)
    TLS_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}  # TLS 1.0-1.3
    
    def __init__(self):
        """Initialize SNI Extractor with performance optimizations."""
        # Cache for recently processed payload prefixes
        self._cache_size = 100
        self._fast_reject_cache = {}
    
    def extract_sni(self, payload: bytes) -> Optional[str]:
        """
        Extract SNI from TLS ClientHello packets with optimized parsing.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            SNI hostname string if found, None otherwise
            
        Requirements: 1.1, 6.1, 6.3
        """
        if not payload or len(payload) < 43:  # Minimum TLS ClientHello size
            return None
        
        # Fast rejection for non-TLS traffic
        if not self._is_likely_tls_clienthello(payload):
            return None
        
        try:
            return self._extract_sni_optimized(payload)
        except (struct.error, IndexError, UnicodeDecodeError):
            # Fallback to existing detector if optimized parsing fails
            try:
                from ..strategies.sni_detector import SNIDetector
                detector = SNIDetector()
                return detector.extract_sni_value(payload)
            except Exception:
                return None
    
    def _is_likely_tls_clienthello(self, payload: bytes) -> bool:
        """
        Fast check if payload is likely a TLS ClientHello.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            True if likely TLS ClientHello, False otherwise
        """
        if len(payload) < 6:
            return False
        
        # Check cache for fast rejection
        prefix = payload[:6]
        if prefix in self._fast_reject_cache:
            return self._fast_reject_cache[prefix]
        
        # Check TLS record header
        record_type = payload[0]
        if record_type != self.TLS_HANDSHAKE:
            result = False
        else:
            # Check TLS version (bytes 1-2)
            version = struct.unpack('>H', payload[1:3])[0]
            if version not in self.TLS_VERSIONS:
                result = False
            else:
                # Check handshake message type (byte 5)
                if len(payload) > 5 and payload[5] == self.TLS_CLIENT_HELLO:
                    result = True
                else:
                    result = False
        
        # Cache result (with size limit)
        if len(self._fast_reject_cache) < self._cache_size:
            self._fast_reject_cache[prefix] = result
        
        return result
    
    def _extract_sni_optimized(self, payload: bytes) -> Optional[str]:
        """
        Optimized SNI extraction with minimal parsing.
        
        Args:
            payload: TLS ClientHello payload
            
        Returns:
            SNI hostname if found, None otherwise
        """
        # Skip TLS record header (5 bytes) and handshake header (4 bytes)
        offset = 9
        
        if len(payload) < offset + 34:  # Need at least ClientHello fixed part
            return None
        
        # Skip ClientHello fixed fields:
        # - Protocol version (2 bytes)
        # - Random (32 bytes)
        offset += 34
        
        # Skip Session ID
        if len(payload) < offset + 1:
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        # Skip Cipher Suites
        if len(payload) < offset + 2:
            return None
        cipher_suites_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2 + cipher_suites_len
        
        # Skip Compression Methods
        if len(payload) < offset + 1:
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len
        
        # Check for extensions
        if len(payload) < offset + 2:
            return None
        extensions_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        # Parse extensions to find SNI
        extensions_end = offset + extensions_len
        while offset < extensions_end - 4:
            if len(payload) < offset + 4:
                break
            
            ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
            ext_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
            offset += 4
            
            if ext_type == 0x0000:  # SNI extension
                return self._parse_sni_extension(payload[offset:offset+ext_len])
            
            offset += ext_len
        
        return None
    
    def _parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """
        Parse SNI extension data to extract hostname.
        
        Args:
            sni_data: SNI extension payload
            
        Returns:
            SNI hostname if found, None otherwise
        """
        if len(sni_data) < 5:
            return None
        
        # Skip server name list length (2 bytes)
        offset = 2
        
        # Parse server name entries
        while offset < len(sni_data) - 3:
            name_type = sni_data[offset]
            if name_type == 0x00:  # hostname type
                name_len = struct.unpack('>H', sni_data[offset+1:offset+3])[0]
                offset += 3
                
                if offset + name_len <= len(sni_data):
                    hostname = sni_data[offset:offset+name_len].decode('utf-8', errors='ignore')
                    if self._is_valid_hostname(hostname):
                        return hostname
                
                offset += name_len
            else:
                # Skip unknown name types
                if offset + 3 > len(sni_data):
                    break
                name_len = struct.unpack('>H', sni_data[offset+1:offset+3])[0]
                offset += 3 + name_len
        
        return None
    
    @lru_cache(maxsize=256)
    def _is_valid_hostname(self, hostname: str) -> bool:
        """
        Validate hostname with caching for performance.
        
        Args:
            hostname: Hostname to validate
            
        Returns:
            True if hostname is valid, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False
        
        # Basic character validation
        allowed_chars = set(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-'
        )
        if not all(c in allowed_chars for c in hostname):
            return False
        
        # Structure validation
        if hostname.startswith('.') or hostname.endswith('.') or '..' in hostname:
            return False
        
        return True
    
    def is_tls_clienthello(self, payload: bytes) -> bool:
        """
        Check if payload is a TLS ClientHello packet.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            True if payload is TLS ClientHello, False otherwise
            
        Requirements: 1.1, 6.1
        """
        return self._is_likely_tls_clienthello(payload)
    
    def clear_cache(self) -> None:
        """Clear internal caches for memory management."""
        self._fast_reject_cache.clear()
        self._is_valid_hostname.cache_clear()