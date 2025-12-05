"""
SNI Domain Extractor

This module implements domain extraction from network packets, supporting both
TLS SNI (Server Name Indication) and HTTP Host header extraction.
"""

from typing import Optional
import logging
import re

logger = logging.getLogger(__name__)


class SNIDomainExtractor:
    """
    Extracts domain names from TLS ClientHello packets and HTTP requests.
    
    This class moves the existing SNI extraction logic from base_engine.py
    and enhances it with HTTP Host header support and better error handling.
    """
    
    def __init__(self):
        """Initialize the SNI domain extractor."""
        # Compiled regex for HTTP Host header extraction
        self.http_host_pattern = re.compile(rb'Host:\s*([^\r\n]+)', re.IGNORECASE)
        
        logger.debug("SNIDomainExtractor initialized")
    
    def extract_domain_from_packet(self, packet) -> Optional[str]:
        """
        Extract domain from packet payload (TLS SNI or HTTP Host).
        
        This method attempts to extract the domain name from the packet payload
        by trying TLS SNI extraction first, then falling back to HTTP Host header.
        
        Args:
            packet: The network packet to extract domain from
            
        Returns:
            Extracted domain name, or None if extraction fails
        """
        try:
            # Get packet payload
            payload = getattr(packet, 'payload', None)
            if not payload:
                return None
            
            # Try TLS SNI extraction first
            domain = self._extract_sni_from_tls(payload)
            if domain:
                logger.debug(f"Extracted domain from TLS SNI: {domain}")
                return domain
            
            # Fall back to HTTP Host header extraction
            domain = self.extract_host_from_http(payload)
            if domain:
                logger.debug(f"Extracted domain from HTTP Host: {domain}")
                return domain
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting domain from packet: {e}")
            return None 
   
    def _extract_sni_from_tls(self, payload: Optional[bytes]) -> Optional[str]:
        """
        Extract SNI from TLS ClientHello packet.
        
        This method implements the TLS ClientHello parsing logic moved from
        base_engine.py with enhanced error handling and validation.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            SNI domain name, or None if extraction fails
        """
        try:
            if not payload or len(payload) < 43:
                return None
                
            # Check if this is a TLS handshake packet (0x16)
            if payload[0] != 0x16:
                return None
                
            # Check if this is a ClientHello (0x01)
            if payload[5] != 0x01:
                return None

            # Parse TLS ClientHello structure
            pos = 9
            
            # Skip random (32 bytes) + version (2 bytes)
            pos += 2 + 32
            if pos + 1 > len(payload):
                return None

            # Skip session ID
            sid_len = payload[pos]
            pos += 1 + sid_len
            if pos + 2 > len(payload):
                return None

            # Skip cipher suites
            cs_len = int.from_bytes(payload[pos : pos + 2], "big")
            pos += 2 + cs_len
            if pos + 1 > len(payload):
                return None

            # Skip compression methods
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return None

            # Parse extensions
            ext_len = int.from_bytes(payload[pos : pos + 2], "big")
            ext_start = pos + 2
            ext_end = min(len(payload), ext_start + ext_len)
            
            return self._parse_tls_extensions(payload, ext_start, ext_end)
            
        except Exception as e:
            logger.debug(f"Error extracting SNI from TLS: {e}")
            return None    

    def _parse_tls_extensions(self, payload: bytes, ext_start: int, ext_end: int) -> Optional[str]:
        """
        Parse TLS extensions to find SNI extension.
        
        Args:
            payload: Raw packet payload bytes
            ext_start: Start position of extensions
            ext_end: End position of extensions
            
        Returns:
            SNI domain name, or None if not found
        """
        s = ext_start
        while s + 4 <= ext_end:
            # Parse extension type and length
            etype = int.from_bytes(payload[s : s + 2], "big")
            elen = int.from_bytes(payload[s + 2 : s + 4], "big")
            epos = s + 4
            
            if epos + elen > ext_end:
                break
                
            # Check if this is SNI extension (type 0)
            if etype == 0 and elen >= 5:
                sni_domain = self._parse_sni_extension(payload, epos, elen)
                if sni_domain:
                    return sni_domain
                    
            s = epos + elen
            
        return None
    
    def _parse_sni_extension(self, payload: bytes, epos: int, elen: int) -> Optional[str]:
        """
        Parse SNI extension to extract domain name.
        
        Args:
            payload: Raw packet payload bytes
            epos: Extension position
            elen: Extension length
            
        Returns:
            SNI domain name, or None if parsing fails
        """
        try:
            list_len = int.from_bytes(payload[epos : epos + 2], "big")
            npos = epos + 2
            
            if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                ntype = payload[npos]
                nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
                nstart = npos + 3
                
                if ntype == 0 and nstart + nlen <= len(payload):
                    try:
                        domain = payload[nstart : nstart + nlen].decode("idna", errors="strict")
                        return self._validate_domain(domain)
                    except Exception:
                        return None
                        
        except Exception:
            pass
            
        return None 
   
    def extract_host_from_http(self, payload: bytes) -> Optional[str]:
        """
        Extract domain from HTTP Host header.
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            Host domain name, or None if extraction fails
        """
        try:
            # Search for Host header in HTTP request
            match = self.http_host_pattern.search(payload)
            if match:
                host = match.group(1).decode('ascii', errors='ignore').strip()
                return self._validate_domain(host)
                
        except Exception as e:
            logger.debug(f"Error extracting HTTP Host: {e}")
            
        return None
    
    def _validate_domain(self, domain: str) -> Optional[str]:
        """
        Validate and normalize extracted domain.
        
        Args:
            domain: Raw domain string to validate
            
        Returns:
            Validated domain name, or None if invalid
        """
        if not domain:
            return None
            
        try:
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Basic domain validation
            domain = domain.lower().strip()
            
            # Check for valid domain format (basic check)
            if not domain or '.' not in domain or len(domain) > 253:
                return None
                
            # Check for invalid characters
            if any(c in domain for c in [' ', '\t', '\n', '\r']):
                return None
                
            return domain
            
        except Exception:
            return None