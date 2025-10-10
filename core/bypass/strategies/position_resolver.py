"""
Position Resolver for DPI Strategy Engine

This module handles position resolution for packet splitting, including:
- Numeric positions (3, 10, etc.)
- SNI position detection in TLS packets
- Position validation and priority handling
"""

from typing import List, Optional, Union
import logging
import struct
from .config_models import SplitConfig
from .exceptions import InvalidSplitPositionError, PacketTooSmallError, SNINotFoundError

logger = logging.getLogger(__name__)


class PositionResolver:
    """Resolves split positions for DPI strategy application"""
    
    def __init__(self):
        self.logger = logger
    
    def resolve_numeric_positions(self, packet: bytes, positions: List[int]) -> List[int]:
        """
        Resolve numeric positions for packet splitting.
        
        Args:
            packet: The packet bytes to analyze
            positions: List of numeric positions (e.g., [3, 10])
            
        Returns:
            List of valid positions that can be used for splitting
            
        Raises:
            PacketTooSmallError: If packet is too small for any position
        """
        if not packet:
            raise PacketTooSmallError("Packet is empty")
        
        valid_positions = []
        packet_size = len(packet)
        
        for position in positions:
            if self.validate_position(packet, position):
                valid_positions.append(position)
                self.logger.debug(f"Position {position} is valid for packet size {packet_size}")
            else:
                self.logger.warning(f"Position {position} is invalid for packet size {packet_size}")
        
        if not valid_positions:
            self.logger.warning(f"No valid numeric positions found for packet size {packet_size}")
        
        return sorted(valid_positions)
    
    def validate_position(self, packet: bytes, position: int) -> bool:
        """
        Validate if a position is valid for packet splitting.
        
        Args:
            packet: The packet bytes to validate against
            position: The position to validate
            
        Returns:
            True if position is valid, False otherwise
        """
        if not packet:
            return False
        
        packet_size = len(packet)
        
        # Position must be positive and less than packet size
        # We need at least 1 byte in each part after splitting
        if position <= 0:
            return False
        
        if position >= packet_size:
            return False
        
        # Ensure we have at least 1 byte for the second part
        if position >= packet_size - 1:
            return False
        
        return True
    
    def resolve_sni_position(self, packet: bytes) -> Optional[int]:
        """
        Find SNI extension position in TLS Client Hello packet.
        
        Args:
            packet: The packet bytes to analyze
            
        Returns:
            Position of SNI extension start, or None if not found
        """
        try:
            if not self._is_client_hello(packet):
                self.logger.debug("Packet is not a TLS Client Hello")
                return None
            
            sni_position = self._find_sni_extension_position(packet)
            if sni_position is not None:
                self.logger.debug(f"SNI extension found at position {sni_position}")
            else:
                self.logger.debug("SNI extension not found in TLS Client Hello")
            
            return sni_position
            
        except Exception as e:
            self.logger.error(f"Error finding SNI position: {e}")
            return None
    
    def _is_client_hello(self, packet: bytes) -> bool:
        """
        Check if packet is a TLS Client Hello.
        
        Args:
            packet: The packet bytes to check
            
        Returns:
            True if packet is TLS Client Hello, False otherwise
        """
        if len(packet) < 6:
            return False
        
        try:
            # Check for TLS record header
            # TLS record: type(1) + version(2) + length(2) + handshake_type(1)
            record_type = packet[0]
            version = struct.unpack('>H', packet[1:3])[0]
            handshake_type = packet[5] if len(packet) > 5 else 0
            
            # TLS record type should be 22 (handshake)
            # Version should be TLS 1.0+ (0x0301+)
            # Handshake type should be 1 (Client Hello)
            return (record_type == 0x16 and 
                   version >= 0x0301 and 
                   handshake_type == 0x01)
                   
        except (struct.error, IndexError):
            return False
    
    def _find_sni_extension_position(self, packet: bytes) -> Optional[int]:
        """
        Parse TLS Client Hello to find SNI extension position.
        
        Args:
            packet: TLS Client Hello packet bytes
            
        Returns:
            Position of SNI extension (type 0x0000), or None if not found
        """
        try:
            # Skip TLS record header (5 bytes)
            offset = 5
            
            if len(packet) < offset + 4:
                return None
            
            # Skip handshake header (4 bytes: type + length)
            offset += 4
            
            # Skip Client Hello version (2 bytes)
            offset += 2
            
            # Skip random (32 bytes)
            offset += 32
            
            if len(packet) < offset + 1:
                return None
            
            # Skip session ID
            session_id_length = packet[offset]
            offset += 1 + session_id_length
            
            if len(packet) < offset + 2:
                return None
            
            # Skip cipher suites
            cipher_suites_length = struct.unpack('>H', packet[offset:offset+2])[0]
            offset += 2 + cipher_suites_length
            
            if len(packet) < offset + 1:
                return None
            
            # Skip compression methods
            compression_methods_length = packet[offset]
            offset += 1 + compression_methods_length
            
            if len(packet) < offset + 2:
                return None
            
            # Extensions length
            extensions_length = struct.unpack('>H', packet[offset:offset+2])[0]
            offset += 2
            
            # Parse extensions to find SNI (type 0x0000)
            extensions_end = offset + extensions_length
            
            while offset < extensions_end and offset + 4 <= len(packet):
                extension_type = struct.unpack('>H', packet[offset:offset+2])[0]
                extension_length = struct.unpack('>H', packet[offset+2:offset+4])[0]
                
                # SNI extension type is 0x0000
                if extension_type == 0x0000:
                    return offset
                
                # Move to next extension
                offset += 4 + extension_length
            
            return None
            
        except (struct.error, IndexError) as e:
            self.logger.error(f"Error parsing TLS Client Hello: {e}")
            return None
    
    def resolve_positions(self, packet: bytes, config: SplitConfig) -> List[int]:
        """
        Resolve all split positions for a packet with priority handling.
        
        Args:
            packet: The packet bytes to analyze
            config: Split configuration with positions and priorities
            
        Returns:
            List of valid positions in priority order
        """
        all_positions = []
        
        # Handle SNI position with highest priority for TLS packets
        if config.use_sni:
            sni_position = self.resolve_sni_position(packet)
            if sni_position is not None:
                all_positions.append(sni_position)
                self.logger.debug(f"SNI position {sni_position} added with highest priority")
        
        # Handle numeric positions
        if config.numeric_positions:
            numeric_positions = self.resolve_numeric_positions(packet, config.numeric_positions)
            all_positions.extend(numeric_positions)
            self.logger.debug(f"Numeric positions {numeric_positions} added")
        
        # Remove duplicates while preserving order
        unique_positions = []
        seen = set()
        for pos in all_positions:
            if pos not in seen:
                unique_positions.append(pos)
                seen.add(pos)
        
        # Apply fallback logic if no positions are available
        if not unique_positions:
            fallback_positions = self._get_fallback_positions(packet)
            if fallback_positions:
                self.logger.info(f"Using fallback positions: {fallback_positions}")
                unique_positions = fallback_positions
        
        self.logger.debug(f"Final resolved positions: {unique_positions}")
        return unique_positions
    
    def _get_fallback_positions(self, packet: bytes) -> List[int]:
        """
        Get fallback positions when preferred positions are not available.
        
        Args:
            packet: The packet bytes to analyze
            
        Returns:
            List of fallback positions
        """
        packet_size = len(packet)
        fallback_positions = []
        
        # Try common fallback positions
        common_positions = [3, 10, packet_size // 2]
        
        for position in common_positions:
            if self.validate_position(packet, position):
                fallback_positions.append(position)
        
        return fallback_positions