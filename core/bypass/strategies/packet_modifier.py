"""
Packet modification component for DPI strategy system.

This module implements packet splitting, TCP segment creation, and sequence number management
for DPI bypass strategies.
"""

import struct
import socket
from typing import List, Optional, Tuple, Dict, Any
import logging

from .interfaces import IPacketModifier
from .config_models import PacketSplitResult, TCPPacketInfo
from .exceptions import (
    InvalidSplitPositionError,
    PacketTooSmallError,
    PacketProcessingError,
    ChecksumCalculationError
)

logger = logging.getLogger(__name__)


class PacketModifier(IPacketModifier):
    """
    Implementation of packet modification operations.
    
    This class handles packet splitting, TCP segment creation, and sequence number management
    for DPI bypass strategies.
    """
    
    def __init__(self):
        """Initialize the packet modifier."""
        self.min_packet_size = 20  # Minimum size for IP header
        self.min_tcp_header_size = 20  # Minimum TCP header size
        self.min_ip_header_size = 20   # Minimum IP header size
    
    def split_packet(self, packet: bytes, positions: List[int]) -> List[bytes]:
        """
        Split a packet at specified positions.
        
        Args:
            packet: The packet bytes to split
            positions: List of positions where to split (sorted)
            
        Returns:
            List of packet parts
            
        Raises:
            InvalidSplitPositionError: If any position is invalid
            PacketTooSmallError: If packet is too small to split
        """
        if not packet:
            raise PacketTooSmallError(0, self.min_packet_size, "packet splitting")
        
        if len(packet) < self.min_packet_size:
            raise PacketTooSmallError(len(packet), self.min_packet_size, "packet splitting")
        
        if not positions:
            # No split positions, return original packet
            return [packet]
        
        # Validate and sort positions
        validated_positions = self._validate_split_positions(packet, positions)
        
        if not validated_positions:
            # No valid positions, return original packet
            logger.debug(f"No valid split positions for packet of size {len(packet)}")
            return [packet]
        
        # Sort positions to ensure correct splitting order
        sorted_positions = sorted(validated_positions)
        
        # Split the packet at the specified positions
        parts = []
        start_pos = 0
        
        for position in sorted_positions:
            if position > start_pos:
                # Create part from start_pos to position
                part = packet[start_pos:position]
                if part:  # Only add non-empty parts
                    parts.append(part)
                start_pos = position
        
        # Add the remaining part
        if start_pos < len(packet):
            remaining_part = packet[start_pos:]
            if remaining_part:  # Only add non-empty parts
                parts.append(remaining_part)
        
        # Ensure we have at least one part
        if not parts:
            logger.warning(f"Split operation resulted in no parts, returning original packet")
            return [packet]
        
        # Validate split result
        self._validate_split_result(packet, parts, sorted_positions)
        
        logger.debug(f"Split packet of size {len(packet)} into {len(parts)} parts at positions {sorted_positions}")
        return parts
    
    def _validate_split_positions(self, packet: bytes, positions: List[int]) -> List[int]:
        """
        Validate split positions and return only valid ones.
        
        Args:
            packet: The packet to be split
            positions: List of positions to validate
            
        Returns:
            List of valid positions
        """
        valid_positions = []
        packet_size = len(packet)
        
        for position in positions:
            try:
                if self._is_position_valid(packet_size, position):
                    valid_positions.append(position)
                else:
                    logger.debug(f"Invalid split position {position} for packet size {packet_size}")
            except Exception as e:
                logger.warning(f"Error validating position {position}: {e}")
        
        return valid_positions
    
    def _is_position_valid(self, packet_size: int, position: int) -> bool:
        """
        Check if a split position is valid.
        
        Args:
            packet_size: Size of the packet
            position: Position to validate
            
        Returns:
            True if position is valid
        """
        # Position must be positive
        if position <= 0:
            return False
        
        # Position must be less than packet size (can't split at the end)
        if position >= packet_size:
            return False
        
        # Position should leave at least 1 byte in each part
        if position >= packet_size - 1:
            return False
        
        return True
    
    def _validate_split_result(self, original_packet: bytes, parts: List[bytes], positions: List[int]):
        """
        Validate that split result is correct.
        
        Args:
            original_packet: The original packet
            parts: List of split parts
            positions: Positions where packet was split
            
        Raises:
            PacketProcessingError: If validation fails
        """
        # Check that parts can be reconstructed into original packet
        reconstructed = b''.join(parts)
        if reconstructed != original_packet:
            raise PacketProcessingError(
                len(original_packet), 
                "PacketModifier",
                f"Split parts do not reconstruct original packet. "
                f"Original: {len(original_packet)} bytes, Reconstructed: {len(reconstructed)} bytes"
            )
        
        # Check that we have the expected number of parts
        expected_parts = len(positions) + 1
        if len(parts) != expected_parts:
            logger.warning(f"Expected {expected_parts} parts but got {len(parts)} parts")
        
        # Check that no part is empty
        for i, part in enumerate(parts):
            if not part:
                raise PacketProcessingError(
                    len(original_packet),
                    "PacketModifier", 
                    f"Split resulted in empty part at index {i}"
                )
    
    def create_tcp_segments(self, original_packet: bytes, parts: List[bytes]) -> List[bytes]:
        """
        Create TCP segments from packet parts.
        
        This method creates proper TCP packets from split payload parts,
        preserving the original IP and TCP headers while updating payload.
        
        Args:
            original_packet: The original packet for header information
            parts: List of packet parts to convert to TCP segments
            
        Returns:
            List of complete TCP packets
            
        Raises:
            PacketProcessingError: If TCP segment creation fails
        """
        if not parts:
            logger.warning("No parts provided for TCP segment creation")
            return [original_packet]
        
        if len(parts) == 1:
            # Single part, return as-is
            logger.debug("Single part provided, returning original packet")
            return [original_packet]
        
        try:
            # Parse original packet to extract headers
            ip_header, tcp_header, original_payload = self._parse_packet_headers(original_packet)
            
            if not ip_header or not tcp_header:
                logger.warning("Could not parse original packet headers, returning parts as-is")
                return parts
            
            tcp_segments = []
            
            for i, part in enumerate(parts):
                # Create new packet with original headers and new payload
                new_packet = self._create_tcp_packet(ip_header, tcp_header, part, i)
                tcp_segments.append(new_packet)
                logger.debug(f"Created TCP segment {i+1}/{len(parts)} with payload size {len(part)}")
            
            logger.debug(f"Successfully created {len(tcp_segments)} TCP segments")
            return tcp_segments
            
        except Exception as e:
            logger.error(f"Failed to create TCP segments: {e}")
            raise PacketProcessingError(
                len(original_packet),
                "create_tcp_segments",
                f"TCP segment creation failed: {e}"
            )
    
    def _parse_packet_headers(self, packet: bytes) -> Tuple[Optional[bytes], Optional[bytes], bytes]:
        """
        Parse IP and TCP headers from packet.
        
        Args:
            packet: Complete packet bytes
            
        Returns:
            Tuple of (ip_header, tcp_header, payload)
        """
        try:
            if len(packet) < self.min_ip_header_size:
                logger.debug(f"Packet too small for IP header: {len(packet)} bytes")
                return None, None, packet
            
            # Parse IP header (simplified - assumes IPv4)
            ip_header_len = (packet[0] & 0x0F) * 4
            if ip_header_len < self.min_ip_header_size or len(packet) < ip_header_len:
                logger.debug(f"Invalid IP header length: {ip_header_len}")
                return None, None, packet
            
            ip_header = packet[:ip_header_len]
            
            # Check if this is TCP (protocol 6)
            if len(packet) < 10 or packet[9] != 6:
                logger.debug("Not a TCP packet")
                return ip_header, None, packet[ip_header_len:]
            
            # Parse TCP header
            tcp_start = ip_header_len
            if len(packet) < tcp_start + self.min_tcp_header_size:
                logger.debug(f"Packet too small for TCP header")
                return ip_header, None, packet[tcp_start:]
            
            tcp_header_len = ((packet[tcp_start + 12] & 0xF0) >> 4) * 4
            if tcp_header_len < self.min_tcp_header_size:
                logger.debug(f"Invalid TCP header length: {tcp_header_len}")
                return ip_header, None, packet[tcp_start:]
            
            tcp_end = tcp_start + tcp_header_len
            if len(packet) < tcp_end:
                logger.debug("Packet too small for complete TCP header")
                return ip_header, None, packet[tcp_start:]
            
            tcp_header = packet[tcp_start:tcp_end]
            payload = packet[tcp_end:]
            
            logger.debug(f"Parsed headers: IP={len(ip_header)}, TCP={len(tcp_header)}, payload={len(payload)}")
            return ip_header, tcp_header, payload
            
        except Exception as e:
            logger.error(f"Error parsing packet headers: {e}")
            return None, None, packet
    
    def _create_tcp_packet(self, ip_header: bytes, tcp_header: bytes, payload: bytes, segment_index: int) -> bytes:
        """
        Create a TCP packet with given headers and payload.
        
        Args:
            ip_header: Original IP header
            tcp_header: Original TCP header  
            payload: New payload for this segment
            segment_index: Index of this segment (for identification)
            
        Returns:
            Complete TCP packet bytes
        """
        try:
            # Create mutable copies of headers
            new_ip_header = bytearray(ip_header)
            new_tcp_header = bytearray(tcp_header)
            
            # Update IP total length
            new_total_length = len(ip_header) + len(tcp_header) + len(payload)
            new_ip_header[2:4] = struct.pack('!H', new_total_length)
            
            # Clear IP checksum (will be recalculated by network stack)
            new_ip_header[10:12] = b'\x00\x00'
            
            # Clear TCP checksum (will be handled by checksum fooler if needed)
            new_tcp_header[16:18] = b'\x00\x00'
            
            # Combine headers and payload
            new_packet = bytes(new_ip_header) + bytes(new_tcp_header) + payload
            
            logger.debug(f"Created TCP packet: total_len={len(new_packet)}, payload_len={len(payload)}")
            return new_packet
            
        except Exception as e:
            logger.error(f"Error creating TCP packet: {e}")
            # Fallback: return headers + payload without modifications
            return ip_header + tcp_header + payload
    
    def update_sequence_numbers(self, packets: List[bytes]) -> List[bytes]:
        """
        Update sequence numbers for split packets.
        
        This method ensures proper TCP sequence number continuity across
        split packet segments to maintain valid TCP stream.
        
        Args:
            packets: List of TCP packets to update
            
        Returns:
            List of packets with updated sequence numbers
            
        Raises:
            PacketProcessingError: If sequence number update fails
        """
        if not packets:
            logger.debug("No packets provided for sequence number update")
            return []
        
        if len(packets) == 1:
            logger.debug("Single packet, no sequence number update needed")
            return packets
        
        try:
            updated_packets = []
            current_seq_offset = 0
            
            for i, packet in enumerate(packets):
                # Parse TCP header to get current sequence number
                seq_info = self._extract_tcp_sequence_info(packet)
                if not seq_info:
                    logger.warning(f"Could not extract TCP sequence info from packet {i}, using as-is")
                    updated_packets.append(packet)
                    continue
                
                # Calculate new sequence number for this segment
                if i == 0:
                    # First packet keeps original sequence number
                    new_seq = seq_info['seq_num']
                    logger.debug(f"Packet {i}: keeping original seq={new_seq}")
                else:
                    # Subsequent packets get incremented sequence numbers
                    new_seq = seq_info['original_seq'] + current_seq_offset
                    logger.debug(f"Packet {i}: updating seq from {seq_info['seq_num']} to {new_seq}")
                
                # Update packet with new sequence number
                updated_packet = self._update_tcp_sequence_number(packet, new_seq)
                updated_packets.append(updated_packet)
                
                # Update offset for next packet (based on payload size)
                payload_size = self._get_tcp_payload_size(packet)
                current_seq_offset += payload_size
                logger.debug(f"Packet {i}: payload_size={payload_size}, next_offset={current_seq_offset}")
            
            logger.debug(f"Successfully updated sequence numbers for {len(updated_packets)} packets")
            return updated_packets
            
        except Exception as e:
            logger.error(f"Failed to update sequence numbers: {e}")
            raise PacketProcessingError(
                len(packets),
                "update_sequence_numbers", 
                f"Sequence number update failed: {e}"
            )
    
    def _extract_tcp_sequence_info(self, packet: bytes) -> Optional[Dict[str, int]]:
        """
        Extract TCP sequence number information from packet.
        
        Args:
            packet: TCP packet bytes
            
        Returns:
            Dictionary with sequence info or None if extraction fails
        """
        try:
            # Find TCP header start
            if len(packet) < self.min_ip_header_size:
                return None
            
            ip_header_len = (packet[0] & 0x0F) * 4
            tcp_start = ip_header_len
            
            if len(packet) < tcp_start + 8:  # Need at least 8 bytes for seq number
                return None
            
            # Extract sequence number (bytes 4-7 of TCP header)
            seq_bytes = packet[tcp_start + 4:tcp_start + 8]
            seq_num = struct.unpack('!I', seq_bytes)[0]
            
            return {
                'seq_num': seq_num,
                'original_seq': seq_num,  # Store original for offset calculation
                'tcp_start': tcp_start
            }
            
        except Exception as e:
            logger.debug(f"Error extracting TCP sequence info: {e}")
            return None
    
    def _update_tcp_sequence_number(self, packet: bytes, new_seq: int) -> bytes:
        """
        Update TCP sequence number in packet.
        
        Args:
            packet: Original packet bytes
            new_seq: New sequence number
            
        Returns:
            Packet with updated sequence number
        """
        try:
            # Create mutable copy
            new_packet = bytearray(packet)
            
            # Find TCP header start
            ip_header_len = (packet[0] & 0x0F) * 4
            tcp_start = ip_header_len
            
            if len(new_packet) < tcp_start + 8:
                logger.warning("Packet too small for sequence number update")
                return packet
            
            # Update sequence number (bytes 4-7 of TCP header)
            new_seq_bytes = struct.pack('!I', new_seq)
            new_packet[tcp_start + 4:tcp_start + 8] = new_seq_bytes
            
            # Clear TCP checksum - will be recalculated by network stack or checksum fooler
            new_packet[tcp_start + 16:tcp_start + 18] = b'\x00\x00'
            
            logger.debug(f"Updated TCP sequence number to {new_seq}")
            return bytes(new_packet)
            
        except Exception as e:
            logger.error(f"Error updating TCP sequence number: {e}")
            return packet
    
    def _get_tcp_payload_size(self, packet: bytes) -> int:
        """
        Get TCP payload size from packet.
        
        Args:
            packet: TCP packet bytes
            
        Returns:
            Size of TCP payload in bytes
        """
        try:
            if len(packet) < self.min_ip_header_size:
                return 0
            
            # Get IP total length
            ip_total_len = struct.unpack('!H', packet[2:4])[0]
            
            # Get IP header length
            ip_header_len = (packet[0] & 0x0F) * 4
            
            # Get TCP header length
            tcp_start = ip_header_len
            if len(packet) < tcp_start + 13:
                return 0
            
            tcp_header_len = ((packet[tcp_start + 12] & 0xF0) >> 4) * 4
            
            # Calculate payload size
            headers_size = ip_header_len + tcp_header_len
            payload_size = ip_total_len - headers_size
            
            # Ensure non-negative
            payload_size = max(0, payload_size)
            
            logger.debug(f"TCP payload size: {payload_size} bytes")
            return payload_size
            
        except Exception as e:
            logger.debug(f"Error calculating TCP payload size: {e}")
            return 0
    
    def get_split_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about packet splitting operations.
        
        Returns:
            Dictionary with splitting statistics
        """
        # This could be extended to track actual statistics
        return {
            'min_packet_size': self.min_packet_size,
            'min_tcp_header_size': self.min_tcp_header_size,
            'min_ip_header_size': self.min_ip_header_size
        }
    
    def validate_packet_structure(self, packet: bytes) -> bool:
        """
        Validate basic packet structure.
        
        Args:
            packet: Packet bytes to validate
            
        Returns:
            True if packet structure is valid
        """
        if not packet:
            return False
        
        if len(packet) < self.min_packet_size:
            return False
        
        # Basic validation - could be extended with more checks
        return True
