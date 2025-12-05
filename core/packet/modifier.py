"""
PacketModifier - Low-level packet modification operations.

This module implements the PacketModifier class for low-level TCP packet
modifications including TTL, TCP flags, and checksum corruption.

Requirements: 7.1, 7.2, 7.4
"""

import logging
import struct
from typing import Dict, Any, Optional

from .packet_models import RawPacket, IPHeader, TCPHeader

logger = logging.getLogger(__name__)


class PacketModifier:
    """
    Low-level packet modifier for DPI bypass attacks.
    
    This class is responsible for:
    1. Modifying IP TTL values
    2. Setting TCP flags
    3. Corrupting TCP checksums (badsum)
    4. Corrupting sequence numbers (badseq)
    5. Calculating correct TCP checksums
    
    Requirements:
    - 7.1: Create packets with incorrect TCP checksum (badsum)
    - 7.2: Create packets with incorrect sequence numbers (badseq)
    - 7.4: Set correct TCP flags according to parameters
    """
    
    def __init__(self):
        """Initialize PacketModifier."""
        self.logger = logger
        self.logger.debug("✅ PacketModifier initialized")
    
    def set_ttl(self, packet: RawPacket, ttl: int) -> RawPacket:
        """
        Set IP TTL (Time To Live) value.
        
        Used for fake attacks where packets should expire before reaching
        the destination server.
        
        Args:
            packet: RawPacket to modify
            ttl: TTL value (typically 1-10 for fake attacks)
            
        Returns:
            Modified RawPacket with new TTL
        """
        if not packet.ip_header:
            self.logger.warning("⚠️ Cannot set TTL: packet has no IP header")
            return packet
        
        old_ttl = packet.ip_header.ttl
        packet.ip_header.ttl = ttl
        
        self.logger.debug(f"🔧 Set TTL: {old_ttl} → {ttl}")
        
        return packet
    
    def set_tcp_flags(self, packet: RawPacket, flags: Dict[str, bool]) -> RawPacket:
        """
        Set TCP flags according to parameters.
        
        TCP flags control the connection state and behavior:
        - FIN: Finish connection
        - SYN: Synchronize sequence numbers
        - RST: Reset connection
        - PSH: Push data immediately
        - ACK: Acknowledgment
        - URG: Urgent pointer is valid
        
        Args:
            packet: RawPacket to modify
            flags: Dictionary of flag names to boolean values
                   e.g., {'PSH': True, 'ACK': True}
            
        Returns:
            Modified RawPacket with new TCP flags
        """
        if not packet.tcp_header:
            self.logger.warning("⚠️ Cannot set TCP flags: packet has no TCP header")
            return packet
        
        # Map flag names to bit values
        flag_map = {
            'FIN': TCPHeader.FIN,
            'SYN': TCPHeader.SYN,
            'RST': TCPHeader.RST,
            'PSH': TCPHeader.PSH,
            'ACK': TCPHeader.ACK,
            'URG': TCPHeader.URG,
            'ECE': TCPHeader.ECE,
            'CWR': TCPHeader.CWR,
        }
        
        # Build new flags value
        new_flags = 0
        for flag_name, flag_value in flags.items():
            if flag_value and flag_name in flag_map:
                new_flags |= flag_map[flag_name]
        
        old_flags = packet.tcp_header.flags
        packet.tcp_header.flags = new_flags
        
        self.logger.debug(
            f"🔧 Set TCP flags: 0x{old_flags:02x} → 0x{new_flags:02x} "
            f"({self._format_flags(new_flags)})"
        )
        
        return packet
    
    def corrupt_checksum(
        self,
        packet: RawPacket,
        method: str = 'badsum'
    ) -> RawPacket:
        """
        Corrupt TCP checksum for fooling DPI.
        
        DPI systems may validate checksums and reject invalid packets,
        but intermediate routers typically don't check checksums, allowing
        fake packets to fool DPI without reaching the destination.
        
        Args:
            packet: RawPacket to modify
            method: Corruption method ('badsum' or 'badseq')
            
        Returns:
            Modified RawPacket with corrupted checksum or sequence
        """
        if not packet.tcp_header:
            self.logger.warning("⚠️ Cannot corrupt checksum: packet has no TCP header")
            return packet
        
        if method == 'badsum':
            # Calculate correct checksum first
            correct_checksum = self.calculate_checksum(packet)
            # XOR with 0xFFFF to corrupt it
            corrupted_checksum = correct_checksum ^ 0xFFFF
            
            old_checksum = packet.tcp_header.checksum
            packet.tcp_header.checksum = corrupted_checksum
            
            self.logger.debug(
                f"🔧 Corrupted TCP checksum (badsum): "
                f"0x{old_checksum:04x} → 0x{corrupted_checksum:04x}"
            )
        elif method == 'badseq':
            # For badseq, corrupt the sequence number instead
            return self.corrupt_sequence(packet, method='offset')
        else:
            self.logger.warning(f"⚠️ Unknown checksum corruption method: {method}")
        
        return packet
    
    def corrupt_sequence(
        self,
        packet: RawPacket,
        method: str = 'offset'
    ) -> RawPacket:
        """
        Corrupt TCP sequence number for fooling DPI (badseq).
        
        This method modifies the TCP sequence number to make the packet
        invalid, causing it to be rejected by the destination server but
        potentially fooling DPI systems.
        
        Args:
            packet: RawPacket to modify
            method: Corruption method:
                - 'offset': Add large offset (0x10000000)
                - 'random': Set random sequence number
                - 'zero': Set sequence to 0
            
        Returns:
            Modified RawPacket with corrupted sequence number
        """
        if not packet.tcp_header:
            self.logger.warning("⚠️ Cannot corrupt sequence: packet has no TCP header")
            return packet
        
        old_seq = packet.tcp_header.sequence_number
        
        if method == 'offset':
            # Add large offset to sequence number
            corrupted_seq = (old_seq + 0x10000000) & 0xFFFFFFFF
        elif method == 'random':
            # Set random sequence number
            import random
            corrupted_seq = random.randint(1, 0xFFFFFFFF)
        elif method == 'zero':
            # Set sequence to 0
            corrupted_seq = 0
        else:
            self.logger.warning(f"⚠️ Unknown sequence corruption method: {method}")
            return packet
        
        packet.tcp_header.sequence_number = corrupted_seq
        
        self.logger.debug(
            f"🔧 Corrupted TCP sequence (badseq, method={method}): "
            f"{old_seq} → {corrupted_seq}"
        )
        
        return packet
    
    def calculate_checksum(self, packet: RawPacket) -> int:
        """
        Calculate correct TCP checksum.
        
        TCP checksum is calculated over:
        1. Pseudo-header (source IP, dest IP, protocol, TCP length)
        2. TCP header (with checksum field set to 0)
        3. TCP payload
        
        Args:
            packet: RawPacket to calculate checksum for
            
        Returns:
            Correct TCP checksum value (16-bit)
        """
        if not packet.tcp_header or not packet.ip_header:
            self.logger.warning("⚠️ Cannot calculate checksum: missing headers")
            return 0
        
        # Build pseudo-header
        pseudo_header = self._build_pseudo_header(packet)
        
        # Build TCP segment (header + payload)
        # Temporarily set checksum to 0
        old_checksum = packet.tcp_header.checksum
        packet.tcp_header.checksum = 0
        
        tcp_segment = packet.tcp_header.to_bytes() + packet.payload
        
        # Restore old checksum
        packet.tcp_header.checksum = old_checksum
        
        # Calculate checksum over pseudo-header + TCP segment
        checksum = self._calculate_internet_checksum(pseudo_header + tcp_segment)
        
        self.logger.debug(f"🔧 Calculated TCP checksum: 0x{checksum:04x}")
        
        return checksum
    
    def _build_pseudo_header(self, packet: RawPacket) -> bytes:
        """
        Build TCP pseudo-header for checksum calculation.
        
        Pseudo-header format:
        - Source IP (4 bytes)
        - Destination IP (4 bytes)
        - Zero (1 byte)
        - Protocol (1 byte, TCP = 6)
        - TCP length (2 bytes)
        
        Args:
            packet: RawPacket with IP and TCP headers
            
        Returns:
            Pseudo-header bytes
        """
        if not packet.ip_header or not packet.tcp_header:
            return b''
        
        # Convert IP addresses to integers
        src_ip = self._ip_to_int(packet.ip_header.source_ip)
        dst_ip = self._ip_to_int(packet.ip_header.destination_ip)
        
        # TCP length = TCP header + payload
        tcp_length = packet.tcp_header.header_length + len(packet.payload)
        
        # Build pseudo-header
        pseudo_header = struct.pack(
            '!IIBBH',
            src_ip,
            dst_ip,
            0,  # Zero
            6,  # Protocol (TCP)
            tcp_length
        )
        
        return pseudo_header
    
    def _calculate_internet_checksum(self, data: bytes) -> int:
        """
        Calculate Internet checksum (RFC 1071).
        
        Algorithm:
        1. Sum all 16-bit words
        2. Add carry bits to the sum
        3. Take one's complement
        
        Args:
            data: Data to calculate checksum for
            
        Returns:
            16-bit checksum
        """
        # Pad data to even length if needed
        if len(data) % 2 == 1:
            data += b'\x00'
        
        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def _ip_to_int(self, ip_str: str) -> int:
        """
        Convert IP address string to integer.
        
        Args:
            ip_str: IP address string (e.g., "192.168.1.1")
            
        Returns:
            IP address as 32-bit integer
        """
        parts = ip_str.split('.')
        return (
            (int(parts[0]) << 24) +
            (int(parts[1]) << 16) +
            (int(parts[2]) << 8) +
            int(parts[3])
        )
    
    def _format_flags(self, flags: int) -> str:
        """
        Format TCP flags as human-readable string.
        
        Args:
            flags: TCP flags value
            
        Returns:
            String representation (e.g., "PSH,ACK")
        """
        flag_names = []
        if flags & TCPHeader.FIN:
            flag_names.append('FIN')
        if flags & TCPHeader.SYN:
            flag_names.append('SYN')
        if flags & TCPHeader.RST:
            flag_names.append('RST')
        if flags & TCPHeader.PSH:
            flag_names.append('PSH')
        if flags & TCPHeader.ACK:
            flag_names.append('ACK')
        if flags & TCPHeader.URG:
            flag_names.append('URG')
        if flags & TCPHeader.ECE:
            flag_names.append('ECE')
        if flags & TCPHeader.CWR:
            flag_names.append('CWR')
        
        return ','.join(flag_names) if flag_names else 'NONE'
