#!/usr/bin/env python3
"""
SegmentPacketBuilder for segments orchestration.

Specialized packet builder for creating packets from segment tuples
with precise control over TCP headers, timing, and options.
"""

import struct
import socket
import logging
import time
from typing import Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass

from core.packet_builder import PacketBuilder
from .base import AttackContext, SegmentTuple


@dataclass
class SegmentPacketInfo:
    """Information about a constructed segment packet."""
    
    packet_bytes: bytes
    packet_size: int
    construction_time_ms: float
    tcp_seq: int
    tcp_ack: int
    tcp_flags: int
    tcp_window: int
    ttl: int
    checksum_corrupted: bool
    options_applied: Dict[str, Any]


class SegmentPacketBuilder:
    """
    Specialized packet builder for segment construction.
    
    Uses EnhancedPacketBuilder for raw packet creation with precise
    control over every header field for segments orchestration.
    """
    
    def __init__(self, enhanced_builder: Optional[PacketBuilder] = None):
        """
        Initialize segment packet builder.
        
        Args:
            enhanced_builder: PacketBuilder instance to use
        """
        self.builder = enhanced_builder or PacketBuilder(use_scapy=False)
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            "packets_built": 0,
            "total_build_time_ms": 0.0,
            "checksum_corruptions": 0,
            "ttl_modifications": 0,
            "flag_modifications": 0
        }
    
    def build_segment(
        self, 
        payload: bytes, 
        seq_offset: int, 
        options: Dict[str, Any], 
        context: AttackContext
    ) -> SegmentPacketInfo:
        """
        Build packet bytes for a segment.
        
        Args:
            payload: Raw bytes to send
            seq_offset: TCP sequence offset from context
            options: Segment options dict
            context: Attack context with TCP session info
            
        Returns:
            SegmentPacketInfo with constructed packet and metadata
        """
        start_time = time.time()
        
        try:
            # Calculate TCP parameters
            tcp_seq = context.tcp_seq + seq_offset
            tcp_ack = context.tcp_ack
            tcp_flags = options.get("flags", context.tcp_flags)
            tcp_window = options.get("window_size", context.tcp_window_size)
            ttl = options.get("ttl", 64)
            bad_checksum = options.get("bad_checksum", False)
            
            # Get source IP (use context or detect)
            src_ip = context.src_ip or self._get_source_ip(context.dst_ip)
            src_port = context.src_port or self._get_source_port()
            
            # Build packet using raw construction for maximum control
            packet_bytes = self._build_raw_tcp_packet(
                src_ip=src_ip,
                dst_ip=context.dst_ip,
                src_port=src_port,
                dst_port=context.dst_port,
                seq=tcp_seq,
                ack=tcp_ack,
                flags=tcp_flags,
                window=tcp_window,
                ttl=ttl,
                payload=payload,
                corrupt_checksum=bad_checksum,
                tcp_options=context.tcp_options
            )
            
            # Update statistics
            construction_time = (time.time() - start_time) * 1000
            self.stats["packets_built"] += 1
            self.stats["total_build_time_ms"] += construction_time
            
            if bad_checksum:
                self.stats["checksum_corruptions"] += 1
            if ttl != 64:
                self.stats["ttl_modifications"] += 1
            if tcp_flags != context.tcp_flags:
                self.stats["flag_modifications"] += 1
            
            return SegmentPacketInfo(
                packet_bytes=packet_bytes,
                packet_size=len(packet_bytes),
                construction_time_ms=construction_time,
                tcp_seq=tcp_seq,
                tcp_ack=tcp_ack,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
                ttl=ttl,
                checksum_corrupted=bad_checksum,
                options_applied=options.copy()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to build segment packet: {e}")
            raise SegmentPacketBuildError(f"Packet construction failed: {e}") from e
    
    def _build_raw_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        ttl: int,
        payload: bytes,
        corrupt_checksum: bool = False,
        tcp_options: bytes = b""
    ) -> bytes:
        """
        Build raw TCP packet with complete control over headers.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            seq: TCP sequence number
            ack: TCP acknowledgment number
            flags: TCP flags
            window: TCP window size
            ttl: IP TTL value
            payload: Packet payload
            corrupt_checksum: Whether to corrupt TCP checksum
            tcp_options: TCP options bytes
            
        Returns:
            Raw packet bytes
        """
        # Convert IP addresses to bytes
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        
        # Build TCP header
        tcp_header = self._build_tcp_header(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            tcp_options=tcp_options
        )
        
        # Calculate TCP checksum
        if corrupt_checksum:
            # Use invalid checksum
            tcp_checksum = 0xDEAD  # Obviously wrong checksum
        else:
            tcp_checksum = self.builder.build_tcp_checksum(
                src_ip_bytes, dst_ip_bytes, tcp_header, payload
            )
        
        # Insert checksum into TCP header
        tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]
        
        # Build IP header
        ip_header = self._build_ip_header(
            src_ip_bytes=src_ip_bytes,
            dst_ip_bytes=dst_ip_bytes,
            total_length=20 + len(tcp_header) + len(payload),
            ttl=ttl
        )
        
        # Combine all parts
        return ip_header + tcp_header + payload
    
    def _build_tcp_header(
        self,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        tcp_options: bytes = b""
    ) -> bytes:
        """
        Build TCP header with precise control.
        
        Args:
            src_port: Source port
            dst_port: Destination port
            seq: Sequence number
            ack: Acknowledgment number
            flags: TCP flags
            window: Window size
            tcp_options: TCP options
            
        Returns:
            TCP header bytes
        """
        # Calculate header length (including options)
        options_padded = tcp_options
        if len(options_padded) % 4 != 0:
            # Pad options to 4-byte boundary
            padding = 4 - (len(options_padded) % 4)
            options_padded += b'\x00' * padding
        
        header_length = (20 + len(options_padded)) // 4  # In 32-bit words
        
        # Build TCP header (without checksum initially)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,           # Source port
            dst_port,           # Destination port
            seq,                # Sequence number
            ack,                # Acknowledgment number
            (header_length << 4), # Header length + reserved
            flags,              # Flags
            window,             # Window size
            0,                  # Checksum (will be filled later)
            0                   # Urgent pointer
        )
        
        # Add options if present
        tcp_header += options_padded
        
        return tcp_header
    
    def _build_ip_header(
        self,
        src_ip_bytes: bytes,
        dst_ip_bytes: bytes,
        total_length: int,
        ttl: int
    ) -> bytes:
        """
        Build IP header with precise control.
        
        Args:
            src_ip_bytes: Source IP as bytes
            dst_ip_bytes: Destination IP as bytes
            total_length: Total packet length
            ttl: Time To Live value
            
        Returns:
            IP header bytes
        """
        # Build IP header (without checksum initially)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,               # Version (4) + Header Length (5)
            0,                  # Type of Service
            total_length,       # Total Length
            0,                  # Identification
            0,                  # Flags + Fragment Offset
            ttl,                # TTL
            6,                  # Protocol (TCP)
            0,                  # Header Checksum (will be calculated)
            src_ip_bytes,       # Source IP
            dst_ip_bytes        # Destination IP
        )
        
        # Calculate IP header checksum
        ip_checksum = self.builder.calculate_checksum(ip_header)
        
        # Insert checksum into header
        ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
        
        return ip_header
    
    def _get_source_ip(self, dst_ip: str) -> str:
        """
        Get appropriate source IP for destination.
        
        Args:
            dst_ip: Destination IP address
            
        Returns:
            Source IP address
        """
        try:
            # Create a socket to determine source IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((dst_ip, 80))
                return s.getsockname()[0]
        except Exception:
            # Fallback to localhost
            return "127.0.0.1"
    
    def _get_source_port(self) -> int:
        """
        Get random source port in ephemeral range.
        
        Returns:
            Random source port
        """
        import random
        return random.randint(49152, 65535)
    
    def validate_segment_options(self, options: Dict[str, Any]) -> bool:
        """
        Validate segment options.
        
        Args:
            options: Segment options dictionary
            
        Returns:
            True if options are valid, False otherwise
        """
        try:
            # Check TTL
            if "ttl" in options:
                ttl = options["ttl"]
                if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                    return False
            
            # Check flags
            if "flags" in options:
                flags = options["flags"]
                if not isinstance(flags, int) or flags < 0 or flags > 255:
                    return False
            
            # Check window size
            if "window_size" in options:
                window = options["window_size"]
                if not isinstance(window, int) or window < 0 or window > 65535:
                    return False
            
            # Check delay
            if "delay_ms" in options:
                delay = options["delay_ms"]
                if not isinstance(delay, (int, float)) or delay < 0:
                    return False
            
            # Check bad_checksum
            if "bad_checksum" in options:
                bad_checksum = options["bad_checksum"]
                if not isinstance(bad_checksum, bool):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get packet builder statistics.
        
        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        
        if stats["packets_built"] > 0:
            stats["avg_build_time_ms"] = stats["total_build_time_ms"] / stats["packets_built"]
        else:
            stats["avg_build_time_ms"] = 0.0
        
        return stats
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "packets_built": 0,
            "total_build_time_ms": 0.0,
            "checksum_corruptions": 0,
            "ttl_modifications": 0,
            "flag_modifications": 0
        }


class SegmentPacketBuildError(Exception):
    """Exception raised when segment packet building fails."""
    pass


# Convenience functions for common segment packet operations

def build_segment_packet(
    segment: SegmentTuple,
    context: AttackContext,
    builder: Optional[SegmentPacketBuilder] = None
) -> SegmentPacketInfo:
    """
    Build packet for a single segment.
    
    Args:
        segment: Segment tuple (payload_data, seq_offset, options_dict)
        context: Attack context
        builder: Optional SegmentPacketBuilder instance
        
    Returns:
        SegmentPacketInfo with constructed packet
    """
    if builder is None:
        builder = SegmentPacketBuilder()
    
    payload_data, seq_offset, options_dict = segment
    return builder.build_segment(payload_data, seq_offset, options_dict, context)


def build_segments_batch(
    segments: list[SegmentTuple],
    context: AttackContext,
    builder: Optional[SegmentPacketBuilder] = None
) -> list[SegmentPacketInfo]:
    """
    Build packets for multiple segments efficiently.
    
    Args:
        segments: List of segment tuples
        context: Attack context
        builder: Optional SegmentPacketBuilder instance
        
    Returns:
        List of SegmentPacketInfo objects
    """
    if builder is None:
        builder = SegmentPacketBuilder()
    
    results = []
    for segment in segments:
        packet_info = build_segment_packet(segment, context, builder)
        results.append(packet_info)
    
    return results


def validate_segments_for_building(
    segments: list[SegmentTuple],
    context: AttackContext
) -> Tuple[bool, Optional[str]]:
    """
    Validate segments before building packets.
    
    Args:
        segments: List of segment tuples to validate
        context: Attack context
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        builder = SegmentPacketBuilder()
        
        for i, segment in enumerate(segments):
            if len(segment) != 3:
                return False, f"Segment {i} has invalid format"
            
            payload_data, seq_offset, options_dict = segment
            
            if not isinstance(payload_data, bytes):
                return False, f"Segment {i} payload_data must be bytes"
            
            if not isinstance(seq_offset, int):
                return False, f"Segment {i} seq_offset must be int"
            
            if not isinstance(options_dict, dict):
                return False, f"Segment {i} options_dict must be dict"
            
            if not builder.validate_segment_options(options_dict):
                return False, f"Segment {i} has invalid options"
        
        if not context.validate_tcp_session():
            return False, "Invalid TCP session in context"
        
        return True, None
        
    except Exception as e:
        return False, f"Validation error: {e}"