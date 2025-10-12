"""
SegmentPacketBuilder for segments orchestration.

Specialized packet builder for creating packets from segment tuples
with precise control over TCP headers, timing, and options.
"""

import struct
import socket
import logging
import time
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from core.packet_builder import PacketBuilder
from core.bypass.attacks.base import AttackContext, SegmentTuple


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
        self.stats = {
            "packets_built": 0,
            "total_build_time_ms": 0.0,
            "checksum_corruptions": 0,
            "ttl_modifications": 0,
            "flag_modifications": 0,
        }

    def build_segment(
        self,
        payload: bytes,
        seq_offset: int,
        options: Dict[str, Any],
        context: AttackContext,
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
            tcp_seq = context.tcp_seq + seq_offset
            tcp_ack = context.tcp_ack
            # Совместимость ключей флагов
            tcp_flags = options.get("tcp_flags", options.get("flags", context.tcp_flags))
            tcp_window = options.get("window_size", context.tcp_window_size)
            ttl = options.get("ttl", 64)
            # Синонимы badsum
            bad_checksum = options.get("bad_checksum", options.get("corrupt_tcp_checksum", False))
            src_ip = context.src_ip or self._get_source_ip(context.dst_ip)
            src_port = context.src_port or self._get_source_port()
            # seq_extra для badseq
            seq_extra = int(options.get("seq_extra", -1 if options.get("corrupt_sequence") else 0))
            packet_bytes = self._build_raw_tcp_packet(
                src_ip=src_ip,
                dst_ip=context.dst_ip,
                src_port=src_port,
                dst_port=context.dst_port,
                seq=tcp_seq + seq_extra,
                ack=tcp_ack,
                flags=tcp_flags,
                window=tcp_window,
                ttl=ttl,
                payload=payload,
                corrupt_checksum=bad_checksum,
                tcp_options=self._merge_tcp_options(context.tcp_options, options),
                raw_packet=context.raw_packet,
            )
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
                options_applied=options.copy(),
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
        tcp_options: bytes = b"",
        raw_packet: Optional[bytes] = None,
    ) -> bytes:
        """
        Build raw TCP packet with complete control over headers.
        """
        tcp_hdr = self._build_tcp_header(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            tcp_options=tcp_options,
        )

        ip_hl = (raw_packet[0] & 0x0F) * 4 if raw_packet else 20

        # Build IP header from scratch
        total_len = ip_hl + len(tcp_hdr) + len(payload)

        raw = bytearray(raw_packet) if raw_packet else bytearray(ip_hl)
        if not raw_packet:
            raw[0] = (4 << 4) | 5
            raw[9] = 6 # TCP
            raw[12:16] = socket.inet_aton(src_ip)
            raw[16:20] = socket.inet_aton(dst_ip)

        ip_hdr = self._build_ip_header(raw, ip_hl, total_len, ttl, None)

        # Assemble packet
        seg_raw = bytearray(ip_hdr + tcp_hdr + payload)

        # Final IP checksum calculation (single pass)
        seg_raw[10:12] = b"\x00\x00"
        ip_csum = self.builder.calculate_checksum(seg_raw[:ip_hl])
        seg_raw[10:12] = struct.pack("!H", ip_csum)
        self.logger.debug(f"✅ IP checksum set: 0x{ip_csum:04X}")

        # TCP checksum calculation
        tcp_start = ip_hl
        tcp_end = ip_hl + len(tcp_hdr)
        # Zero CSUM field before calculation
        seg_raw[tcp_start+16:tcp_start+18] = b"\x00\x00"
        good_csum = self.builder.build_tcp_checksum(
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
            seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:]
        )

        if corrupt_checksum:
            bad_csum = 0xBEEF if b"\x13\x12" in tcp_options else 0xDEAD
            seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
        else:
            seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", good_csum)
            self.logger.debug(f"✅ TCP checksum set: 0x{good_csum:04X}")

        return bytes(seg_raw)

    def _build_tcp_header(
        self,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
        tcp_options: bytes = b"",
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
        options_padded = tcp_options
        if len(options_padded) % 4 != 0:
            padding = 4 - len(options_padded) % 4
            options_padded += b"\x01" * padding  # NOP padding
        header_length = (20 + len(options_padded)) // 4
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            header_length << 4,
            flags,
            window,
            0,
            0,
        )
        tcp_header += options_padded
        return tcp_header

    def _merge_tcp_options(self, base_opts: bytes, options: Dict[str, Any]) -> bytes:
        """
        Добавить MD5SIG (kind=19,len=18) при необходимости к base_opts с выравниванием.
        """
        out = base_opts or b""
        if options.get("add_md5sig_option"):
            md5opt = b"\x13\x12" + b"\x00" * 16
            out = out + md5opt
            if len(out) % 4 != 0:
                out += b"\x01" * (4 - len(out) % 4)  # NOP padding
        return out

    def _build_ip_header(self, raw: bytearray, ip_hl: int, total_len: int,
                           ttl: int, ip_id: Optional[int]) -> bytearray:
        """
        Builds a new IPv4 header from scratch, preserving key fields
        from the original header.
        """
        vihl = raw[0]
        version = (vihl >> 4) & 0x0F
        ihl = vihl & 0x0F
        if version != 4 or ihl < 5:
            raise ValueError(f"Unsupported IP header: version={version}, ihl={ihl}")

        tos = raw[1]
        if ip_id is None:
            ip_id_val = struct.unpack("!H", raw[4:6])[0]
        else:
            ip_id_val = int(ip_id) & 0xFFFF

        flags_frag = struct.unpack("!H", raw[6:8])[0]
        proto = raw[9]
        src = raw[12:16]
        dst = raw[16:20]

        ip_hdr = bytearray(ihl * 4)
        ip_hdr[0] = (4 << 4) | ihl            # Version/IHL
        ip_hdr[1] = tos                       # DSCP/ECN
        ip_hdr[2:4] = struct.pack("!H", total_len)
        ip_hdr[4:6] = struct.pack("!H", ip_id_val)
        ip_hdr[6:8] = struct.pack("!H", flags_frag)
        ip_hdr[8] = ttl & 0xFF
        ip_hdr[9] = proto
        ip_hdr[10:12] = b"\x00\x00"
        ip_hdr[12:16] = src
        ip_hdr[16:20] = dst

        # Copy IP options if they exist
        if ihl > 5:
            ip_hdr[20:ihl*4] = raw[20:ihl*4]

        return ip_hdr

    def _get_source_ip(self, dst_ip: str) -> str:
        """
        Get appropriate source IP for destination.

        Args:
            dst_ip: Destination IP address

        Returns:
            Source IP address
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((dst_ip, 80))
                return s.getsockname()[0]
        except Exception:
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
            if "ttl" in options:
                ttl = options["ttl"]
                if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                    return False
            if "flags" in options:
                flags = options["flags"]
                if not isinstance(flags, int) or flags < 0 or flags > 255:
                    return False
            if "window_size" in options:
                window = options["window_size"]
                if not isinstance(window, int) or window < 0 or window > 65535:
                    return False
            if "delay_ms" in options:
                delay = options["delay_ms"]
                if not isinstance(delay, (int, float)) or delay < 0:
                    return False
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
            stats["avg_build_time_ms"] = (
                stats["total_build_time_ms"] / stats["packets_built"]
            )
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
            "flag_modifications": 0,
        }


class SegmentPacketBuildError(Exception):
    """Exception raised when segment packet building fails."""

    pass


def build_segment_packet(
    segment: SegmentTuple,
    context: AttackContext,
    builder: Optional[SegmentPacketBuilder] = None,
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
    builder: Optional[SegmentPacketBuilder] = None,
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
    segments: list[SegmentTuple], context: AttackContext
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
                return (False, f"Segment {i} has invalid format")
            payload_data, seq_offset, options_dict = segment
            if not isinstance(payload_data, bytes):
                return (False, f"Segment {i} payload_data must be bytes")
            if not isinstance(seq_offset, int):
                return (False, f"Segment {i} seq_offset must be int")
            if not isinstance(options_dict, dict):
                return (False, f"Segment {i} options_dict must be dict")
            if not builder.validate_segment_options(options_dict):
                return (False, f"Segment {i} has invalid options")
        if not context.validate_tcp_session():
            return (False, "Invalid TCP session in context")
        return (True, None)
    except Exception as e:
        return (False, f"Validation error: {e}")
