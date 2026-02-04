"""Packet assembly and modification utilities."""

import struct
import random
import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.packet_builder import PacketParams

from core.packet_utils.checksum import ChecksumCache
from core.packet_utils.tcp_builder import TCPHeaderBuilder


class PacketAssembler:
    """Assembles and modifies TCP packets at byte level."""

    @staticmethod
    def assemble_tcp_packet(
        original_raw: bytes,
        new_payload: bytes = b"",
        new_seq: Optional[int] = None,
        new_flags: Optional[str] = None,
        new_ttl: Optional[int] = None,
        new_window: Optional[int] = None,
        new_options: bytes = b"",
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
    ) -> bytes:
        """
        Assemble TCP packet with modifications (legacy method for compatibility).
        If original_raw is empty, create a new packet from scratch.

        Args:
            original_raw: Original packet bytes
            new_payload: New payload to use
            new_seq: New sequence number
            new_flags: New TCP flags
            new_ttl: New TTL value
            new_window: New window size
            new_options: New TCP options
            src_ip: Source IP (for new packets)
            dst_ip: Destination IP (for new packets)
            src_port: Source port (for new packets)
            dst_port: Destination port (for new packets)

        Returns:
            Modified packet bytes
        """
        try:
            if not original_raw or len(original_raw) < 20:
                return PacketAssembler.create_minimal_tcp_packet(
                    src_ip or "127.0.0.1",
                    dst_ip or "127.0.0.1",
                    src_port or 12345,
                    dst_port or 80,
                    new_payload,
                    new_seq,
                    new_flags,
                )

            if (original_raw[0] >> 4) != 4:
                # This assembler currently supports IPv4 raw packets only.
                return original_raw + new_payload

            ip_header_len = (original_raw[0] & 15) * 4
            tcp_header_start = ip_header_len
            tcp_header_len = (original_raw[tcp_header_start + 12] >> 4 & 15) * 4

            ip_header = bytearray(original_raw[:ip_header_len])
            tcp_header = bytearray(
                original_raw[tcp_header_start : tcp_header_start + tcp_header_len]
            )

            # Apply TCP options replacement if provided.
            if new_options:
                opts = bytes(new_options)
                while len(opts) % 4 != 0:
                    opts += b"\x01"  # NOP padding
                base = bytearray(tcp_header[:20])
                tcp_header = base + bytearray(opts)
                tcp_header_len = len(tcp_header)
                data_offset = (tcp_header_len // 4) & 0x0F
                tcp_header[12] = (data_offset << 4) | (tcp_header[12] & 0x0F)

            if new_seq is not None:
                struct.pack_into("!I", tcp_header, 4, new_seq)

            if new_flags is not None:
                flags_byte = TCPHeaderBuilder.flags_to_byte(new_flags)
                tcp_header[13] = flags_byte

            if new_window is not None:
                struct.pack_into("!H", tcp_header, 14, new_window)

            new_total_length = ip_header_len + tcp_header_len + len(new_payload)
            struct.pack_into("!H", ip_header, 2, new_total_length)

            if new_ttl is not None:
                ip_header[8] = new_ttl

            ip_header[10:12] = b"\x00\x00"
            ip_checksum = ChecksumCache.calculate_checksum(bytes(ip_header))
            struct.pack_into("!H", ip_header, 10, ip_checksum)

            tcp_header[16:18] = b"\x00\x00"
            src_ip_bytes = ip_header[12:16]
            dst_ip_bytes = ip_header[16:20]
            tcp_length = tcp_header_len + len(new_payload)
            pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 6, tcp_length)
            tcp_checksum = ChecksumCache.calculate_checksum(
                pseudo_header + bytes(tcp_header) + new_payload
            )
            struct.pack_into("!H", tcp_header, 16, tcp_checksum)

            return bytes(ip_header) + bytes(tcp_header) + new_payload

        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to assemble TCP packet: {e}")
            return original_raw + new_payload if original_raw else new_payload

    @staticmethod
    def create_minimal_tcp_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes,
        seq: Optional[int] = None,
        flags: Optional[str] = None,
    ) -> bytes:
        """
        Create a minimal TCP packet when no original raw data is available.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            payload: Packet payload
            seq: Sequence number
            flags: TCP flags

        Returns:
            Complete TCP packet bytes
        """
        try:
            import socket

            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)

            version_ihl = 4 << 4 | 5
            tos = 0
            total_length = 20 + 20 + len(payload)
            identification = random.randint(0, 65535)
            flags_offset = 0
            ttl = 64
            protocol = 6
            checksum = 0

            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                checksum,
                src_ip_bytes,
                dst_ip_bytes,
            )

            checksum = 0
            header_words = struct.unpack("!10H", ip_header[:20])
            for word in header_words:
                checksum += word
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            checksum = ~checksum & 65535

            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                version_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                checksum,
                src_ip_bytes,
                dst_ip_bytes,
            )

            seq_num = seq or random.randint(0, 2**32 - 1)
            ack_num = 0
            data_offset = 5 << 4
            flags_byte = 24 if flags is None else 0

            if flags:
                if "F" in flags:
                    flags_byte |= 1
                if "S" in flags:
                    flags_byte |= 2
                if "R" in flags:
                    flags_byte |= 4
                if "P" in flags:
                    flags_byte |= 8
                if "A" in flags:
                    flags_byte |= 16
                if "U" in flags:
                    flags_byte |= 32

            window = 65535
            tcp_checksum = 0
            urgent_ptr = 0

            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port,
                dst_port,
                seq_num,
                ack_num,
                data_offset,
                flags_byte,
                window,
                tcp_checksum,
                urgent_ptr,
            )

            pseudo_header = (
                src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 6, 20 + len(payload))
            )
            checksum_data = pseudo_header + tcp_header + payload
            if len(checksum_data) % 2:
                checksum_data += b"\x00"

            checksum = 0
            for i in range(0, len(checksum_data), 2):
                checksum += (checksum_data[i] << 8) + checksum_data[i + 1]
            while checksum >> 16:
                checksum = (checksum & 65535) + (checksum >> 16)
            tcp_checksum = ~checksum & 65535

            tcp_header = struct.pack(
                "!HHIIBBHHH",
                src_port,
                dst_port,
                seq_num,
                ack_num,
                data_offset,
                flags_byte,
                window,
                tcp_checksum,
                urgent_ptr,
            )

            return ip_header + tcp_header + payload

        except Exception:
            return payload if payload else b""
