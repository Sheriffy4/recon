"""TCP header building utilities."""

import struct
import socket
from typing import List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.packet_builder import PacketParams

from core.packet_utils.checksum import ChecksumCache


class TCPHeaderBuilder:
    """Builder for TCP headers with options and pseudo-headers."""

    @staticmethod
    def flags_to_byte(flags: str) -> int:
        """
        Convert TCP flags string to byte value.

        Args:
            flags: TCP flags string (e.g., 'SYN', 'ACK', 'PSH')

        Returns:
            Flags byte value
        """
        flags_byte = 0
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
        return flags_byte

    @staticmethod
    def build_tcp_options(options: List[Any]) -> bytes:
        """
        Build TCP options bytes.

        Args:
            options: List of TCP options tuples

        Returns:
            TCP options bytes with padding
        """
        options_bytes = b""
        for option in options:
            if isinstance(option, tuple):
                opt_name, opt_value = option
                if opt_name == "MSS":
                    options_bytes += struct.pack("!BBH", 2, 4, opt_value)
                elif opt_name == "WScale":
                    options_bytes += struct.pack("!BBB", 3, 3, opt_value)
                elif opt_name == "SAckOK":
                    options_bytes += struct.pack("!BB", 4, 2)
                elif opt_name == "Timestamp":
                    ts_val, ts_ecr = opt_value
                    options_bytes += struct.pack("!BBII", 8, 10, ts_val, ts_ecr)
                elif opt_name == "NOP":
                    options_bytes += b"\x01"
        while len(options_bytes) % 4 != 0:
            options_bytes += b"\x01"
        return options_bytes

    @staticmethod
    def build_ipv4_pseudo_header(params: "PacketParams", tcp_length: int) -> bytes:
        """
        Build pseudo-header for TCP checksum calculation over IPv4.

        Args:
            params: Packet parameters
            tcp_length: Total TCP segment length (header + payload)

        Returns:
            IPv4 pseudo-header bytes
        """
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)
        return src_ip_bytes + dst_ip_bytes + struct.pack("!BBH", 0, 6, tcp_length)

    @staticmethod
    def build_ipv6_pseudo_header(params: "PacketParams", tcp_length: int) -> bytes:
        """
        Build pseudo-header for TCP checksum calculation over IPv6.

        Args:
            params: Packet parameters
            tcp_length: Total TCP segment length (header + payload)

        Returns:
            IPv6 pseudo-header bytes
        """
        src_ip = params.src_ip or "::"
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)
        return src_ip_bytes + dst_ip_bytes + struct.pack("!I3xB", tcp_length, 6)

    @classmethod
    def build_tcp_header(cls, params: "PacketParams", is_ipv6: bool) -> bytes:
        """
        Build complete TCP header with checksum.

        Args:
            params: Packet parameters
            is_ipv6: Whether this is for IPv6

        Returns:
            Complete TCP header bytes
        """
        flags_byte = cls.flags_to_byte(params.flags)
        data_offset = 5
        reserved_flags = data_offset << 4 | 0
        checksum = 0
        urgent_pointer = 0

        header = struct.pack(
            "!HHIIBBHHH",
            params.src_port,
            params.dst_port,
            params.seq,
            params.ack,
            reserved_flags,
            flags_byte,
            params.window,
            checksum,
            urgent_pointer,
        )

        if params.options:
            options_bytes = cls.build_tcp_options(params.options)
            header += options_bytes
            data_offset = (20 + len(options_bytes)) // 4
            header = header[:12] + struct.pack("!B", data_offset << 4) + header[13:]

        if is_ipv6:
            pseudo_header = cls.build_ipv6_pseudo_header(params, len(header) + len(params.payload))
        else:
            pseudo_header = cls.build_ipv4_pseudo_header(params, len(header) + len(params.payload))

        checksum = ChecksumCache.calculate_checksum(pseudo_header + header + params.payload)
        header = header[:16] + struct.pack("!H", checksum) + header[18:]
        return header
