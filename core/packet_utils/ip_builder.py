"""IP header building utilities for IPv4 and IPv6."""

import struct
import socket
import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.packet_builder import PacketParams

from core.packet_utils.checksum import ChecksumCache


class IPHeaderBuilder:
    """Builder for IPv4 and IPv6 headers."""

    @staticmethod
    def build_ipv4_header(params: "PacketParams", payload_length: int, protocol: int = 6) -> bytes:
        """
        Build IPv4 header.

        Args:
            params: Packet parameters
            payload_length: Length of payload (TCP/UDP header + data)
            protocol: Protocol number (6=TCP, 17=UDP)

        Returns:
            IPv4 header bytes
        """
        src_ip = params.src_ip or socket.gethostbyname(socket.gethostname())
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(params.dst_ip)

        version_ihl = 4 << 4 | 5
        tos = 0
        total_length = 20 + payload_length
        identification = random.randint(0, 65535)
        flags_offset = 0
        ttl = params.ttl or 64
        checksum = 0

        header = (
            struct.pack(
                "!BBHHHBBH",
                version_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                checksum,
            )
            + src_ip_bytes
            + dst_ip_bytes
        )

        checksum = ChecksumCache.calculate_checksum(header)
        header = header[:10] + struct.pack("!H", checksum) + header[12:]
        return header

    @staticmethod
    def build_ipv6_header(
        params: "PacketParams", payload_length: int, next_header: int = 6
    ) -> bytes:
        """
        Build IPv6 header.

        Args:
            params: Packet parameters
            payload_length: Length of payload (TCP/UDP header + data)
            next_header: Next header type (6=TCP, 17=UDP)

        Returns:
            IPv6 header bytes
        """
        src_ip = params.src_ip or "::"
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)

        version_class_flow = 6 << 28
        hop_limit = params.ttl or 64

        header = (
            struct.pack("!IHBB", version_class_flow, payload_length, next_header, hop_limit)
            + src_ip_bytes
            + dst_ip_bytes
        )
        return header

    @staticmethod
    def is_ipv6(ip_address: str) -> bool:
        """
        Check if IP address is IPv6.

        Args:
            ip_address: IP address string

        Returns:
            True if IPv6, False if IPv4
        """
        return ":" in ip_address
