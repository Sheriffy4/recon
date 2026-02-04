"""UDP header building utilities."""

import struct
import socket
from typing import TYPE_CHECKING

from core.packet_utils.checksum import ChecksumCache

if TYPE_CHECKING:
    from core.packet_builder import PacketParams


class UDPHeaderBuilder:
    """Builder for UDP headers (with correct IPv6 checksum)."""

    @staticmethod
    def build_udp_header(params: "PacketParams", is_ipv6: bool) -> bytes:
        """
        Build UDP header with correct checksum.

        Args:
            params: Packet parameters
            is_ipv6: Whether this is for IPv6

        Returns:
            UDP header bytes
        """
        udp_length = 8 + len(params.payload)
        header = struct.pack("!HHHH", params.src_port, params.dst_port, udp_length, 0)

        # Preserve old behavior for IPv4 (checksum=0 is allowed).
        if not is_ipv6:
            return header

        src_ip = params.src_ip or "::"
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, params.dst_ip)

        checksum = ChecksumCache.build_udp_checksum(
            src_ip_bytes, dst_ip_bytes, header, params.payload
        )
        # UDP checksum of 0x0000 must be transmitted as 0xFFFF (0 means "no checksum" historically).
        if checksum == 0:
            checksum = 0xFFFF

        return struct.pack(
            "!HHHH",
            params.src_port,
            params.dst_port,
            udp_length,
            checksum,
        )
