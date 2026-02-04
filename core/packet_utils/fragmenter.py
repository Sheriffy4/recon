"""Packet fragmentation utilities."""

import struct
import logging
from typing import List, Union, TYPE_CHECKING

if TYPE_CHECKING:
    try:
        from scapy.all import Packet
    except ImportError:
        Packet = None

from core.packet_utils.checksum import ChecksumCache


class PacketFragmenter:
    """Fragments packets for both Scapy and byte-level packets."""

    @staticmethod
    def fragment_packet_scapy(packet: "Packet", frag_size: int) -> List["Packet"]:
        """
        Fragment packet using Scapy.

        Args:
            packet: Scapy packet to fragment
            frag_size: Fragment size

        Returns:
            List of fragmented Scapy packets
        """
        try:
            from scapy.all import fragment

            return fragment(packet, fragsize=frag_size)
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to fragment packet with Scapy: {e}")
            return [packet]

    @staticmethod
    def fragment_packet_bytes(packet: bytes, frag_size: int) -> List[bytes]:
        """
        Fragment packet at byte level.

        Args:
            packet: Packet bytes to fragment
            frag_size: Fragment size

        Returns:
            List of fragmented packet bytes
        """
        fragments = []
        try:
            if len(packet) > 0:
                version = packet[0] >> 4 & 15
                if version == 4:
                    ip_header_len = (packet[0] & 15) * 4
                    total_length = struct.unpack("!H", packet[2:4])[0]
                    data_start = ip_header_len
                    data = packet[data_start:]
                    offset = 0
                    frag_id = struct.unpack("!H", packet[4:6])[0]

                    while offset < len(data):
                        chunk_size = min(frag_size, len(data) - offset)
                        chunk_size = chunk_size // 8 * 8

                        if chunk_size == 0 and offset < len(data):
                            chunk_size = len(data) - offset

                        more_fragments = 1 if offset + chunk_size < len(data) else 0
                        flags_offset = more_fragments << 13 | offset // 8

                        new_header = bytearray(packet[:ip_header_len])
                        new_total_length = ip_header_len + chunk_size
                        struct.pack_into("!H", new_header, 2, new_total_length)
                        struct.pack_into("!H", new_header, 6, flags_offset)
                        struct.pack_into("!H", new_header, 10, 0)

                        checksum = ChecksumCache.calculate_checksum(bytes(new_header))
                        struct.pack_into("!H", new_header, 10, checksum)

                        fragment = bytes(new_header) + data[offset : offset + chunk_size]
                        fragments.append(fragment)
                        offset += chunk_size
                else:
                    fragments = [packet]
            else:
                fragments = [packet]
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to fragment packet bytes: {e}")
            fragments = [packet]
        return fragments
