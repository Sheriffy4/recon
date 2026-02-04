"""
QUIC Packet Coalescing Strategies

Extracted from quic_attacks.py to reduce QUICPacketCoalescingAttack complexity.
Implements various packet coalescing strategies for DPI evasion.

Addresses:
- SM10, SM11, SM12, SM13: Feature envy smells (methods operating heavily on external data)
- UN12-UN15: Unused method warnings (now public strategy methods)
"""

import random
import secrets
from typing import List, Tuple

from .packets import QUICPacket, QUICPacketType, QUICFrameType
from .encoding import encode_varint


class PacketCoalescingStrategy:
    """
    Encapsulates all packet coalescing strategies for QUIC attacks.

    This class extracts coalescing logic from QUICPacketCoalescingAttack
    to improve maintainability and testability.
    """

    def coalesce_mixed_types(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """
        Coalesce packets of different types in single datagram.

        Addresses: SM10 (feature_envy), UN12 (unused method)
        Previously: quic_attacks.py:634-659

        Args:
            packets: List of QUIC packets to coalesce
            target_size: Target datagram size in bytes

        Returns:
            List of (datagram_bytes, delay) tuples
        """
        segments = []
        by_type = {}

        # Group packets by type
        for packet in packets:
            ptype = packet.packet_type
            if ptype not in by_type:
                by_type[ptype] = []
            by_type[ptype].append(packet)

        # Coalesce one packet of each type per datagram
        while any(by_type.values()):
            datagram = b""
            for ptype in [
                QUICPacketType.INITIAL,
                QUICPacketType.HANDSHAKE,
                QUICPacketType.ONE_RTT,
            ]:
                if ptype in by_type and by_type[ptype]:
                    packet = by_type[ptype].pop(0)
                    packet_bytes = packet.to_bytes()
                    if len(datagram) + len(packet_bytes) <= target_size:
                        datagram += packet_bytes

            if datagram:
                segments.append((datagram, random.randint(0, 5)))

        return segments

    def coalesce_with_size_padding(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """
        Coalesce packets and pad to specific sizes.

        Addresses: SM11 (feature_envy), UN13 (unused method)
        Previously: quic_attacks.py:661-681

        Args:
            packets: List of QUIC packets to coalesce
            target_size: Target datagram size in bytes

        Returns:
            List of (datagram_bytes, delay) tuples
        """
        segments = []

        for packet in packets:
            packet_bytes = packet.to_bytes()

            if len(packet_bytes) < target_size:
                # Add padding to reach target size
                padding_size = target_size - len(packet_bytes)
                padding_frame = bytes([QUICFrameType.PADDING]) * padding_size

                padded_packet = QUICPacket(
                    packet_type=packet.packet_type,
                    connection_id=packet.connection_id,
                    packet_number=packet.packet_number,
                    payload=packet.payload + padding_frame,
                    version=packet.version,
                )
                segments.append((padded_packet.to_bytes(), 0))
            else:
                segments.append((packet_bytes, 0))

        return segments

    def coalesce_with_frame_stuffing(
        self, packets: List[QUICPacket], target_size: int, add_decoy: bool
    ) -> List[Tuple[bytes, int]]:
        """
        Stuff packets with additional frames.

        Addresses: SM12 (feature_envy), UN14 (unused method)
        Previously: quic_attacks.py:683-708

        Args:
            packets: List of QUIC packets to coalesce
            target_size: Target datagram size in bytes
            add_decoy: Whether to add decoy frames

        Returns:
            List of (datagram_bytes, delay) tuples
        """
        segments = []

        for packet in packets:
            enhanced_payload = packet.payload

            if add_decoy:
                # Add PING frame
                enhanced_payload += bytes([QUICFrameType.PING])

                # Add MAX_DATA frame
                max_data_frame = bytes([QUICFrameType.MAX_DATA])
                max_data_frame += encode_varint(random.randint(1000000, 2000000))
                enhanced_payload += max_data_frame

                # Add NEW_TOKEN frame
                token = secrets.token_bytes(32)
                new_token_frame = bytes([QUICFrameType.NEW_TOKEN])
                new_token_frame += encode_varint(len(token))
                new_token_frame += token
                enhanced_payload += new_token_frame

            enhanced_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=packet.connection_id,
                packet_number=packet.packet_number,
                payload=enhanced_payload,
                version=packet.version,
            )
            segments.append((enhanced_packet.to_bytes(), 0))

        return segments

    def basic_coalescing(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """
        Basic coalescing strategy.

        Addresses: SM13 (feature_envy), UN15 (unused method)
        Previously: quic_attacks.py:710-726

        Args:
            packets: List of QUIC packets to coalesce
            target_size: Target datagram size in bytes

        Returns:
            List of (datagram_bytes, delay) tuples
        """
        segments = []
        current_datagram = b""

        for packet in packets:
            packet_bytes = packet.to_bytes()

            if len(current_datagram) + len(packet_bytes) <= target_size:
                current_datagram += packet_bytes
            else:
                if current_datagram:
                    segments.append((current_datagram, 0))
                current_datagram = packet_bytes

        if current_datagram:
            segments.append((current_datagram, 0))

        return segments
