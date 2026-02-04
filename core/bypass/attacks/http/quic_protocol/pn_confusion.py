"""
QUIC Packet Number Confusion Strategies

Extracted from quic_attacks.py to reduce AdvancedPacketNumberSpaceConfusion complexity.
Implements various packet number manipulation strategies for DPI evasion.

Addresses:
- SM5, SM6, SM7, SM8: Feature envy smells (methods operating heavily on external data)
- UN7-UN10: Unused method warnings (now public strategy methods)
- FD3: Functional dedup cluster (sim=0.81)
"""

import random
from typing import List

from .packets import QUICPacket, QUICPacketType
from .frames import create_crypto_frame, create_padding_frame


class PacketNumberConfusionStrategy:
    """
    Encapsulates all Packet Number confusion strategies for QUIC attacks.

    This class extracts PN confusion logic from AdvancedPacketNumberSpaceConfusion
    to improve maintainability and testability.
    """

    def apply_mixed_spaces_confusion(self, packets: List[QUICPacket]) -> List[QUICPacket]:
        """
        Mix different encryption levels with confusing packet numbers.

        Addresses: SM5 (feature_envy), UN7 (unused method)
        Previously: quic_attacks.py:403-439

        Args:
            packets: List of QUIC packets to process

        Returns:
            List of packets with mixed encryption level confusion applied
        """
        confused_packets = []
        initial_pn = 0
        handshake_pn = 0
        app_pn = 0

        for i, packet in enumerate(packets):
            # Create Initial packet
            initial_packet = QUICPacket(
                packet_type=QUICPacketType.INITIAL,
                connection_id=packet.connection_id,
                packet_number=initial_pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(initial_packet)
            initial_pn += random.randint(1, 10)

            # Periodically add Handshake packet
            if i % 3 == 0:
                handshake_packet = QUICPacket(
                    packet_type=QUICPacketType.HANDSHAKE,
                    connection_id=packet.connection_id,
                    packet_number=handshake_pn,
                    payload=create_crypto_frame(b"CONFUSION"),
                    version=packet.version,
                )
                confused_packets.append(handshake_packet)
                handshake_pn += random.randint(1, 5)

            # Create 1-RTT packet
            app_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=packet.connection_id,
                packet_number=app_pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(app_packet)
            app_pn += random.randint(1, 15)

        # Shuffle to maximize confusion
        random.shuffle(confused_packets)
        return confused_packets

    def apply_overlapping_pn_confusion(self, packets: List[QUICPacket]) -> List[QUICPacket]:
        """
        Create overlapping packet numbers across different spaces.

        Addresses: SM6 (feature_envy), UN8 (unused method), FD3 (functional dedup)
        Previously: quic_attacks.py:441-471

        Args:
            packets: List of QUIC packets to process

        Returns:
            List of packets with overlapping PN confusion applied
        """
        confused_packets = []
        base_pn = random.randint(1000, 5000)

        for i, packet in enumerate(packets):
            packet_types = [
                QUICPacketType.INITIAL,
                QUICPacketType.HANDSHAKE,
                QUICPacketType.ONE_RTT,
            ]
            packet_type = packet_types[i % len(packet_types)]
            pn = base_pn + i // len(packet_types)

            confused_packet = QUICPacket(
                packet_type=packet_type,
                connection_id=packet.connection_id,
                packet_number=pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(confused_packet)

            # Add duplicate with different type
            if i % 5 == 0:
                dup_type = packet_types[(i + 1) % len(packet_types)]
                dup_packet = QUICPacket(
                    packet_type=dup_type,
                    connection_id=packet.connection_id,
                    packet_number=pn,
                    payload=create_crypto_frame(b"DUPLICATE"),
                    version=packet.version,
                )
                confused_packets.append(dup_packet)

        return confused_packets

    def apply_phantom_spaces_confusion(self, packets: List[QUICPacket]) -> List[QUICPacket]:
        """
        Create phantom packet number spaces that don't follow spec.

        Addresses: SM7 (feature_envy), UN9 (unused method)
        Previously: quic_attacks.py:473-500

        Args:
            packets: List of QUIC packets to process

        Returns:
            List of packets with phantom space confusion applied
        """
        confused_packets = []
        phantom_spaces = {
            "negative": -1000,
            "huge": 2**32 - 1000,
            "zero": 0,
            "random": random.randint(10000, 50000),
        }
        space_names = list(phantom_spaces.keys())

        for i, packet in enumerate(packets):
            # Add original packet
            confused_packets.append(packet)

            # Add phantom packet
            space_name = space_names[i % len(space_names)]
            base_pn = phantom_spaces[space_name]
            phantom_pn = base_pn + i // len(space_names)

            # Normalize to valid range
            if phantom_pn < 0:
                phantom_pn = (2**32 + phantom_pn) & 0xFFFFFFFF
            else:
                phantom_pn = phantom_pn & 0xFFFFFFFF

            phantom_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=packet.connection_id,
                packet_number=phantom_pn,
                payload=create_padding_frame(20),
                version=packet.version,
            )
            confused_packets.append(phantom_packet)

        return confused_packets

    def apply_chaotic_ordering(self, packets: List[QUICPacket], max_gap: int) -> List[QUICPacket]:
        """
        Apply chaotic packet number ordering with large gaps.

        Addresses: SM8 (feature_envy), UN10 (unused method)
        Previously: quic_attacks.py:502-534

        Args:
            packets: List of QUIC packets to process
            max_gap: Maximum gap between packet numbers

        Returns:
            List of packets with chaotic ordering applied
        """
        confused_packets = []
        current_pn = random.randint(1000, 10000)
        used_pns = set()

        for packet in packets:
            # Randomly go backward or forward
            if random.random() < 0.3:
                pn = current_pn - random.randint(1, min(100, current_pn))
            else:
                pn = current_pn + random.randint(1, max_gap)

            # Ensure uniqueness
            while pn in used_pns:
                pn += 1
            used_pns.add(pn)
            current_pn = pn

            confused_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=packet.connection_id,
                packet_number=pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(confused_packet)

            # Randomly add retransmission
            if random.random() < 0.2 and len(used_pns) > 3:
                old_pn = random.choice(list(used_pns))
                retrans_packet = QUICPacket(
                    packet_type=packet.packet_type,
                    connection_id=packet.connection_id,
                    packet_number=old_pn,
                    payload=create_padding_frame(10),
                    version=packet.version,
                )
                confused_packets.append(retrans_packet)

        return confused_packets
