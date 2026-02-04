"""
QUIC Connection ID Rotation Strategies

Extracted from quic_attacks.py to reduce AdvancedQUICConnectionIDRotation complexity.
Implements various CID rotation strategies for DPI evasion.

Addresses:
- SM1, SM2, SM3, SM4: Feature envy smells (methods operating heavily on external data)
- UN3-UN6: Unused method warnings (now public strategy methods)
"""

import asyncio
from typing import List

from .packets import QUICPacket, QUICPacketType
from .frames import create_new_connection_id_frame, create_retire_connection_id_frame
from .encoding import calculate_entropy


class ConnectionIDRotationStrategy:
    """
    Encapsulates all Connection ID rotation strategies for QUIC attacks.

    This class extracts rotation logic from AdvancedQUICConnectionIDRotation
    to improve maintainability and testability.
    """

    async def apply_aggressive_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """
        Apply aggressive CID rotation - change on every packet.

        Addresses: SM1 (feature_envy), UN3 (unused method)
        Previously: quic_attacks.py:216-254

        Args:
            packets: List of QUIC packets to process
            cid_pool: Pool of connection IDs to rotate through

        Returns:
            List of packets with aggressive CID rotation applied
        """
        rotated_packets = []
        cid_sequence_number = 0

        for i, packet in enumerate(packets):
            new_cid = cid_pool[i % len(cid_pool)]

            if i > 0:
                # Send NEW_CONNECTION_ID frame
                new_cid_frame = create_new_connection_id_frame(cid_sequence_number, new_cid)
                control_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=cid_pool[(i - 1) % len(cid_pool)],
                    packet_number=packet.packet_number + 1000,
                    payload=new_cid_frame,
                )
                rotated_packets.append(control_packet)
                cid_sequence_number += 1

            # Create packet with new CID
            rotated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=new_cid,
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            rotated_packets.append(rotated_packet)

            # Periodically retire old CIDs
            if i > 0 and i % 3 == 0:
                retire_frame = create_retire_connection_id_frame(max(0, cid_sequence_number - 3))
                retire_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=new_cid,
                    packet_number=packet.packet_number + 2000,
                    payload=retire_frame,
                )
                rotated_packets.append(retire_packet)

            await asyncio.sleep(0)

        return rotated_packets

    def apply_entropy_based_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """
        Rotate CIDs based on packet content entropy to evade analysis.

        Addresses: SM2 (feature_envy), UN4 (unused method)
        Previously: quic_attacks.py:256-275

        Args:
            packets: List of QUIC packets to process
            cid_pool: Pool of connection IDs to rotate through

        Returns:
            List of packets with entropy-based CID rotation applied
        """
        rotated_packets = []
        current_cid_index = 0

        for packet in packets:
            # Calculate entropy and rotate if high
            entropy = calculate_entropy(packet.payload)
            if entropy > 0.7:
                current_cid_index = (current_cid_index + 1) % len(cid_pool)

            rotated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=cid_pool[current_cid_index],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            rotated_packets.append(rotated_packet)

        return rotated_packets

    def apply_coordinated_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """
        Coordinate CID rotation with packet number spaces and encryption levels.

        Addresses: SM3 (feature_envy), UN5 (unused method)
        Previously: quic_attacks.py:277-303

        Args:
            packets: List of QUIC packets to process
            cid_pool: Pool of connection IDs to rotate through

        Returns:
            List of packets with coordinated CID rotation applied
        """
        rotated_packets = []

        # Assign CIDs per encryption level
        initial_cid = cid_pool[0]
        handshake_cid = cid_pool[1 % len(cid_pool)]
        app_data_cids = cid_pool[2:]
        app_cid_index = 0

        for packet in packets:
            # Select CID based on packet type
            if packet.packet_type == QUICPacketType.INITIAL:
                cid = initial_cid
            elif packet.packet_type == QUICPacketType.HANDSHAKE:
                cid = handshake_cid
            else:
                cid = app_data_cids[app_cid_index % len(app_data_cids)]
                if packet.packet_number % 5 == 0:
                    app_cid_index += 1

            rotated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=cid,
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            rotated_packets.append(rotated_packet)

        return rotated_packets

    def apply_standard_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """
        Standard rotation - change CID every N packets.

        Addresses: SM4 (feature_envy), UN6 (unused method)
        Previously: quic_attacks.py:305-323

        Args:
            packets: List of QUIC packets to process
            cid_pool: Pool of connection IDs to rotate through

        Returns:
            List of packets with standard CID rotation applied
        """
        rotated_packets = []
        current_cid_index = 0
        rotation_frequency = 5

        for i, packet in enumerate(packets):
            # Rotate every N packets
            if i > 0 and i % rotation_frequency == 0:
                current_cid_index = (current_cid_index + 1) % len(cid_pool)

            rotated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=cid_pool[current_cid_index],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            rotated_packets.append(rotated_packet)

        return rotated_packets
