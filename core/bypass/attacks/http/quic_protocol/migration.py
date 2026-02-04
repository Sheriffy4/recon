"""
QUIC Connection Migration Simulation

Extracted from quic_attacks.py to reduce QUICMigrationSimulation complexity.
Implements various connection migration strategies for DPI evasion.

Addresses:
- SM14, SM15, SM16, SM17: Feature envy smells (methods operating heavily on external data)
- UN16-UN20: Unused method warnings (now public strategy methods)
- FD8: Functional dedup cluster (sim=0.70)
"""

import secrets
from typing import List

from .packets import QUICPacket, QUICPacketType, QUICFrameType
from .frames import create_path_challenge_frame, create_path_response_frame


class MigrationSimulator:
    """
    Encapsulates all connection migration simulation strategies for QUIC attacks.

    This class extracts migration logic from QUICMigrationSimulation
    to improve maintainability and testability.
    """

    def simulate_full_migration(
        self, packets: List[QUICPacket], path_count: int, validate: bool
    ) -> List[QUICPacket]:
        """
        Simulate full connection migration with path validation.

        Addresses: SM14 (feature_envy), UN16 (unused method)
        Previously: quic_attacks.py:804-842

        Args:
            packets: List of QUIC packets to process
            path_count: Number of migration paths to simulate
            validate: Whether to include path validation frames

        Returns:
            List of packets with migration simulation applied
        """
        migrated_packets = []
        paths = [secrets.token_bytes(8) for _ in range(path_count)]
        current_path = 0

        # Calculate migration points
        migration_points = [len(packets) // (path_count + 1) * i for i in range(1, path_count + 1)]

        for i, packet in enumerate(packets):
            if i in migration_points:
                old_path = current_path
                current_path = (current_path + 1) % len(paths)

                if validate:
                    # Send PATH_CHALLENGE
                    challenge_data = secrets.token_bytes(8)
                    challenge_frame = create_path_challenge_frame(challenge_data)
                    challenge_packet = QUICPacket(
                        packet_type=QUICPacketType.ONE_RTT,
                        connection_id=paths[old_path],
                        packet_number=packet.packet_number + 10000,
                        payload=challenge_frame,
                    )
                    migrated_packets.append(challenge_packet)

                    # Send PATH_RESPONSE
                    response_frame = create_path_response_frame(challenge_data)
                    response_packet = QUICPacket(
                        packet_type=QUICPacketType.ONE_RTT,
                        connection_id=paths[current_path],
                        packet_number=packet.packet_number + 10001,
                        payload=response_frame,
                    )
                    migrated_packets.append(response_packet)

            # Create packet with current path CID
            migrated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=paths[current_path],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            migrated_packets.append(migrated_packet)

        return migrated_packets

    def simulate_nat_rebinding(self, packets: List[QUICPacket]) -> List[QUICPacket]:
        """
        Simulate NAT rebinding scenario.

        Addresses: SM15 (feature_envy), UN17 (unused method)
        Previously: quic_attacks.py:844-868

        Args:
            packets: List of QUIC packets to process

        Returns:
            List of packets with NAT rebinding simulation applied
        """
        migrated_packets = []
        original_cid = secrets.token_bytes(8)
        rebind_cid = secrets.token_bytes(8)
        rebind_point = len(packets) // 2

        for i, packet in enumerate(packets):
            # At rebind point, send probe packet
            if i == rebind_point:
                probe_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=rebind_cid,
                    packet_number=packet.packet_number + 5000,
                    payload=bytes([QUICFrameType.PING]),
                )
                migrated_packets.append(probe_packet)

            # Use new CID after rebind point
            cid = rebind_cid if i >= rebind_point else original_cid

            migrated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=cid,
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            migrated_packets.append(migrated_packet)

        return migrated_packets

    def simulate_multipath(self, packets: List[QUICPacket], path_count: int) -> List[QUICPacket]:
        """
        Simulate multipath QUIC behavior.

        Addresses: SM16 (feature_envy), UN18 (unused method)
        Previously: quic_attacks.py:870-894

        Args:
            packets: List of QUIC packets to process
            path_count: Number of paths to use

        Returns:
            List of packets with multipath simulation applied
        """
        migrated_packets = []
        paths = [secrets.token_bytes(8) for _ in range(path_count)]

        for i, packet in enumerate(packets):
            # Send on primary path
            primary_path = i % path_count
            primary_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=paths[primary_path],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            migrated_packets.append(primary_packet)

            # Occasionally duplicate on backup path
            if __import__("random").random() < 0.1:
                backup_path = (primary_path + 1) % path_count
                backup_packet = QUICPacket(
                    packet_type=packet.packet_type,
                    connection_id=paths[backup_path],
                    packet_number=packet.packet_number,
                    payload=packet.payload,
                    version=packet.version,
                )
                migrated_packets.append(backup_packet)

        return migrated_packets

    @staticmethod
    def is_path_validation_frame(payload: bytes) -> bool:
        """
        Check if payload contains path validation frames.

        Addresses: UN19 (unused method)
        Previously: quic_attacks.py:896-901

        Args:
            payload: Packet payload to check

        Returns:
            True if payload contains PATH_CHALLENGE or PATH_RESPONSE
        """
        if not payload:
            return False
        frame_type = payload[0]
        return frame_type in [QUICFrameType.PATH_CHALLENGE, QUICFrameType.PATH_RESPONSE]
