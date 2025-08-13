# recon/core/bypass/attacks/http/quic_attacks.py
"""
QUIC/HTTP3 Protocol Attacks

Advanced attacks that manipulate QUIC protocol features to evade DPI detection.
Includes Connection ID manipulation, packet coalescing, migration techniques,
and advanced packet number space confusion.
"""

import time
import struct
import random
import secrets
from typing import List, Dict, Tuple, Optional, Union, Any
from dataclasses import dataclass
from enum import IntEnum
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


class QUICPacketType(IntEnum):
    """QUIC packet types."""

    INITIAL = 0x00
    ZERO_RTT = 0x01
    HANDSHAKE = 0x02
    RETRY = 0x03
    ONE_RTT = 0x40  # Short header packet
    VERSION_NEGOTIATION = 0xFF


class QUICFrameType(IntEnum):
    """QUIC frame types."""

    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    CONNECTION_CLOSE = 0x1C


@dataclass
class QUICFrame:
    """QUIC frame structure."""

    frame_type: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """Convert frame to bytes."""
        frame_type_bytes = self._encode_varint(self.frame_type)
        return frame_type_bytes + self.payload

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        """Encode variable-length integer."""
        if value < 64:
            return struct.pack(">B", value)
        elif value < 16384:
            return struct.pack(">H", 0x4000 | value)
        elif value < 1073741824:
            return struct.pack(">I", 0x80000000 | value)
        else:
            return struct.pack(">Q", 0xC000000000000000 | value)


@dataclass
class QUICPacket:
    """QUIC packet structure."""

    packet_type: QUICPacketType
    connection_id: bytes
    packet_number: int
    payload: bytes
    version: int = 0x00000001

    @property
    def is_long_header(self) -> bool:
        return self.packet_type != QUICPacketType.ONE_RTT

    def to_bytes(self) -> bytes:
        """Convert packet to bytes."""
        if self.is_long_header:
            return self._build_long_header_packet()
        else:
            return self._build_short_header_packet()

    def _build_long_header_packet(self) -> bytes:
        """Build long header packet."""
        # Header flags
        first_byte = 0x80 | (self.packet_type << 4) | 0x40

        result = struct.pack(">B", first_byte)
        result += struct.pack(">I", self.version)

        # Destination Connection ID
        result += struct.pack(">B", len(self.connection_id))
        result += self.connection_id

        # Source Connection ID (empty for simplicity)
        result += struct.pack(">B", 0)

        # Token (empty for non-Initial packets)
        if self.packet_type == QUICPacketType.INITIAL:
            result += QUICFrame._encode_varint(0)

        # Length
        packet_number_length = self._get_packet_number_length()
        payload_length = (
            packet_number_length + len(self.payload) + 16
        )  # +16 for AEAD tag
        result += QUICFrame._encode_varint(payload_length)

        # Packet Number
        result += self._encode_packet_number()

        # Payload
        result += self.payload

        # Fake AEAD tag
        result += secrets.token_bytes(16)

        return result

    def _build_short_header_packet(self) -> bytes:
        """Build short header packet."""
        # Header flags with spin bit and key phase
        spin_bit = random.randint(0, 1) << 5
        key_phase = random.randint(0, 1) << 2
        pn_length = 0x01  # 2-byte packet number
        first_byte = 0x40 | spin_bit | key_phase | pn_length

        result = struct.pack(">B", first_byte)
        result += self.connection_id
        result += self._encode_packet_number()
        result += self.payload
        result += secrets.token_bytes(16)  # Fake AEAD tag

        return result

    def _get_packet_number_length(self) -> int:
        """Get packet number length in bytes."""
        if self.packet_number < 128:
            return 1
        elif self.packet_number < 32768:
            return 2
        else:
            return 4

    def _encode_packet_number(self) -> bytes:
        """Encode packet number."""
        length = self._get_packet_number_length()
        if length == 1:
            return struct.pack(">B", self.packet_number & 0xFF)
        elif length == 2:
            return struct.pack(">H", self.packet_number & 0xFFFF)
        else:
            return struct.pack(">I", self.packet_number & 0xFFFFFFFF)


class BaseQUICAttack(BaseAttack):
    """Base class for QUIC attacks with common functionality."""

    def _is_quic_traffic(self, payload: bytes) -> bool:
        """Check if payload contains QUIC traffic."""
        if len(payload) < 1:
            return False
        first_byte = payload[0]
        return bool(first_byte & 0x80) or bool(first_byte & 0x40)

    def _convert_to_quic_packets(
        self,
        payload: bytes,
        connection_id: Optional[bytes] = None,
        chunk_size: int = 500,
    ) -> List[QUICPacket]:
        """Convert payload to QUIC packets."""
        packets = []
        if connection_id is None:
            connection_id = secrets.token_bytes(8)

        packet_number = 0

        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]

            # First packet is INITIAL, rest are 1-RTT
            packet_type = QUICPacketType.INITIAL if i == 0 else QUICPacketType.ONE_RTT

            # Create STREAM frame
            stream_frame = self._create_stream_frame(0, chunk)

            packet = QUICPacket(
                packet_type=packet_type,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=stream_frame,
            )
            packets.append(packet)
            packet_number += 1

        return packets

    def _create_stream_frame(
        self, stream_id: int, data: bytes, fin: bool = False, offset: int = 0
    ) -> bytes:
        """Create STREAM frame."""
        # Frame type with flags
        frame_type = QUICFrameType.STREAM
        if offset > 0:
            frame_type |= 0x04  # OFF bit
        if len(data) > 0:
            frame_type |= 0x02  # LEN bit
        if fin:
            frame_type |= 0x01  # FIN bit

        frame = QUICFrame._encode_varint(frame_type)
        frame += QUICFrame._encode_varint(stream_id)

        if offset > 0:
            frame += QUICFrame._encode_varint(offset)

        if len(data) > 0:
            frame += QUICFrame._encode_varint(len(data))
            frame += data

        return frame

    def _create_crypto_frame(self, data: bytes, offset: int = 0) -> bytes:
        """Create CRYPTO frame."""
        frame = QUICFrame(QUICFrameType.CRYPTO, b"")
        result = frame._encode_varint(QUICFrameType.CRYPTO)
        result += frame._encode_varint(offset)
        result += frame._encode_varint(len(data))
        result += data
        return result

    def _create_http3_settings_frame(self) -> bytes:
        """Create HTTP/3 SETTINGS frame."""
        settings = {
            0x01: 100,  # QPACK Max Table Capacity
            0x06: 16384,  # MAX_FIELD_SECTION_SIZE
            0x07: 100,  # QPACK Blocked Streams
        }

        frame_type = QUICFrame._encode_varint(0x04)  # SETTINGS frame
        payload = b""

        for setting_id, value in settings.items():
            payload += QUICFrame._encode_varint(setting_id)
            payload += QUICFrame._encode_varint(value)

        return frame_type + payload

    def _create_http3_headers_frame(self, headers: Dict[str, str]) -> bytes:
        """Create HTTP/3 HEADERS frame with QPACK encoding."""
        # Simplified QPACK encoding
        encoded_headers = b""

        for name, value in headers.items():
            # Literal Header Field with Name Reference
            encoded_headers += b"\x50"  # Literal with post-base name reference
            encoded_headers += struct.pack(">B", len(name))
            encoded_headers += name.encode()
            encoded_headers += struct.pack(">B", len(value))
            encoded_headers += value.encode()

        frame_type = QUICFrame._encode_varint(0x01)  # HEADERS frame
        length = QUICFrame._encode_varint(len(encoded_headers))

        return frame_type + length + encoded_headers


@register_attack
class AdvancedQUICConnectionIDRotation(BaseQUICAttack):
    """
    Advanced QUIC Connection ID Rotation Attack.

    Implements sophisticated CID rotation strategies including:
    - Rapid rotation with proper NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames
    - Variable-length CIDs to confuse tracking
    - CID pools with entropy analysis evasion
    - Coordinated rotation with packet number spaces
    """

    @property
    def name(self) -> str:
        return "quic_advanced_cid_rotation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Advanced QUIC Connection ID rotation with multiple evasion techniques"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced CID rotation attack."""
        start_time = time.time()

        try:
            # Parameters
            rotation_strategy = context.params.get("rotation_strategy", "aggressive")
            min_cid_length = context.params.get("min_cid_length", 4)
            max_cid_length = context.params.get("max_cid_length", 18)
            pool_size = context.params.get("pool_size", 20)
            use_zero_length = context.params.get("use_zero_length", True)

            # Generate CID pool with variable lengths
            cid_pool = self._generate_cid_pool(
                pool_size, min_cid_length, max_cid_length, use_zero_length
            )

            # Convert payload to QUIC packets
            packets = self._convert_to_quic_packets(context.payload)

            # Apply CID rotation strategy
            if rotation_strategy == "aggressive":
                rotated_packets = self._apply_aggressive_rotation(packets, cid_pool)
            elif rotation_strategy == "entropy_based":
                rotated_packets = self._apply_entropy_based_rotation(packets, cid_pool)
            elif rotation_strategy == "coordinated":
                rotated_packets = self._apply_coordinated_rotation(packets, cid_pool)
            else:
                rotated_packets = self._apply_standard_rotation(packets, cid_pool)

            # Generate segments
            segments = [(packet.to_bytes(), 0) for packet in rotated_packets]

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "rotation_strategy": rotation_strategy,
                    "cid_pool_size": pool_size,
                    "unique_cids_used": len(
                        set(p.connection_id for p in rotated_packets)
                    ),
                    "zero_length_cids": sum(
                        1 for p in rotated_packets if len(p.connection_id) == 0
                    ),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC CID Rotation ({rotation_strategy})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _generate_cid_pool(
        self, pool_size: int, min_length: int, max_length: int, use_zero_length: bool
    ) -> List[bytes]:
        """Generate pool of Connection IDs with variable lengths."""
        cid_pool = []

        # Add zero-length CID if requested
        if use_zero_length:
            cid_pool.append(b"")

        # Generate CIDs with entropy patterns
        for i in range(pool_size):
            if i % 5 == 0 and use_zero_length:
                # Periodic zero-length CID
                cid_pool.append(b"")
            else:
                # Variable length with different entropy patterns
                length = random.randint(min_length, max_length)

                if i % 3 == 0:
                    # High entropy (random)
                    cid = secrets.token_bytes(length)
                elif i % 3 == 1:
                    # Low entropy (repeated pattern)
                    pattern = bytes([i % 256])
                    cid = pattern * length
                else:
                    # Mixed entropy
                    cid = secrets.token_bytes(length // 2) + bytes(
                        [0xFF] * (length - length // 2)
                    )

                cid_pool.append(cid)

        return cid_pool

    def _apply_aggressive_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """Apply aggressive CID rotation - change on every packet."""
        rotated_packets = []
        cid_sequence_number = 0

        for i, packet in enumerate(packets):
            # Rotate CID for every packet
            new_cid = cid_pool[i % len(cid_pool)]

            # Add NEW_CONNECTION_ID frame before switching
            if i > 0:
                new_cid_frame = self._create_new_connection_id_frame(
                    cid_sequence_number, new_cid
                )
                # Create control packet with NEW_CONNECTION_ID
                control_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=cid_pool[(i - 1) % len(cid_pool)],
                    packet_number=packet.packet_number + 1000,
                    payload=new_cid_frame,
                )
                rotated_packets.append(control_packet)
                cid_sequence_number += 1

            # Create data packet with new CID
            rotated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=new_cid,
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            rotated_packets.append(rotated_packet)

            # Retire old CID periodically
            if i > 0 and i % 3 == 0:
                retire_frame = self._create_retire_connection_id_frame(
                    max(0, cid_sequence_number - 3)
                )
                retire_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=new_cid,
                    packet_number=packet.packet_number + 2000,
                    payload=retire_frame,
                )
                rotated_packets.append(retire_packet)

        return rotated_packets

    def _apply_entropy_based_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """Rotate CIDs based on packet content entropy to evade analysis."""
        rotated_packets = []
        current_cid_index = 0

        for packet in packets:
            # Calculate payload entropy
            entropy = self._calculate_entropy(packet.payload)

            # Change CID if entropy crosses threshold
            if entropy > 0.7:  # High entropy threshold
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

    def _apply_coordinated_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """Coordinate CID rotation with packet number spaces and encryption levels."""
        rotated_packets = []

        # Different CIDs for different packet number spaces
        initial_cid = cid_pool[0]
        handshake_cid = cid_pool[1 % len(cid_pool)]
        app_data_cids = cid_pool[2:]
        app_cid_index = 0

        for packet in packets:
            if packet.packet_type == QUICPacketType.INITIAL:
                cid = initial_cid
            elif packet.packet_type == QUICPacketType.HANDSHAKE:
                cid = handshake_cid
            else:
                # Rotate through app data CIDs
                cid = app_data_cids[app_cid_index % len(app_data_cids)]
                if packet.packet_number % 5 == 0:  # Rotate every 5 packets
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

    def _apply_standard_rotation(
        self, packets: List[QUICPacket], cid_pool: List[bytes]
    ) -> List[QUICPacket]:
        """Standard rotation - change CID every N packets."""
        rotated_packets = []
        current_cid_index = 0
        rotation_frequency = 5

        for i, packet in enumerate(packets):
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

    def _create_new_connection_id_frame(
        self, sequence_number: int, connection_id: bytes
    ) -> bytes:
        """Create NEW_CONNECTION_ID frame."""
        frame = QUICFrame._encode_varint(QUICFrameType.NEW_CONNECTION_ID)
        frame += QUICFrame._encode_varint(sequence_number)
        frame += QUICFrame._encode_varint(
            max(0, sequence_number - 2)
        )  # Retire Prior To
        frame += struct.pack(">B", len(connection_id))
        frame += connection_id
        frame += secrets.token_bytes(16)  # Stateless Reset Token
        return frame

    def _create_retire_connection_id_frame(self, sequence_number: int) -> bytes:
        """Create RETIRE_CONNECTION_ID frame."""
        frame = QUICFrame._encode_varint(QUICFrameType.RETIRE_CONNECTION_ID)
        frame += QUICFrame._encode_varint(sequence_number)
        return frame

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (
                    probability
                    if probability == 1
                    else probability * (1 / probability).bit_length()
                )

        # Normalize to 0-1 range
        return min(1.0, entropy / 8.0)


@register_attack
class AdvancedPacketNumberSpaceConfusion(BaseQUICAttack):
    """
    Advanced QUIC Packet Number Space Confusion Attack.

    Implements sophisticated confusion techniques:
    - Mixed encryption levels in single datagram
    - Overlapping packet numbers across spaces
    - Out-of-order packet number sequences
    - Phantom packet number spaces
    """

    @property
    def name(self) -> str:
        return "quic_advanced_pn_confusion"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Advanced packet number space manipulation to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced packet number confusion attack."""
        start_time = time.time()

        try:
            # Parameters
            confusion_strategy = context.params.get(
                "confusion_strategy", "mixed_spaces"
            )
            use_coalescing = context.params.get("use_coalescing", True)
            max_pn_gap = context.params.get("max_pn_gap", 1000)

            # Convert payload to packets
            base_packets = self._convert_to_quic_packets(context.payload)

            # Apply confusion strategy
            if confusion_strategy == "mixed_spaces":
                confused_packets = self._apply_mixed_spaces_confusion(base_packets)
            elif confusion_strategy == "overlapping_pn":
                confused_packets = self._apply_overlapping_pn_confusion(base_packets)
            elif confusion_strategy == "phantom_spaces":
                confused_packets = self._apply_phantom_spaces_confusion(base_packets)
            elif confusion_strategy == "chaotic_ordering":
                confused_packets = self._apply_chaotic_ordering(
                    base_packets, max_pn_gap
                )
            else:
                confused_packets = base_packets

            # Apply packet coalescing if requested
            if use_coalescing:
                segments = self._coalesce_packets(confused_packets)
            else:
                segments = [(packet.to_bytes(), 0) for packet in confused_packets]

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "confusion_strategy": confusion_strategy,
                    "original_packets": len(base_packets),
                    "confused_packets": len(confused_packets),
                    "coalesced": use_coalescing,
                    "pn_ranges": self._analyze_pn_distribution(confused_packets),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC PN Confusion ({confusion_strategy})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _apply_mixed_spaces_confusion(
        self, packets: List[QUICPacket]
    ) -> List[QUICPacket]:
        """Mix different encryption levels with confusing packet numbers."""
        confused_packets = []

        # Create separate packet number spaces
        initial_pn = 0
        handshake_pn = 0
        app_pn = 0

        for i, packet in enumerate(packets):
            # Create packets in all three spaces with same content
            # This confuses DPI about which space is actually being used

            # Initial space packet
            initial_packet = QUICPacket(
                packet_type=QUICPacketType.INITIAL,
                connection_id=packet.connection_id,
                packet_number=initial_pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(initial_packet)
            initial_pn += random.randint(1, 10)

            # Handshake space packet (sometimes)
            if i % 3 == 0:
                handshake_packet = QUICPacket(
                    packet_type=QUICPacketType.HANDSHAKE,
                    connection_id=packet.connection_id,
                    packet_number=handshake_pn,
                    payload=self._create_crypto_frame(b"CONFUSION"),
                    version=packet.version,
                )
                confused_packets.append(handshake_packet)
                handshake_pn += random.randint(1, 5)

            # Application space packet
            app_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=packet.connection_id,
                packet_number=app_pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(app_packet)
            app_pn += random.randint(1, 15)

        # Shuffle to mix ordering
        random.shuffle(confused_packets)
        return confused_packets

    def _apply_overlapping_pn_confusion(
        self, packets: List[QUICPacket]
    ) -> List[QUICPacket]:
        """Create overlapping packet numbers across different spaces."""
        confused_packets = []

        # Use same packet number range for different encryption levels
        base_pn = random.randint(1000, 5000)

        for i, packet in enumerate(packets):
            # Determine packet type in rotating fashion
            packet_types = [
                QUICPacketType.INITIAL,
                QUICPacketType.HANDSHAKE,
                QUICPacketType.ONE_RTT,
            ]
            packet_type = packet_types[i % len(packet_types)]

            # Use overlapping packet numbers
            pn = base_pn + (i // len(packet_types))

            confused_packet = QUICPacket(
                packet_type=packet_type,
                connection_id=packet.connection_id,
                packet_number=pn,
                payload=packet.payload,
                version=packet.version,
            )
            confused_packets.append(confused_packet)

            # Occasionally duplicate packet numbers across spaces
            if i % 5 == 0:
                dup_type = packet_types[(i + 1) % len(packet_types)]
                dup_packet = QUICPacket(
                    packet_type=dup_type,
                    connection_id=packet.connection_id,
                    packet_number=pn,  # Same PN!
                    payload=self._create_crypto_frame(b"DUPLICATE"),
                    version=packet.version,
                )
                confused_packets.append(dup_packet)

        return confused_packets

    def _apply_phantom_spaces_confusion(
        self, packets: List[QUICPacket]
    ) -> List[QUICPacket]:
        """Create phantom packet number spaces that don't follow spec."""
        confused_packets = []

        # Create non-standard packet number spaces
        phantom_spaces = {
            "negative": -1000,
            "huge": 2**32 - 1000,
            "zero": 0,
            "random": random.randint(10000, 50000),
        }

        space_names = list(phantom_spaces.keys())

        for i, packet in enumerate(packets):
            # Regular packet
            confused_packets.append(packet)

            # Add phantom space packet
            space_name = space_names[i % len(space_names)]
            base_pn = phantom_spaces[space_name]

            # Create packet with unusual packet number
            phantom_pn = base_pn + (i // len(space_names))

            # Ensure packet number fits in encoding
            if phantom_pn < 0:
                phantom_pn = (2**32 + phantom_pn) & 0xFFFFFFFF
            else:
                phantom_pn = phantom_pn & 0xFFFFFFFF

            phantom_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=packet.connection_id,
                packet_number=phantom_pn,
                payload=self._create_padding_frame(20),
                version=packet.version,
            )
            confused_packets.append(phantom_packet)

        return confused_packets

    def _apply_chaotic_ordering(
        self, packets: List[QUICPacket], max_gap: int
    ) -> List[QUICPacket]:
        """Apply chaotic packet number ordering with large gaps."""
        confused_packets = []

        # Generate chaotic packet number sequence
        current_pn = random.randint(1000, 10000)
        used_pns = set()

        for packet in packets:
            # Jump forward or backward randomly
            if random.random() < 0.3:  # 30% chance of backward jump
                pn = current_pn - random.randint(1, min(100, current_pn))
            else:
                pn = current_pn + random.randint(1, max_gap)

            # Ensure unique packet number
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

            # Occasionally inject out-of-order retransmission
            if random.random() < 0.2 and len(used_pns) > 3:
                old_pn = random.choice(list(used_pns))
                retrans_packet = QUICPacket(
                    packet_type=packet.packet_type,
                    connection_id=packet.connection_id,
                    packet_number=old_pn,
                    payload=self._create_padding_frame(10),
                    version=packet.version,
                )
                confused_packets.append(retrans_packet)

        return confused_packets

    def _coalesce_packets(self, packets: List[QUICPacket]) -> List[Tuple[bytes, int]]:
        """Coalesce multiple packets into single UDP datagrams."""
        segments = []
        max_datagram_size = 1200

        current_datagram = b""
        current_size = 0

        for packet in packets:
            packet_bytes = packet.to_bytes()
            packet_size = len(packet_bytes)

            if current_size + packet_size <= max_datagram_size:
                # Add to current datagram
                current_datagram += packet_bytes
                current_size += packet_size
            else:
                # Finalize current datagram
                if current_datagram:
                    segments.append((current_datagram, 0))

                # Start new datagram
                current_datagram = packet_bytes
                current_size = packet_size

        # Add final datagram
        if current_datagram:
            segments.append((current_datagram, 0))

        return segments

    def _create_padding_frame(self, size: int) -> bytes:
        """Create PADDING frame of specified size."""
        return bytes([QUICFrameType.PADDING]) * size

    def _analyze_pn_distribution(self, packets: List[QUICPacket]) -> Dict[str, Any]:
        """Analyze packet number distribution."""
        if not packets:
            return {}

        pn_by_type = {}
        for packet in packets:
            pn_type = packet.packet_type.name
            if pn_type not in pn_by_type:
                pn_by_type[pn_type] = []
            pn_by_type[pn_type].append(packet.packet_number)

        analysis = {}
        for pn_type, pns in pn_by_type.items():
            if pns:
                analysis[pn_type] = {
                    "min": min(pns),
                    "max": max(pns),
                    "count": len(pns),
                    "unique": len(set(pns)),
                    "duplicates": len(pns) - len(set(pns)),
                }

        return analysis


@register_attack
class QUICPacketCoalescingAttack(BaseQUICAttack):
    """
    Advanced QUIC Packet Coalescing Attack.

    Combines multiple QUIC packets in sophisticated ways:
    - Mixed encryption levels in single datagram
    - Strategic padding placement
    - Frame reordering within packets
    - Datagram size manipulation
    """

    @property
    def name(self) -> str:
        return "quic_advanced_coalescing"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Advanced packet coalescing to evade DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute packet coalescing attack."""
        start_time = time.time()

        try:
            # Parameters
            coalescing_strategy = context.params.get("strategy", "mixed_types")
            target_size = context.params.get("target_size", 1200)
            add_decoy_frames = context.params.get("add_decoy_frames", True)

            # Convert payload to packets
            base_packets = self._convert_to_quic_packets(context.payload)

            # Apply coalescing strategy
            if coalescing_strategy == "mixed_types":
                segments = self._coalesce_mixed_types(base_packets, target_size)
            elif coalescing_strategy == "size_padding":
                segments = self._coalesce_with_size_padding(base_packets, target_size)
            elif coalescing_strategy == "frame_stuffing":
                segments = self._coalesce_with_frame_stuffing(
                    base_packets, target_size, add_decoy_frames
                )
            else:
                segments = self._basic_coalescing(base_packets, target_size)

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "coalescing_strategy": coalescing_strategy,
                    "original_packets": len(base_packets),
                    "coalesced_datagrams": len(segments),
                    "avg_datagram_size": total_bytes / len(segments) if segments else 0,
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC Coalescing ({coalescing_strategy})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _coalesce_mixed_types(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """Coalesce packets of different types in single datagram."""
        segments = []

        # Group packets by type
        by_type = {}
        for packet in packets:
            ptype = packet.packet_type
            if ptype not in by_type:
                by_type[ptype] = []
            by_type[ptype].append(packet)

        # Create datagrams with mixed types
        while any(by_type.values()):
            datagram = b""

            # Try to include one packet of each type
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

    def _coalesce_with_size_padding(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """Coalesce packets and pad to specific sizes."""
        segments = []

        for packet in packets:
            packet_bytes = packet.to_bytes()

            # Pad to various target sizes to confuse size-based analysis
            if len(packet_bytes) < target_size:
                padding_size = target_size - len(packet_bytes)

                # Create padding frame
                padding_frame = bytes([QUICFrameType.PADDING]) * padding_size

                # Rebuild packet with padding
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

    def _coalesce_with_frame_stuffing(
        self, packets: List[QUICPacket], target_size: int, add_decoy: bool
    ) -> List[Tuple[bytes, int]]:
        """Stuff packets with additional frames."""
        segments = []

        for packet in packets:
            # Add various frames to packet
            enhanced_payload = packet.payload

            if add_decoy:
                # Add PING frame
                enhanced_payload += bytes([QUICFrameType.PING])

                # Add MAX_DATA frame with random value
                max_data_frame = bytes([QUICFrameType.MAX_DATA])
                max_data_frame += QUICFrame._encode_varint(
                    random.randint(1000000, 2000000)
                )
                enhanced_payload += max_data_frame

                # Add NEW_TOKEN frame
                token = secrets.token_bytes(32)
                new_token_frame = bytes([QUICFrameType.NEW_TOKEN])
                new_token_frame += QUICFrame._encode_varint(len(token))
                new_token_frame += token
                enhanced_payload += new_token_frame

            # Create enhanced packet
            enhanced_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=packet.connection_id,
                packet_number=packet.packet_number,
                payload=enhanced_payload,
                version=packet.version,
            )

            segments.append((enhanced_packet.to_bytes(), 0))

        return segments

    def _basic_coalescing(
        self, packets: List[QUICPacket], target_size: int
    ) -> List[Tuple[bytes, int]]:
        """Basic coalescing strategy."""
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


@register_attack
class QUICMigrationSimulation(BaseQUICAttack):
    """
    QUIC Connection Migration Simulation.

    Simulates complex migration scenarios:
    - Path validation with challenges/responses
    - Multi-path simulation
    - NAT rebinding simulation
    - Coordinated CID and path changes
    """

    @property
    def name(self) -> str:
        return "quic_migration_simulation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Simulates QUIC connection migration to evade tracking"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute migration simulation."""
        start_time = time.time()

        try:
            # Parameters
            migration_type = context.params.get("migration_type", "full_migration")
            path_count = context.params.get("path_count", 3)
            validate_paths = context.params.get("validate_paths", True)

            # Convert payload to packets
            base_packets = self._convert_to_quic_packets(context.payload)

            # Apply migration simulation
            if migration_type == "full_migration":
                migrated_packets = self._simulate_full_migration(
                    base_packets, path_count, validate_paths
                )
            elif migration_type == "nat_rebinding":
                migrated_packets = self._simulate_nat_rebinding(base_packets)
            elif migration_type == "multipath":
                migrated_packets = self._simulate_multipath(base_packets, path_count)
            else:
                migrated_packets = base_packets

            # Generate segments
            segments = [(packet.to_bytes(), 0) for packet in migrated_packets]

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "migration_type": migration_type,
                    "path_count": path_count,
                    "migrations_simulated": self._count_migrations(migrated_packets),
                    "path_validations": sum(
                        1
                        for p in migrated_packets
                        if self._is_path_validation_frame(p.payload)
                    ),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC Migration ({migration_type})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _simulate_full_migration(
        self, packets: List[QUICPacket], path_count: int, validate: bool
    ) -> List[QUICPacket]:
        """Simulate full connection migration with path validation."""
        migrated_packets = []

        # Create different "paths" (simulated by different CIDs)
        paths = [secrets.token_bytes(8) for _ in range(path_count)]
        current_path = 0

        migration_points = [
            len(packets) // (path_count + 1) * i for i in range(1, path_count + 1)
        ]

        for i, packet in enumerate(packets):
            # Check if we should migrate
            if i in migration_points:
                old_path = current_path
                current_path = (current_path + 1) % len(paths)

                if validate:
                    # Send PATH_CHALLENGE on old path
                    challenge_data = secrets.token_bytes(8)
                    challenge_frame = self._create_path_challenge_frame(challenge_data)

                    challenge_packet = QUICPacket(
                        packet_type=QUICPacketType.ONE_RTT,
                        connection_id=paths[old_path],
                        packet_number=packet.packet_number + 10000,
                        payload=challenge_frame,
                    )
                    migrated_packets.append(challenge_packet)

                    # Send PATH_RESPONSE on new path
                    response_frame = self._create_path_response_frame(challenge_data)

                    response_packet = QUICPacket(
                        packet_type=QUICPacketType.ONE_RTT,
                        connection_id=paths[current_path],
                        packet_number=packet.packet_number + 10001,
                        payload=response_frame,
                    )
                    migrated_packets.append(response_packet)

            # Regular packet on current path
            migrated_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=paths[current_path],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            migrated_packets.append(migrated_packet)

        return migrated_packets

    def _simulate_nat_rebinding(self, packets: List[QUICPacket]) -> List[QUICPacket]:
        """Simulate NAT rebinding scenario."""
        migrated_packets = []

        # Simulate changing "source port" by using different CIDs
        original_cid = secrets.token_bytes(8)
        rebind_cid = secrets.token_bytes(8)

        rebind_point = len(packets) // 2

        for i, packet in enumerate(packets):
            if i == rebind_point:
                # Add probe packet from "new binding"
                probe_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=rebind_cid,
                    packet_number=packet.packet_number + 5000,
                    payload=bytes([QUICFrameType.PING]),  # PING frame
                )
                migrated_packets.append(probe_packet)

            # Use appropriate CID based on position
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

    def _simulate_multipath(
        self, packets: List[QUICPacket], path_count: int
    ) -> List[QUICPacket]:
        """Simulate multipath QUIC behavior."""
        migrated_packets = []

        # Create multiple paths
        paths = [secrets.token_bytes(8) for _ in range(path_count)]

        # Distribute packets across paths
        for i, packet in enumerate(packets):
            # Round-robin distribution with occasional duplication
            primary_path = i % path_count

            # Send on primary path
            primary_packet = QUICPacket(
                packet_type=packet.packet_type,
                connection_id=paths[primary_path],
                packet_number=packet.packet_number,
                payload=packet.payload,
                version=packet.version,
            )
            migrated_packets.append(primary_packet)

            # Occasionally duplicate on another path (redundancy)
            if random.random() < 0.1:  # 10% duplication
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

    def _create_path_challenge_frame(self, data: bytes) -> bytes:
        """Create PATH_CHALLENGE frame."""
        frame = bytes([QUICFrameType.PATH_CHALLENGE])
        frame += data[:8]  # Exactly 8 bytes
        return frame

    def _create_path_response_frame(self, data: bytes) -> bytes:
        """Create PATH_RESPONSE frame."""
        frame = bytes([QUICFrameType.PATH_RESPONSE])
        frame += data[:8]  # Echo the challenge data
        return frame

    def _is_path_validation_frame(self, payload: bytes) -> bool:
        """Check if payload contains path validation frames."""
        if not payload:
            return False

        frame_type = payload[0]
        return frame_type in [QUICFrameType.PATH_CHALLENGE, QUICFrameType.PATH_RESPONSE]

    def _count_migrations(self, packets: List[QUICPacket]) -> int:
        """Count number of connection migrations."""
        if not packets:
            return 0

        migrations = 0
        last_cid = packets[0].connection_id

        for packet in packets[1:]:
            if packet.connection_id != last_cid:
                migrations += 1
                last_cid = packet.connection_id

        return migrations


@register_attack
class QUICHTTP3FullSession(BaseQUICAttack):
    """
    QUIC/HTTP3 Full Session Simulation.

    Simulates a complete HTTP/3 session including:
    - SETTINGS exchange
    - QPACK dynamic table updates
    - Multiple concurrent streams
    - Server push simulation
    - Priority updates
    """

    @property
    def name(self) -> str:
        return "quic_http3_full_session"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Simulates full HTTP/3 session to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/3 session simulation."""
        start_time = time.time()

        try:
            # Parameters
            stream_count = context.params.get("stream_count", 3)
            use_qpack_dynamic = context.params.get("use_qpack_dynamic", True)
            simulate_push = context.params.get("simulate_push", True)

            # Create full HTTP/3 session
            session_packets = self._create_http3_session(
                context.payload,
                context.domain,
                stream_count,
                use_qpack_dynamic,
                simulate_push,
            )

            # Generate segments
            segments = [(packet.to_bytes(), 0) for packet in session_packets]

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "stream_count": stream_count,
                    "total_packets": len(session_packets),
                    "http3_frames": self._count_http3_frames(session_packets),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used="QUIC/HTTP3 Full Session",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_http3_session(
        self,
        payload: bytes,
        domain: str,
        stream_count: int,
        use_qpack_dynamic: bool,
        simulate_push: bool,
    ) -> List[QUICPacket]:
        """Create complete HTTP/3 session."""
        packets = []
        connection_id = secrets.token_bytes(8)
        packet_number = 0

        # 1. Control streams setup (stream 0, 2, 3)
        # Create SETTINGS frame on control stream
        settings_frame = self._create_http3_settings_frame()
        settings_stream = self._create_stream_frame(0, settings_frame)

        settings_packet = QUICPacket(
            packet_type=QUICPacketType.ONE_RTT,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=settings_stream,
        )
        packets.append(settings_packet)
        packet_number += 1

        # 2. QPACK encoder/decoder streams
        if use_qpack_dynamic:
            # Encoder stream (stream 2)
            encoder_data = self._create_qpack_encoder_stream()
            encoder_stream = self._create_stream_frame(2, encoder_data)

            encoder_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=encoder_stream,
            )
            packets.append(encoder_packet)
            packet_number += 1

        # 3. Create multiple request streams
        stream_id = 4  # First client-initiated bidirectional stream

        for i in range(stream_count):
            # Create HTTP/3 request
            headers = {
                ":method": "GET",
                ":scheme": "https",
                ":authority": domain,
                ":path": f"/stream_{i}",
                "user-agent": "QUIC-Bypass/1.0",
                "accept": "*/*",
            }

            headers_frame = self._create_http3_headers_frame(headers)

            # Split payload across streams
            chunk_size = len(payload) // stream_count
            chunk_start = i * chunk_size
            chunk_end = (
                chunk_start + chunk_size if i < stream_count - 1 else len(payload)
            )
            chunk = payload[chunk_start:chunk_end]

            # Create DATA frame
            data_frame = self._create_http3_data_frame(chunk)

            # Combine frames
            stream_data = headers_frame + data_frame

            # Create STREAM frame
            stream_frame = self._create_stream_frame(stream_id, stream_data, fin=True)

            stream_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=stream_frame,
            )
            packets.append(stream_packet)
            packet_number += 1

            stream_id += 4  # Next client-initiated bidirectional stream

        # 4. Simulate server push if requested
        if simulate_push:
            # PUSH_PROMISE frame
            push_id = 0
            push_headers = {
                ":method": "GET",
                ":scheme": "https",
                ":authority": domain,
                ":path": "/pushed_resource",
            }

            push_promise_frame = self._create_push_promise_frame(push_id, push_headers)
            push_stream = self._create_stream_frame(
                1, push_promise_frame
            )  # Server stream

            push_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=push_stream,
            )
            packets.append(push_packet)
            packet_number += 1

        # 5. Add some PRIORITY_UPDATE frames
        for i in range(stream_count):
            priority_frame = self._create_priority_update_frame(4 + i * 4, i * 10)
            priority_stream = self._create_stream_frame(0, priority_frame)

            priority_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=priority_stream,
            )
            packets.append(priority_packet)
            packet_number += 1

        return packets

    def _create_http3_data_frame(self, data: bytes) -> bytes:
        """Create HTTP/3 DATA frame."""
        frame_type = QUICFrame._encode_varint(0x00)  # DATA frame
        length = QUICFrame._encode_varint(len(data))
        return frame_type + length + data

    def _create_qpack_encoder_stream(self) -> bytes:
        """Create QPACK encoder stream data."""
        # Insert some entries into dynamic table
        stream_data = b""

        # Insert literal with name reference
        stream_data += b"\x80"  # Insert with name reference
        stream_data += b"\x10"  # Dynamic table capacity
        stream_data += QUICFrame._encode_varint(4096)

        return stream_data

    def _create_push_promise_frame(
        self, push_id: int, headers: Dict[str, str]
    ) -> bytes:
        """Create PUSH_PROMISE frame."""
        frame_type = QUICFrame._encode_varint(0x05)  # PUSH_PROMISE

        # Encode push ID
        push_id_encoded = QUICFrame._encode_varint(push_id)

        # Encode headers (simplified)
        encoded_headers = self._encode_qpack_headers(headers)

        length = QUICFrame._encode_varint(len(push_id_encoded) + len(encoded_headers))

        return frame_type + length + push_id_encoded + encoded_headers

    def _create_priority_update_frame(self, stream_id: int, priority: int) -> bytes:
        """Create PRIORITY_UPDATE frame."""
        frame_type = QUICFrame._encode_varint(0x0F)  # PRIORITY_UPDATE

        prioritized_element_type = 0x00  # REQUEST_STREAM
        prioritized_element_id = QUICFrame._encode_varint(stream_id)

        # Priority Field Value (simplified)
        priority_value = f"u={priority}".encode()

        content = (
            bytes([prioritized_element_type]) + prioritized_element_id + priority_value
        )
        length = QUICFrame._encode_varint(len(content))

        return frame_type + length + content

    def _encode_qpack_headers(self, headers: Dict[str, str]) -> bytes:
        """Simplified QPACK header encoding."""
        encoded = b""

        for name, value in headers.items():
            # Literal with name reference (simplified)
            encoded += b"\x50"
            encoded += struct.pack(">B", len(name))
            encoded += name.encode()
            encoded += struct.pack(">B", len(value))
            encoded += value.encode()

        return encoded

    def _count_http3_frames(self, packets: List[QUICPacket]) -> Dict[str, int]:
        """Count HTTP/3 frame types in packets."""
        frame_counts = {
            "DATA": 0,
            "HEADERS": 0,
            "SETTINGS": 0,
            "PUSH_PROMISE": 0,
            "PRIORITY_UPDATE": 0,
        }

        # Simplified counting - would need proper parsing in production
        for packet in packets:
            payload = packet.payload
            if b"\x00" in payload:
                frame_counts["DATA"] += 1
            if b"\x01" in payload:
                frame_counts["HEADERS"] += 1
            if b"\x04" in payload:
                frame_counts["SETTINGS"] += 1
            if b"\x05" in payload:
                frame_counts["PUSH_PROMISE"] += 1
            if b"\x0f" in payload:
                frame_counts["PRIORITY_UPDATE"] += 1

        return frame_counts


# Добавить в конец файла quic_attacks.py


@register_attack
class QUICZeroRTTEarlyDataAttack(BaseQUICAttack):
    """
    QUIC 0-RTT Early Data Attack.

    Implements sophisticated 0-RTT techniques:
    - Sending legitimate data in 0-RTT packets before handshake
    - Mixing 0-RTT with garbage data to confuse DPI
    - Overlapping 0-RTT and 1-RTT packet number spaces
    - Using 0-RTT for protocol obfuscation
    """

    @property
    def name(self) -> str:
        return "quic_0rtt_early_data"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses QUIC 0-RTT early data to bypass DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC 0-RTT early data attack."""
        start_time = time.time()

        try:
            # Parameters
            early_data_strategy = context.params.get("strategy", "legitimate_early")
            mix_with_garbage = context.params.get("mix_with_garbage", True)
            early_data_ratio = context.params.get("early_data_ratio", 0.5)
            use_psk = context.params.get("use_psk", True)

            # Generate session ticket/PSK for 0-RTT
            session_ticket = self._generate_session_ticket(context.domain)

            # Split payload for 0-RTT and 1-RTT
            early_data_size = int(len(context.payload) * early_data_ratio)
            early_data = context.payload[:early_data_size]
            remaining_data = context.payload[early_data_size:]

            # Create packets based on strategy
            if early_data_strategy == "legitimate_early":
                packets = self._create_legitimate_0rtt_flow(
                    early_data, remaining_data, session_ticket, context.domain
                )
            elif early_data_strategy == "garbage_injection":
                packets = self._create_garbage_injected_0rtt(
                    early_data, remaining_data, session_ticket, mix_with_garbage
                )
            elif early_data_strategy == "overlapping_spaces":
                packets = self._create_overlapping_0rtt_1rtt(
                    early_data, remaining_data, session_ticket
                )
            elif early_data_strategy == "protocol_masquerade":
                packets = self._create_protocol_masquerade_0rtt(
                    context.payload, session_ticket, context.domain
                )
            else:
                packets = self._create_simple_0rtt_flow(
                    early_data, remaining_data, session_ticket
                )

            # Generate segments
            segments = [(packet.to_bytes(), 0) for packet in packets]

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "early_data_strategy": early_data_strategy,
                    "early_data_bytes": early_data_size,
                    "zero_rtt_packets": sum(
                        1 for p in packets if p.packet_type == QUICPacketType.ZERO_RTT
                    ),
                    "mix_with_garbage": mix_with_garbage,
                    "session_ticket_size": len(session_ticket),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC 0-RTT ({early_data_strategy})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _generate_session_ticket(self, domain: str) -> bytes:
        """Generate QUIC session ticket for 0-RTT."""
        # Simplified ticket generation
        ticket_data = b"QUIC_TICKET_" + domain.encode()[:20]
        ticket_data += secrets.token_bytes(32)  # Random session key
        ticket_data += struct.pack(">I", int(time.time()))  # Timestamp
        ticket_data += struct.pack(">I", 3600)  # Lifetime
        return ticket_data

    def _create_legitimate_0rtt_flow(
        self,
        early_data: bytes,
        remaining_data: bytes,
        session_ticket: bytes,
        domain: str,
    ) -> List[QUICPacket]:
        """Create legitimate 0-RTT flow with proper handshake."""
        packets = []
        connection_id = secrets.token_bytes(8)

        # 1. Initial packet with crypto handshake
        client_hello = self._create_quic_client_hello(domain, session_ticket)
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(client_hello),
        )
        packets.append(initial_packet)

        # 2. 0-RTT packets with early data
        packet_number = 0
        for chunk in self._chunk_data(early_data, 1000):
            zero_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),  # Stream 4 for early data
            )
            packets.append(zero_rtt_packet)
            packet_number += 1

        # 3. 1-RTT packets for remaining data (after handshake)
        for chunk in self._chunk_data(remaining_data, 1000):
            one_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(0, chunk),
            )
            packets.append(one_rtt_packet)
            packet_number += 1

        return packets

    def _create_garbage_injected_0rtt(
        self,
        early_data: bytes,
        remaining_data: bytes,
        session_ticket: bytes,
        mix_garbage: bool,
    ) -> List[QUICPacket]:
        """Create 0-RTT flow with garbage data injection."""
        packets = []
        connection_id = secrets.token_bytes(8)

        # Initial packet
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),  # Fake crypto
        )
        packets.append(initial_packet)

        # Mix legitimate early data with garbage
        packet_number = 0

        if mix_garbage:
            # Inject garbage 0-RTT packets
            for _ in range(3):
                garbage_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=packet_number,
                    payload=self._create_garbage_frames(),
                )
                packets.append(garbage_packet)
                packet_number += 1

        # Real early data
        for chunk in self._chunk_data(early_data, 800):
            data_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(data_packet)
            packet_number += 1

            # Inject garbage between real data
            if mix_garbage and random.random() < 0.3:
                garbage_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=packet_number,
                    payload=self._create_garbage_frames(),
                )
                packets.append(garbage_packet)
                packet_number += 1

        # 1-RTT data
        for chunk in self._chunk_data(remaining_data, 1000):
            one_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(0, chunk),
            )
            packets.append(one_rtt_packet)
            packet_number += 1

        return packets

    def _create_overlapping_0rtt_1rtt(
        self, early_data: bytes, remaining_data: bytes, session_ticket: bytes
    ) -> List[QUICPacket]:
        """Create overlapping 0-RTT and 1-RTT packet number spaces."""
        packets = []
        connection_id = secrets.token_bytes(8)

        # Use same packet numbers for different encryption levels
        zero_rtt_pn = 0
        one_rtt_pn = 0

        # Initial packet
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial_packet)

        # Interleave 0-RTT and 1-RTT packets with overlapping numbers
        early_chunks = list(self._chunk_data(early_data, 500))
        remaining_chunks = list(self._chunk_data(remaining_data, 500))

        max_chunks = max(len(early_chunks), len(remaining_chunks))

        for i in range(max_chunks):
            # 0-RTT packet
            if i < len(early_chunks):
                zero_rtt_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=zero_rtt_pn,
                    payload=self._create_stream_frame(4, early_chunks[i]),
                )
                packets.append(zero_rtt_packet)
                zero_rtt_pn += 1

            # 1-RTT packet with same packet number
            if i < len(remaining_chunks):
                one_rtt_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=connection_id,
                    packet_number=one_rtt_pn,  # Same as 0-RTT!
                    payload=self._create_stream_frame(0, remaining_chunks[i]),
                )
                packets.append(one_rtt_packet)
                one_rtt_pn += 1

            # Occasionally use same packet number for both
            if i % 3 == 0:
                confusion_packet = QUICPacket(
                    packet_type=random.choice(
                        [QUICPacketType.ZERO_RTT, QUICPacketType.ONE_RTT]
                    ),
                    connection_id=connection_id,
                    packet_number=min(zero_rtt_pn, one_rtt_pn),
                    payload=bytes([QUICFrameType.PING]),
                )
                packets.append(confusion_packet)

        return packets

    def _create_protocol_masquerade_0rtt(
        self, payload: bytes, session_ticket: bytes, domain: str
    ) -> List[QUICPacket]:
        """Use 0-RTT to masquerade as different protocol."""
        packets = []
        connection_id = secrets.token_bytes(8)

        # Create Initial that looks like TLS
        tls_like_hello = self._create_tls_like_client_hello(domain)
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(tls_like_hello),
        )
        packets.append(initial_packet)

        # Send HTTP-like data in 0-RTT
        http_request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + domain.encode() + b"\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"\r\n"
        )

        # First 0-RTT packet with HTTP-like data
        http_packet = QUICPacket(
            packet_type=QUICPacketType.ZERO_RTT,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_stream_frame(4, http_request),
        )
        packets.append(http_packet)

        # Then send actual payload in 0-RTT
        packet_number = 1
        for chunk in self._chunk_data(payload, 1000):
            data_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(data_packet)
            packet_number += 1

        return packets

    def _create_simple_0rtt_flow(
        self, early_data: bytes, remaining_data: bytes, session_ticket: bytes
    ) -> List[QUICPacket]:
        """Create simple 0-RTT flow."""
        packets = []
        connection_id = secrets.token_bytes(8)
        packet_number = 0

        # Initial packet
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial_packet)
        packet_number += 1

        # 0-RTT data
        for chunk in self._chunk_data(early_data, 1200):
            zero_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(zero_rtt_packet)
            packet_number += 1

        # 1-RTT data
        for chunk in self._chunk_data(remaining_data, 1200):
            one_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(0, chunk),
            )
            packets.append(one_rtt_packet)
            packet_number += 1

        return packets

    def _create_quic_client_hello(self, domain: str, session_ticket: bytes) -> bytes:
        """Create QUIC ClientHello with 0-RTT support."""
        # Simplified QUIC crypto handshake data
        client_hello = b"CHLO"  # Tag
        client_hello += struct.pack("<I", 2)  # Number of entries

        # SNI
        client_hello += b"SNI\x00"
        sni_data = struct.pack("<I", len(domain)) + domain.encode()
        client_hello += struct.pack("<I", len(sni_data)) + sni_data

        # Session ticket for 0-RTT
        client_hello += b"STK\x00"
        client_hello += struct.pack("<I", len(session_ticket)) + session_ticket

        return client_hello

    def _create_garbage_frames(self) -> bytes:
        """Create garbage frames to confuse DPI."""
        frames = b""

        # Random frame types that might confuse DPI
        garbage_types = [
            (0x1E, secrets.token_bytes(random.randint(10, 50))),  # Unknown frame
            (0x30, b"GARBAGE_DATA_" + secrets.token_bytes(20)),  # Extension frame
            (QUICFrameType.PADDING, b"\x00" * random.randint(50, 200)),  # Large padding
        ]

        for frame_type, data in random.sample(garbage_types, 2):
            frames += bytes([frame_type])
            if frame_type != QUICFrameType.PADDING:
                frames += QUICFrame._encode_varint(len(data))
                frames += data
            else:
                frames += data

        return frames

    def _create_tls_like_client_hello(self, domain: str) -> bytes:
        """Create data that looks like TLS ClientHello."""
        # TLS-like handshake header
        tls_hello = b"\x16\x03\x03"  # TLS handshake, version

        # Length (2 bytes)
        hello_data = b"\x01"  # ClientHello
        hello_data += b"\x00\x00\xfe"  # Length placeholder
        hello_data += b"\x03\x03"  # TLS 1.2
        hello_data += secrets.token_bytes(32)  # Random
        hello_data += b"\x20" + secrets.token_bytes(32)  # Session ID

        # Cipher suites
        hello_data += b"\x00\x02\x13\x01"  # TLS_AES_128_GCM_SHA256

        # Compression
        hello_data += b"\x01\x00"

        # Extensions with SNI
        ext_data = b"\x00\x00"  # SNI extension
        sni_list = struct.pack(">H", len(domain) + 3)
        sni_list += b"\x00" + struct.pack(">H", len(domain)) + domain.encode()
        ext_data += struct.pack(">H", len(sni_list)) + sni_list

        hello_data += struct.pack(">H", len(ext_data)) + ext_data

        # Fix length
        hello_data = (
            hello_data[:1] + struct.pack(">I", len(hello_data) - 4)[1:] + hello_data[4:]
        )

        tls_hello += struct.pack(">H", len(hello_data)) + hello_data

        return tls_hello

    def _chunk_data(self, data: bytes, chunk_size: int) -> List[bytes]:
        """Split data into chunks."""
        return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


@register_attack
class QUICMixedEncryptionLevelAttack(BaseQUICAttack):
    """
    QUIC Mixed Encryption Level Attack.

    Sends packets with different encryption levels (0-RTT, 1-RTT) in the same
    UDP datagram to confuse DPI packet parsers.
    """

    @property
    def name(self) -> str:
        return "quic_mixed_encryption"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Mixes QUIC packets with different encryption levels in single datagram"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute mixed encryption level attack."""
        start_time = time.time()

        try:
            # Parameters
            mixing_strategy = context.params.get("mixing_strategy", "interleaved")
            include_handshake = context.params.get("include_handshake", True)
            randomize_order = context.params.get("randomize_order", True)

            # Convert payload to base packets
            base_packets = self._convert_to_quic_packets(context.payload)

            # Create packets with different encryption levels
            mixed_packets = []

            if include_handshake:
                # Add Initial and Handshake packets
                mixed_packets.extend(self._create_handshake_packets())

            # Apply mixing strategy
            if mixing_strategy == "interleaved":
                mixed_packets.extend(self._create_interleaved_packets(base_packets))
            elif mixing_strategy == "burst":
                mixed_packets.extend(self._create_burst_packets(base_packets))
            elif mixing_strategy == "nested":
                mixed_packets.extend(self._create_nested_packets(base_packets))
            else:
                mixed_packets.extend(base_packets)

            # Randomize packet order if requested
            if randomize_order:
                random.shuffle(mixed_packets)

            # Coalesce into datagrams
            segments = self._create_mixed_datagrams(mixed_packets)

            total_bytes = sum(len(seg[0]) for seg in segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(segments),
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "mixing_strategy": mixing_strategy,
                    "total_packets": len(mixed_packets),
                    "datagrams": len(segments),
                    "encryption_levels": self._count_encryption_levels(mixed_packets),
                    "segments": segments if context.engine_type != "local" else None,
                },
                technique_used=f"QUIC Mixed Encryption ({mixing_strategy})",
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_handshake_packets(self) -> List[QUICPacket]:
        """Create Initial and Handshake packets."""
        packets = []
        connection_id = secrets.token_bytes(8)

        # Initial packet
        initial = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial)

        # Handshake packet
        handshake = QUICPacket(
            packet_type=QUICPacketType.HANDSHAKE,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(150)),
        )
        packets.append(handshake)

        return packets

    def _create_interleaved_packets(
        self, base_packets: List[QUICPacket]
    ) -> List[QUICPacket]:
        """Create interleaved 0-RTT and 1-RTT packets."""
        mixed = []

        for i, packet in enumerate(base_packets):
            # Alternate between 0-RTT and 1-RTT
            if i % 2 == 0:
                zero_rtt = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=packet.connection_id,
                    packet_number=i,
                    payload=packet.payload,
                )
                mixed.append(zero_rtt)
            else:
                one_rtt = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=packet.connection_id,
                    packet_number=i,
                    payload=packet.payload,
                )
                mixed.append(one_rtt)

        return mixed

    def _create_burst_packets(self, base_packets: List[QUICPacket]) -> List[QUICPacket]:
        """Create bursts of same encryption level."""
        mixed = []
        burst_size = 3

        for i, packet in enumerate(base_packets):
            burst_type = (i // burst_size) % 3

            if burst_type == 0:
                packet_type = QUICPacketType.ZERO_RTT
            elif burst_type == 1:
                packet_type = QUICPacketType.ONE_RTT
            else:
                packet_type = QUICPacketType.HANDSHAKE

            mixed_packet = QUICPacket(
                packet_type=packet_type,
                connection_id=packet.connection_id,
                packet_number=i,
                payload=packet.payload,
            )
            mixed.append(mixed_packet)

        return mixed

    def _create_nested_packets(
        self, base_packets: List[QUICPacket]
    ) -> List[QUICPacket]:
        """Create nested encryption levels (experimental)."""
        mixed = []

        for i, packet in enumerate(base_packets):
            # Create all encryption levels for same data
            for ptype in [QUICPacketType.ZERO_RTT, QUICPacketType.ONE_RTT]:
                nested = QUICPacket(
                    packet_type=ptype,
                    connection_id=packet.connection_id,
                    packet_number=i,
                    payload=packet.payload,
                )
                mixed.append(nested)

        return mixed

    def _create_mixed_datagrams(
        self, packets: List[QUICPacket]
    ) -> List[Tuple[bytes, int]]:
        """Create datagrams with mixed encryption levels."""
        segments = []
        max_datagram_size = 1200

        i = 0
        while i < len(packets):
            datagram = b""
            current_size = 0

            # Try to mix different encryption levels in same datagram
            encryption_levels_in_datagram = set()

            while i < len(packets) and current_size < max_datagram_size:
                packet_bytes = packets[i].to_bytes()

                if current_size + len(packet_bytes) <= max_datagram_size:
                    datagram += packet_bytes
                    current_size += len(packet_bytes)
                    encryption_levels_in_datagram.add(packets[i].packet_type)
                    i += 1

                    # Try to include different encryption levels
                    if len(encryption_levels_in_datagram) >= 2:
                        break
                else:
                    break

            if datagram:
                segments.append((datagram, 0))

        return segments

    def _count_encryption_levels(self, packets: List[QUICPacket]) -> Dict[str, int]:
        """Count packets by encryption level."""
        counts = {}
        for packet in packets:
            level = packet.packet_type.name
            counts[level] = counts.get(level, 0) + 1
        return counts


# Utility function to integrate 0-RTT with other attacks
def create_0rtt_enhanced_attack(base_attack_name: str) -> type:
    """
    Factory to create 0-RTT enhanced versions of existing attacks.

    Example:
        ZeroRTTEnhancedCIDRotation = create_0rtt_enhanced_attack("quic_advanced_cid_rotation")
    """

    base_attack_class = AttackRegistry.get_attack(base_attack_name)
    if not base_attack_class:
        raise ValueError(f"Base attack {base_attack_name} not found")

    class ZeroRTTEnhancedAttack(base_attack_class):
        @property
        def name(self) -> str:
            return f"{base_attack_name}_0rtt_enhanced"

        @property
        def description(self) -> str:
            return f"{super().description} enhanced with 0-RTT early data"

        def execute(self, context: AttackContext) -> AttackResult:
            # Add 0-RTT parameters
            enhanced_params = context.params.copy()
            enhanced_params["include_0rtt"] = True
            enhanced_params["early_data_ratio"] = 0.3

            # Create new context with enhanced params
            enhanced_context = AttackContext(
                dst_ip=context.dst_ip,
                dst_port=context.dst_port,
                domain=context.domain,
                payload=context.payload,
                params=enhanced_params,
                debug=context.debug,
            )

            # Execute base attack
            result = super().execute(enhanced_context)

            # Add 0-RTT packets if successful
            if result.status == AttackStatus.SUCCESS:
                # Enhance with 0-RTT
                early_data_attack = QUICZeroRTTEarlyDataAttack()
                early_result = early_data_attack.execute(context)

                if early_result.status == AttackStatus.SUCCESS:
                    # Merge results
                    result.packets_sent += early_result.packets_sent
                    result.bytes_sent += early_result.bytes_sent
                    result.metadata.update(
                        {
                            "0rtt_enhanced": True,
                            "0rtt_packets": early_result.metadata.get(
                                "zero_rtt_packets", 0
                            ),
                        }
                    )

            return result

    # Register the enhanced attack
    register_attack(ZeroRTTEnhancedAttack)

    return ZeroRTTEnhancedAttack
