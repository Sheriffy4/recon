from __future__ import annotations

# core/bypass/attacks/http/quic_attacks.py
"""
QUIC/HTTP3 Protocol Attacks

Advanced attacks that manipulate QUIC protocol features to evade DPI detection.
Includes Connection ID manipulation, packet coalescing, migration techniques,
and advanced packet number space confusion.

Refactored Structure:
--------------------
This module has been refactored to improve maintainability and reduce code duplication.
Core QUIC protocol utilities have been extracted to the `quic_protocol` submodule:

- quic_protocol.encoding: Variable-length integer encoding, entropy calculation
- quic_protocol.frames: QUIC frame builders (STREAM, CRYPTO, HTTP3, etc.)
- quic_protocol.packets: Packet structures, builders, and utilities
- quic_protocol.session: HTTP3 session creation and QPACK encoding

Attack Classes:
--------------
- BaseQUICAttack: Abstract base class for all QUIC attacks
- AdvancedQUICConnectionIDRotation: CID rotation with multiple strategies
- AdvancedPacketNumberSpaceConfusion: Packet number manipulation
- QUICPacketCoalescingAttack: Packet coalescing techniques
- QUICMigrationSimulation: Connection migration simulation
- QUICHTTP3FullSession: Full HTTP3 session simulation
- QUICZeroRTTEarlyDataAttack: 0-RTT early data techniques
- QUICMixedEncryptionLevelAttack: Mixed encryption level attacks

Refactoring Benefits:
--------------------
- Reduced main file from 2017 to ~1700 LOC (-15%)
- Eliminated 16+ unused/duplicate methods
- Resolved 12+ code smells (feature envy, god class)
- Improved testability and reusability
- Maintained full backward compatibility
"""

import asyncio
import time
import struct
import random
import secrets
from abc import abstractmethod
from typing import Any, Awaitable, Callable, List, Dict, Tuple, Optional, TypeVar

from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import AttackRegistry

# Import from new quic_protocol module (addresses SM1-SM12, UN1-UN11, UN16-UN17)
from core.bypass.attacks.http.quic_protocol import (
    QUICPacket,
    QUICFrame,
    QUICPacketType,
    QUICFrameType,
    generate_cid_pool,
    coalesce_packets,
    create_http3_session,
    convert_payload_to_quic_packets,
    analyze_pn_distribution,
    count_migrations,
    ConnectionIDRotationStrategy,
    PacketNumberConfusionStrategy,
    PacketCoalescingStrategy,
    MigrationSimulator,
)

_T = TypeVar("_T")


class BaseQUICAttack(BaseAttack):
    """
    Base class for QUIC attacks with common functionality.

    This is an abstract base class and should not be instantiated directly.
    Subclasses must implement the name and category properties.

    Note: Frame/packet building methods moved to quic_protocol module (SM3-SM6, UN7-UN10).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Attack name - must be implemented by subclasses."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Attack category - must be implemented by subclasses."""
        pass

    @property
    def required_params(self) -> List[str]:
        """Default required params for QUIC attacks."""
        return []

    @property
    def optional_params(self) -> dict:
        """Default optional params for QUIC attacks."""
        return {}

    def _is_quic_traffic(self, payload: bytes) -> bool:
        """Check if payload contains QUIC traffic."""
        if len(payload) < 1:
            return False
        first_byte = payload[0]
        return bool(first_byte & 128) or bool(first_byte & 64)

    def _convert_to_quic_packets(
        self,
        payload: bytes,
        connection_id: Optional[bytes] = None,
        chunk_size: int = 500,
    ) -> List[QUICPacket]:
        """
        Convert payload to QUIC packets.

        Note: Now uses extracted utility function for consistency.
        """
        return convert_payload_to_quic_packets(payload, connection_id, chunk_size)

    # ---------------------------------------------------------------------
    # Minimal frame builders (robustness / backward compatibility)
    # ---------------------------------------------------------------------
    # Some attacks in this module still call _create_stream_frame/_create_crypto_frame
    # after refactoring. Provide stable helpers here to avoid runtime errors.

    def _encode_varint(self, value: int) -> bytes:
        """
        Encode QUIC varint.
        Prefer quic_protocol implementation if present (QUICFrame._encode_varint),
        otherwise fall back to a local implementation.
        """
        try:
            # noinspection PyProtectedMember
            enc = getattr(QUICFrame, "_encode_varint", None)
            if callable(enc):
                return enc(int(value))
        except Exception:
            pass

        v = int(value)
        if v < 0:
            v = 0
        if v < (1 << 6):
            return bytes([(0b00 << 6) | v])
        if v < (1 << 14):
            v |= 0b01 << 14
            return struct.pack("!H", v)
        if v < (1 << 30):
            v |= 0b10 << 30
            return struct.pack("!I", v)
        if v < (1 << 62):
            v |= 0b11 << 62
            return struct.pack("!Q", v)
        # Cap to max representable (2^62-1)
        return self._encode_varint((1 << 62) - 1)

    def _create_crypto_frame(self, data: bytes, offset: int = 0) -> bytes:
        """
        Build a minimal QUIC CRYPTO frame.
        Format: type(0x06) + offset(varint) + length(varint) + data
        """
        # QUIC CRYPTO frame type is 0x06 in RFC 9000.
        frame_type = getattr(QUICFrameType, "CRYPTO", 0x06)
        data = data or b""
        return bytes([int(frame_type)]) + self._encode_varint(offset) + self._encode_varint(len(data)) + data

    def _create_stream_frame(self, stream_id: int, data: bytes, offset: int = 0) -> bytes:
        """
        Build a minimal QUIC STREAM frame.
        We set LEN bit=1 and OFFSET bit=(offset>0).
        Frame type base is 0x08 plus flags.
        """
        data = data or b""
        flags = 0
        if offset:
            flags |= 0x04  # OFF
        flags |= 0x02  # LEN
        frame_type = 0x08 | flags
        out = bytearray()
        out.append(frame_type)
        out += self._encode_varint(int(stream_id))
        if offset:
            out += self._encode_varint(int(offset))
        out += self._encode_varint(len(data))
        out += data
        return bytes(out)


@register_attack
class AdvancedQUICConnectionIDRotation(BaseQUICAttack):
    """
    Advanced QUIC Connection ID Rotation Attack.

    Implements sophisticated CID rotation strategies including:
    - Rapid rotation with proper NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames
    - Variable-length CIDs to confuse tracking
    - CID pools with entropy analysis evasion
    - Coordinated rotation with packet number spaces

    Refactored: Rotation logic extracted to ConnectionIDRotationStrategy
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = ConnectionIDRotationStrategy()

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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced CID rotation attack."""
        start_time = time.time()
        try:
            rotation_strategy = context.params.get("rotation_strategy", "aggressive")
            min_cid_length = context.params.get("min_cid_length", 4)
            max_cid_length = context.params.get("max_cid_length", 18)
            pool_size = context.params.get("pool_size", 20)
            use_zero_length = context.params.get("use_zero_length", True)

            # Generate CID pool
            cid_pool = generate_cid_pool(pool_size, min_cid_length, max_cid_length, use_zero_length)

            packets = self._convert_to_quic_packets(context.payload)

            # Delegate to strategy (addresses SM1-SM4, UN3-UN6)
            if rotation_strategy == "aggressive":
                rotated_packets = await self._strategy.apply_aggressive_rotation(packets, cid_pool)
            elif rotation_strategy == "entropy_based":
                rotated_packets = self._strategy.apply_entropy_based_rotation(packets, cid_pool)
            elif rotation_strategy == "coordinated":
                rotated_packets = self._strategy.apply_coordinated_rotation(packets, cid_pool)
            else:
                rotated_packets = self._strategy.apply_standard_rotation(packets, cid_pool)

            segments = [(packet.to_bytes(), 0) for packet in rotated_packets]
            total_bytes = sum((len(seg[0]) for seg in segments))
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
                    "unique_cids_used": len(set((p.connection_id for p in rotated_packets))),
                    "zero_length_cids": sum(
                        (1 for p in rotated_packets if len(p.connection_id) == 0)
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


@register_attack
class AdvancedPacketNumberSpaceConfusion(BaseQUICAttack):
    """
    Advanced QUIC Packet Number Space Confusion Attack.

    Implements sophisticated confusion techniques:
    - Mixed encryption levels in single datagram
    - Overlapping packet numbers across spaces
    - Out-of-order packet number sequences
    - Phantom packet number spaces

    Refactored: Confusion logic extracted to PacketNumberConfusionStrategy
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = PacketNumberConfusionStrategy()

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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced packet number confusion attack."""
        start_time = time.time()
        try:
            confusion_strategy = context.params.get("confusion_strategy", "mixed_spaces")
            use_coalescing = context.params.get("use_coalescing", True)
            max_pn_gap = context.params.get("max_pn_gap", 1000)

            base_packets = self._convert_to_quic_packets(context.payload)

            # Delegate to strategy (addresses SM5-SM8, UN7-UN10)
            if confusion_strategy == "mixed_spaces":
                confused_packets = self._strategy.apply_mixed_spaces_confusion(base_packets)
            elif confusion_strategy == "overlapping_pn":
                confused_packets = self._strategy.apply_overlapping_pn_confusion(base_packets)
            elif confusion_strategy == "phantom_spaces":
                confused_packets = self._strategy.apply_phantom_spaces_confusion(base_packets)
            elif confusion_strategy == "chaotic_ordering":
                confused_packets = self._strategy.apply_chaotic_ordering(base_packets, max_pn_gap)
            else:
                confused_packets = base_packets

            if use_coalescing:
                segments = coalesce_packets(confused_packets)
            else:
                segments = [(packet.to_bytes(), 0) for packet in confused_packets]

            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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
                    "pn_ranges": analyze_pn_distribution(confused_packets),
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


@register_attack
class QUICPacketCoalescingAttack(BaseQUICAttack):
    """
    Advanced QUIC Packet Coalescing Attack.

    Combines multiple QUIC packets in sophisticated ways:
    - Mixed encryption levels in single datagram
    - Strategic padding placement
    - Frame reordering within packets
    - Datagram size manipulation

    Refactored: Coalescing logic extracted to PacketCoalescingStrategy
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = PacketCoalescingStrategy()

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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute packet coalescing attack."""
        start_time = time.time()
        try:
            coalescing_strategy = context.params.get("strategy", "mixed_types")
            target_size = context.params.get("target_size", 1200)
            add_decoy_frames = context.params.get("add_decoy_frames", True)

            base_packets = self._convert_to_quic_packets(context.payload)

            # Delegate to strategy (addresses SM10-SM13, UN12-UN15)
            if coalescing_strategy == "mixed_types":
                segments = self._strategy.coalesce_mixed_types(base_packets, target_size)
            elif coalescing_strategy == "size_padding":
                segments = self._strategy.coalesce_with_size_padding(base_packets, target_size)
            elif coalescing_strategy == "frame_stuffing":
                segments = self._strategy.coalesce_with_frame_stuffing(
                    base_packets, target_size, add_decoy_frames
                )
            else:
                # Use extracted utility (addresses UN28)
                segments = coalesce_packets(base_packets, target_size)

            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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


@register_attack
class QUICMigrationSimulation(BaseQUICAttack):
    """
    QUIC Connection Migration Simulation.

    Simulates complex migration scenarios:
    - Path validation with challenges/responses
    - Multi-path simulation
    - NAT rebinding simulation
    - Coordinated CID and path changes

    Refactored: Migration logic extracted to MigrationSimulator
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._simulator = MigrationSimulator()

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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute migration simulation."""
        start_time = time.time()
        try:
            migration_type = context.params.get("migration_type", "full_migration")
            path_count = context.params.get("path_count", 3)
            validate_paths = context.params.get("validate_paths", True)
            base_packets = self._convert_to_quic_packets(context.payload)

            # Delegate to simulator (addresses SM14-SM17, UN16-UN20)
            if migration_type == "full_migration":
                migrated_packets = self._simulator.simulate_full_migration(
                    base_packets, path_count, validate_paths
                )
            elif migration_type == "nat_rebinding":
                migrated_packets = self._simulator.simulate_nat_rebinding(base_packets)
            elif migration_type == "multipath":
                migrated_packets = self._simulator.simulate_multipath(base_packets, path_count)
            else:
                migrated_packets = base_packets

            segments = [(packet.to_bytes(), 0) for packet in migrated_packets]
            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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
                    "migrations_simulated": count_migrations(migrated_packets),
                    "path_validations": sum(
                        (
                            1
                            for p in migrated_packets
                            if self._simulator.is_path_validation_frame(p.payload)
                        )
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

    Refactored: Session creation logic extracted to session.py module
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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/3 session simulation."""
        start_time = time.time()
        try:
            stream_count = context.params.get("stream_count", 3)
            use_qpack_dynamic = context.params.get("use_qpack_dynamic", True)
            simulate_push = context.params.get("simulate_push", True)

            # Use extracted function (addresses SM18-SM20, UN21-UN27)
            session_packets = create_http3_session(
                context.payload,
                context.domain,
                stream_count,
                use_qpack_dynamic,
                simulate_push,
            )

            segments = [(packet.to_bytes(), 0) for packet in session_packets]
            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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

    def _count_http3_frames(self, packets: List[QUICPacket]) -> Dict[str, int]:
        """Count HTTP/3 frame types in packets."""
        frame_counts = {
            "DATA": 0,
            "HEADERS": 0,
            "SETTINGS": 0,
            "PUSH_PROMISE": 0,
            "PRIORITY_UPDATE": 0,
        }
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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC 0-RTT early data attack."""
        start_time = time.time()
        try:
            early_data_strategy = context.params.get("strategy", "legitimate_early")
            mix_with_garbage = context.params.get("mix_with_garbage", True)
            early_data_ratio = context.params.get("early_data_ratio", 0.5)
            use_psk = context.params.get("use_psk", True)
            session_ticket = self._generate_session_ticket(context.domain)
            early_data_size = int(len(context.payload) * early_data_ratio)
            early_data = context.payload[:early_data_size]
            remaining_data = context.payload[early_data_size:]
            if early_data_strategy == "legitimate_early":
                packets = await self._create_legitimate_0rtt_flow(
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
                packets = self._create_simple_0rtt_flow(early_data, remaining_data, session_ticket)
            segments = [(packet.to_bytes(), 0) for packet in packets]
            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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
                        (1 for p in packets if p.packet_type == QUICPacketType.ZERO_RTT)
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
        ticket_data = b"QUIC_TICKET_" + domain.encode()[:20]
        ticket_data += secrets.token_bytes(32)
        ticket_data += struct.pack(">I", int(time.time()))
        ticket_data += struct.pack(">I", 3600)
        return ticket_data

    async def _create_legitimate_0rtt_flow(
        self,
        early_data: bytes,
        remaining_data: bytes,
        session_ticket: bytes,
        domain: str,
    ) -> List[QUICPacket]:
        """Create legitimate 0-RTT flow with proper handshake."""
        packets = []
        connection_id = secrets.token_bytes(8)
        client_hello = self._create_quic_client_hello(domain, session_ticket)
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(client_hello),
        )
        packets.append(initial_packet)
        packet_number = 0
        for chunk in self._chunk_data(early_data, 1000):
            zero_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(zero_rtt_packet)
            packet_number += 1
            await asyncio.sleep(0)
        for chunk in self._chunk_data(remaining_data, 1000):
            one_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ONE_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(0, chunk),
            )
            packets.append(one_rtt_packet)
            packet_number += 1
            await asyncio.sleep(0)
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
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial_packet)
        packet_number = 0
        if mix_garbage:
            for _ in range(3):
                garbage_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=packet_number,
                    payload=self._create_garbage_frames(),
                )
                packets.append(garbage_packet)
                packet_number += 1
        for chunk in self._chunk_data(early_data, 800):
            data_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(data_packet)
            packet_number += 1
            if mix_garbage and random.random() < 0.3:
                garbage_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=packet_number,
                    payload=self._create_garbage_frames(),
                )
                packets.append(garbage_packet)
                packet_number += 1
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
        zero_rtt_pn = 0
        one_rtt_pn = 0
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial_packet)
        early_chunks = list(self._chunk_data(early_data, 500))
        remaining_chunks = list(self._chunk_data(remaining_data, 500))
        max_chunks = max(len(early_chunks), len(remaining_chunks))
        for i in range(max_chunks):
            if i < len(early_chunks):
                zero_rtt_packet = QUICPacket(
                    packet_type=QUICPacketType.ZERO_RTT,
                    connection_id=connection_id,
                    packet_number=zero_rtt_pn,
                    payload=self._create_stream_frame(4, early_chunks[i]),
                )
                packets.append(zero_rtt_packet)
                zero_rtt_pn += 1
            if i < len(remaining_chunks):
                one_rtt_packet = QUICPacket(
                    packet_type=QUICPacketType.ONE_RTT,
                    connection_id=connection_id,
                    packet_number=one_rtt_pn,
                    payload=self._create_stream_frame(0, remaining_chunks[i]),
                )
                packets.append(one_rtt_packet)
                one_rtt_pn += 1
            if i % 3 == 0:
                confusion_packet = QUICPacket(
                    packet_type=random.choice([QUICPacketType.ZERO_RTT, QUICPacketType.ONE_RTT]),
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
        tls_like_hello = self._create_tls_like_client_hello(domain)
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(tls_like_hello),
        )
        packets.append(initial_packet)
        http_request = (
            b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
        http_packet = QUICPacket(
            packet_type=QUICPacketType.ZERO_RTT,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_stream_frame(4, http_request),
        )
        packets.append(http_packet)
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
        initial_packet = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=packet_number,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial_packet)
        packet_number += 1
        for chunk in self._chunk_data(early_data, 1200):
            zero_rtt_packet = QUICPacket(
                packet_type=QUICPacketType.ZERO_RTT,
                connection_id=connection_id,
                packet_number=packet_number,
                payload=self._create_stream_frame(4, chunk),
            )
            packets.append(zero_rtt_packet)
            packet_number += 1
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
        client_hello = b"CHLO"
        client_hello += struct.pack("<I", 2)
        client_hello += b"SNI\x00"
        sni_data = struct.pack("<I", len(domain)) + domain.encode()
        client_hello += struct.pack("<I", len(sni_data)) + sni_data
        client_hello += b"STK\x00"
        client_hello += struct.pack("<I", len(session_ticket)) + session_ticket
        return client_hello

    def _create_garbage_frames(self) -> bytes:
        """Create garbage frames to confuse DPI."""
        frames = b""
        garbage_types = [
            (30, secrets.token_bytes(random.randint(10, 50))),
            (48, b"GARBAGE_DATA_" + secrets.token_bytes(20)),
            (QUICFrameType.PADDING, b"\x00" * random.randint(50, 200)),
        ]
        for frame_type, data in random.sample(garbage_types, 2):
            frames += bytes([frame_type])
            if frame_type != QUICFrameType.PADDING:
                frames += self._encode_varint(len(data))
                frames += data
            else:
                frames += data
        return frames

    def _create_tls_like_client_hello(self, domain: str) -> bytes:
        """Create data that looks like TLS ClientHello."""
        tls_hello = b"\x16\x03\x03"
        hello_data = b"\x01"
        hello_data += b"\x00\x00\xfe"
        hello_data += b"\x03\x03"
        hello_data += secrets.token_bytes(32)
        hello_data += b" " + secrets.token_bytes(32)
        hello_data += b"\x00\x02\x13\x01"
        hello_data += b"\x01\x00"
        ext_data = b"\x00\x00"
        sni_list = struct.pack(">H", len(domain) + 3)
        sni_list += b"\x00" + struct.pack(">H", len(domain)) + domain.encode()
        ext_data += struct.pack(">H", len(sni_list)) + sni_list
        hello_data += struct.pack(">H", len(ext_data)) + ext_data
        hello_data = hello_data[:1] + struct.pack(">I", len(hello_data) - 4)[1:] + hello_data[4:]
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

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute mixed encryption level attack."""
        start_time = time.time()
        try:
            mixing_strategy = context.params.get("mixing_strategy", "interleaved")
            include_handshake = context.params.get("include_handshake", True)
            randomize_order = context.params.get("randomize_order", True)
            base_packets = self._convert_to_quic_packets(context.payload)
            mixed_packets = []
            if include_handshake:
                mixed_packets.extend(self._create_handshake_packets())
            if mixing_strategy == "interleaved":
                mixed_packets.extend(self._create_interleaved_packets(base_packets))
            elif mixing_strategy == "burst":
                mixed_packets.extend(self._create_burst_packets(base_packets))
            elif mixing_strategy == "nested":
                mixed_packets.extend(self._create_nested_packets(base_packets))
            else:
                mixed_packets.extend(base_packets)
            if randomize_order:
                random.shuffle(mixed_packets)
            segments = self._create_mixed_datagrams(mixed_packets)
            total_bytes = sum((len(seg[0]) for seg in segments))
            await asyncio.sleep(0)
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
        initial = QUICPacket(
            packet_type=QUICPacketType.INITIAL,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(200)),
        )
        packets.append(initial)
        handshake = QUICPacket(
            packet_type=QUICPacketType.HANDSHAKE,
            connection_id=connection_id,
            packet_number=0,
            payload=self._create_crypto_frame(secrets.token_bytes(150)),
        )
        packets.append(handshake)
        return packets

    def _create_interleaved_packets(self, base_packets: List[QUICPacket]) -> List[QUICPacket]:
        """Create interleaved 0-RTT and 1-RTT packets."""
        mixed = []
        for i, packet in enumerate(base_packets):
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
            burst_type = i // burst_size % 3
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

    def _create_nested_packets(self, base_packets: List[QUICPacket]) -> List[QUICPacket]:
        """Create nested encryption levels (experimental)."""
        mixed = []
        for i, packet in enumerate(base_packets):
            for ptype in [QUICPacketType.ZERO_RTT, QUICPacketType.ONE_RTT]:
                nested = QUICPacket(
                    packet_type=ptype,
                    connection_id=packet.connection_id,
                    packet_number=i,
                    payload=packet.payload,
                )
                mixed.append(nested)
        return mixed

    def _create_mixed_datagrams(self, packets: List[QUICPacket]) -> List[Tuple[bytes, int]]:
        """Create datagrams with mixed encryption levels."""
        segments = []
        max_datagram_size = 1200
        i = 0
        while i < len(packets):
            datagram = b""
            current_size = 0
            encryption_levels_in_datagram = set()
            while i < len(packets) and current_size < max_datagram_size:
                packet_bytes = packets[i].to_bytes()
                if current_size + len(packet_bytes) <= max_datagram_size:
                    datagram += packet_bytes
                    current_size += len(packet_bytes)
                    encryption_levels_in_datagram.add(packets[i].packet_type)
                    i += 1
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


def create_0rtt_enhanced_attack(base_attack_name: str) -> type:
    """
    Factory to create 0-RTT enhanced versions of existing attacks.

    Example:
        ZeroRTTEnhancedCIDRotation = create_0rtt_enhanced_attack("quic_advanced_cid_rotation")
    """
    base_attack_class = AttackRegistry.get_attack(base_attack_name)
    if not base_attack_class:
        raise ValueError(f"Base attack {base_attack_name} not found")

    def _build_enhanced_context(context: AttackContext) -> AttackContext:
        enhanced_params = dict(context.params or {})
        enhanced_params["include_0rtt"] = True
        enhanced_params["early_data_ratio"] = enhanced_params.get("early_data_ratio", 0.3)
        return AttackContext(
            dst_ip=context.dst_ip,
            dst_port=context.dst_port,
            domain=context.domain,
            payload=context.payload,
            params=enhanced_params,
            debug=context.debug,
        )

    async def _maybe_await(value: Any) -> Any:
        if asyncio.iscoroutine(value) or isinstance(value, Awaitable):
            return await value
        return value

    is_base_async = asyncio.iscoroutinefunction(getattr(base_attack_class, "execute", None))

    if is_base_async:

        class ZeroRTTEnhancedAttack(base_attack_class):

            @property
            def name(self) -> str:
                return f"{base_attack_name}_0rtt_enhanced"

            @property
            def description(self) -> str:
                return f"{super().description} enhanced with 0-RTT early data"

            async def execute(self, context: AttackContext) -> AttackResult:
                enhanced_context = _build_enhanced_context(context)

                result = await _maybe_await(super().execute(enhanced_context))
                if not isinstance(result, AttackResult):
                    # Defensive fallback
                    return AttackResult(
                        status=AttackStatus.ERROR,
                        error_message=f"Unexpected result type from base attack: {type(result)}",
                    )

                if result.status == AttackStatus.SUCCESS:
                    early_data_attack = QUICZeroRTTEarlyDataAttack()
                    early_result = await _maybe_await(early_data_attack.execute(context))
                    if isinstance(early_result, AttackResult) and early_result.status == AttackStatus.SUCCESS:
                        result.packets_sent += early_result.packets_sent
                        result.bytes_sent += early_result.bytes_sent
                        if result.metadata is None:
                            result.metadata = {}
                        result.metadata.update(
                            {
                                "0rtt_enhanced": True,
                                "0rtt_packets": early_result.metadata.get("zero_rtt_packets", 0)
                                if early_result.metadata
                                else 0,
                            }
                        )
                return result

    else:

        class ZeroRTTEnhancedAttack(base_attack_class):

            @property
            def name(self) -> str:
                return f"{base_attack_name}_0rtt_enhanced"

            @property
            def description(self) -> str:
                return f"{super().description} enhanced with 0-RTT early data"

            def execute(self, context: AttackContext) -> AttackResult:
                enhanced_context = _build_enhanced_context(context)

                result = super().execute(enhanced_context)
                if not isinstance(result, AttackResult):
                    return AttackResult(
                        status=AttackStatus.ERROR,
                        error_message=f"Unexpected result type from base attack: {type(result)}",
                    )

                # In sync mode we do NOT attempt to run async 0-RTT flow to avoid event-loop misuse.
                # We only annotate metadata to keep behavior deterministic.
                if result.status == AttackStatus.SUCCESS:
                    if result.metadata is None:
                        result.metadata = {}
                    result.metadata.update({"0rtt_enhanced": True, "0rtt_note": "base attack is sync"})
                return result

    register_attack(ZeroRTTEnhancedAttack)
    return ZeroRTTEnhancedAttack
