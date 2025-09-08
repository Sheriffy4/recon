"""
QUIC Obfuscation Attacks

Advanced QUIC protocol obfuscation techniques that use QUIC protocol features
to fragment and obfuscate traffic while evading DPI detection.
"""

import asyncio
import time
import random
import struct
from typing import List, Optional
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


@register_attack
class QUICFragmentationObfuscationAttack(BaseAttack):
    """
    QUIC Fragmentation Obfuscation Attack.

    Uses QUIC protocol fragmentation and connection establishment
    to obfuscate traffic patterns and evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "quic_fragmentation_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Uses QUIC fragmentation to obfuscate traffic patterns"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC fragmentation obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragment_size = context.params.get("fragment_size", 300)
            add_version_negotiation = context.params.get(
                "add_version_negotiation", False
            )
            connection_id_length = context.params.get("connection_id_length", 8)
            quic_packets = []
            if add_version_negotiation:
                vn_packet = self._create_version_negotiation_packet(
                    connection_id_length
                )
                quic_packets.append(vn_packet)
            initial_packet = self._create_initial_packet(
                connection_id_length, context.domain
            )
            quic_packets.append(initial_packet)
            if payload:
                fragment_packets = self._create_fragmented_data_packets(
                    payload, fragment_size, connection_id_length
                )
                quic_packets.extend(fragment_packets)
            else:
                dummy_payload = b"dummy_quic_data_for_obfuscation" * 10
                fragment_packets = self._create_fragmented_data_packets(
                    dummy_payload, fragment_size, connection_id_length
                )
                quic_packets.extend(fragment_packets)
            segments = []
            for i, packet in enumerate(quic_packets):
                delay = await self._calculate_quic_delay(i, add_version_negotiation)
                packet_type = self._get_quic_packet_type(i, add_version_negotiation)
                segments.append(
                    (
                        packet,
                        delay,
                        {
                            "packet_type": packet_type,
                            "fragment_index": i,
                            "packet_size": len(packet),
                        },
                    )
                )
            packets_sent = len(quic_packets)
            bytes_sent = sum((len(packet) for packet in quic_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="quic_fragmentation_obfuscation",
                metadata={
                    "fragment_size": fragment_size,
                    "fragment_count": (
                        len(fragment_packets) if "fragment_packets" in locals() else 0
                    ),
                    "add_version_negotiation": add_version_negotiation,
                    "version_negotiation_added": add_version_negotiation,
                    "connection_id_length": connection_id_length,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="quic_fragmentation_obfuscation",
            )

    def _create_version_negotiation_packet(self, connection_id_length: int) -> bytes:
        """Create QUIC version negotiation packet."""
        header_form = 128
        version = 0
        dcid_len = connection_id_length
        dcid = random.randbytes(dcid_len)
        scid_len = connection_id_length
        scid = random.randbytes(scid_len)
        supported_versions = [1, 4278190109, 4278190110, 4278190111]
        packet = struct.pack("!BI", header_form, version)
        packet += bytes([dcid_len]) + dcid
        packet += bytes([scid_len]) + scid
        for version in supported_versions:
            packet += struct.pack("!I", version)
        return packet

    def _create_initial_packet(
        self, connection_id_length: int, server_name: Optional[str]
    ) -> bytes:
        """Create QUIC Initial packet."""
        header_byte = 192
        version = 1
        dcid_len = connection_id_length
        dcid = random.randbytes(dcid_len)
        scid_len = connection_id_length
        scid = random.randbytes(scid_len)
        token_length = 0
        token = b""
        packet_number = random.randint(0, 16777215)
        pn_bytes = struct.pack("!I", packet_number)[1:]
        tls_payload = self._create_quic_tls_client_hello(server_name)
        payload_length = len(pn_bytes) + len(tls_payload)
        packet = struct.pack("!BI", header_byte, version)
        packet += bytes([dcid_len]) + dcid
        packet += bytes([scid_len]) + scid
        packet += self._encode_varint(token_length) + token
        packet += self._encode_varint(payload_length)
        packet += pn_bytes
        packet += tls_payload
        return packet

    def _create_fragmented_data_packets(
        self, payload: bytes, fragment_size: int, connection_id_length: int
    ) -> List[bytes]:
        """Create fragmented QUIC data packets."""
        packets = []
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]
            packet = self._create_1rtt_packet(
                fragment, connection_id_length, i // fragment_size
            )
            packets.append(packet)
        return packets

    def _create_1rtt_packet(
        self, data: bytes, connection_id_length: int, sequence: int
    ) -> bytes:
        """Create QUIC 1-RTT packet."""
        header_byte = 64
        header_byte |= random.randint(0, 1) << 5
        header_byte |= random.randint(0, 1) << 2
        header_byte |= 3
        dcid = random.randbytes(connection_id_length)
        packet_number = sequence + 1000
        pn_bytes = struct.pack("!I", packet_number)
        encrypted_payload = self._encrypt_quic_payload(data, packet_number)
        packet = bytes([header_byte])
        packet += dcid
        packet += pn_bytes
        packet += encrypted_payload
        return packet

    def _create_quic_tls_client_hello(self, server_name: Optional[str]) -> bytes:
        """Create TLS Client Hello for QUIC."""
        handshake_type = 1
        tls_version = b"\x03\x03"
        random_bytes = random.randbytes(32)
        session_id_len = 0
        session_id = b""
        cipher_suites = b"\x00\x02\x13\x01"
        compression_methods = b"\x01\x00"
        extensions = self._create_quic_tls_extensions(server_name)
        client_hello = (
            tls_version
            + random_bytes
            + bytes([session_id_len])
            + session_id
            + cipher_suites
            + compression_methods
            + struct.pack("!H", len(extensions))
            + extensions
        )
        handshake_length = len(client_hello)
        handshake_msg = (
            bytes([handshake_type])
            + struct.pack("!I", handshake_length)[1:]
            + client_hello
        )
        return handshake_msg

    def _create_quic_tls_extensions(self, server_name: Optional[str]) -> bytes:
        """Create TLS extensions for QUIC."""
        extensions = b""
        if server_name:
            sni_data = server_name.encode("utf-8")
            sni_ext = (
                b"\x00\x00"
                + struct.pack("!H", len(sni_data) + 5)
                + struct.pack("!H", len(sni_data) + 3)
                + b"\x00"
                + struct.pack("!H", len(sni_data))
                + sni_data
            )
            extensions += sni_ext
        quic_params = self._create_quic_transport_parameters()
        quic_ext = b"\x009" + struct.pack("!H", len(quic_params)) + quic_params
        extensions += quic_ext
        groups_ext = b"\x00\n" + b"\x00\x04" + b"\x00\x02" + b"\x00\x17"
        extensions += groups_ext
        return extensions

    def _create_quic_transport_parameters(self) -> bytes:
        """Create QUIC transport parameters."""
        params = b""
        params += self._encode_transport_param(1, self._encode_varint(30000))
        params += self._encode_transport_param(3, self._encode_varint(1472))
        params += self._encode_transport_param(4, self._encode_varint(1048576))
        params += self._encode_transport_param(5, self._encode_varint(262144))
        params += self._encode_transport_param(8, self._encode_varint(100))
        return params

    def _encode_transport_param(self, param_id: int, value: bytes) -> bytes:
        """Encode QUIC transport parameter."""
        return self._encode_varint(param_id) + self._encode_varint(len(value)) + value

    def _encode_varint(self, value: int) -> bytes:
        """Encode QUIC variable-length integer."""
        if value < 64:
            return bytes([value])
        elif value < 16384:
            return struct.pack("!H", 16384 | value)
        elif value < 1073741824:
            return struct.pack("!I", 2147483648 | value)
        else:
            return struct.pack("!Q", 13835058055282163712 | value)

    def _encrypt_quic_payload(self, data: bytes, packet_number: int) -> bytes:
        """Simulate QUIC payload encryption."""
        key = struct.pack("!I", packet_number) * (len(data) // 4 + 1)
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        auth_tag = random.randbytes(16)
        return bytes(encrypted) + auth_tag

    async def _calculate_quic_delay(
        self, packet_index: int, has_version_negotiation: bool
    ) -> int:
        """Calculate realistic QUIC packet delay."""
        delay = 0
        if has_version_negotiation and packet_index == 0:
            delay = 0
        elif packet_index <= (1 if has_version_negotiation else 0):
            delay = random.randint(10, 50)
        else:
            delay = random.randint(5, 25)

        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
        return delay

    def _get_quic_packet_type(
        self, packet_index: int, has_version_negotiation: bool
    ) -> str:
        """Get QUIC packet type description."""
        if has_version_negotiation:
            if packet_index == 0:
                return "version_negotiation"
            elif packet_index == 1:
                return "initial"
            else:
                return "1rtt_data"
        elif packet_index == 0:
            return "initial"
        else:
            return "1rtt_data"
