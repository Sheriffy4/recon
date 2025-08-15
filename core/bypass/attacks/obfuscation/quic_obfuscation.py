# recon/core/bypass/attacks/obfuscation/quic_obfuscation.py
"""
QUIC Obfuscation Attacks

Attacks that modify QUIC packets or flows to evade DPI detection.
"""

import time
import os
import struct
import random
from typing import List, Tuple, Optional, Dict, Any
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


def encode_variable_length(value: int) -> bytes:
    """Encode integer in QUIC variable-length format."""
    if value < 64:
        return struct.pack("!B", value)
    elif value < 16384:
        return struct.pack("!H", value | 0x4000)
    elif value < 1073741824:
        return struct.pack("!I", value | 0x80000000)
    else:
        return struct.pack("!Q", value | 0xC000000000000000)


@register_attack
class QUICFragmentationObfuscationAttack(BaseAttack):
    """
    Fragments QUIC Initial packets to evade DPI that does not handle
    fragmented QUIC traffic correctly.
    """

    @property
    def name(self) -> str:
        return "quic_fragmentation_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Fragments QUIC Initial packets to bypass DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC fragmentation attack."""
        start_time = time.time()
        try:
            fragment_size = context.params.get("fragment_size", 100)
            domain = context.domain or "example.com"
            add_version_negotiation = context.params.get("add_version_negotiation", False)

            full_quic_packet = self._create_quic_initial_packet(domain, context.payload)
            fragments = self._fragment_packet(full_quic_packet, fragment_size)

            segments = []
            if add_version_negotiation:
                vn_packet = self._create_version_negotiation_packet()
                segments.append((vn_packet, 0, {"packet_type": "version_negotiation"}))

            for i, fragment in enumerate(fragments):
                delay = random.randint(0, 20) if i > 0 else 0
                segments.append((fragment, delay, {"packet_type": "fragment", "fragment_index": i}))

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=(time.time() - start_time) * 1000,
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "fragment_size": fragment_size,
                    "fragment_count": len(fragments),
                    "original_packet_size": len(full_quic_packet),
                    "version_negotiation_added": add_version_negotiation,
                    "segments": segments
                }
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used=self.name
            )

    def _create_quic_initial_packet(self, domain: str, payload_data: Optional[bytes] = None) -> bytes:
        """Create a complete QUIC Initial packet."""
        header_flags = 0b11000000
        version = b"\x00\x00\x00\x01"
        dcid = os.urandom(8)
        scid = os.urandom(8)
        token_length = encode_variable_length(0)
        packet_number = b"\x00\x00\x00\x00"

        client_hello = self._create_simple_tls_client_hello(domain)
        crypto_frame = b"\x06" + encode_variable_length(0) + encode_variable_length(len(client_hello)) + client_hello

        frames = crypto_frame
        if payload_data:
            stream_frame = b"\x0a" + encode_variable_length(0) + encode_variable_length(len(payload_data)) + payload_data
            frames += stream_frame

        min_packet_size = 1200
        current_size = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + len(token_length) + 2 + 4 + len(frames) + 16
        if current_size < min_packet_size:
            frames += b"\x00" * (min_packet_size - current_size)

        payload_length = len(packet_number) + len(frames) + 16
        length_field = encode_variable_length(payload_length)
        header_flags |= 0x03

        packet = (
            bytes([header_flags]) + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid +
            token_length + length_field + packet_number + frames
        )
        packet += os.urandom(16) # Fake AEAD tag
        return packet

    def _create_simple_tls_client_hello(self, domain: str) -> bytes:
        """Create a simplified TLS 1.3 ClientHello for QUIC."""
        server_name = domain.encode("utf-8")
        sni_ext = b"\x00\x00" + struct.pack("!H", len(server_name) + 5) + b"\x00" + struct.pack("!H", len(server_name) + 3) + struct.pack("!H", len(server_name)) + server_name

        # Simplified ClientHello, focusing on SNI
        extensions = sni_ext

        client_hello_body = (
            b"\x03\x03" + os.urandom(32) + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" +
            struct.pack("!H", len(extensions)) + extensions
        )

        handshake_header = b"\x01" + struct.pack("!I", len(client_hello_body))[1:]
        return handshake_header + client_hello_body

    def _fragment_packet(self, payload: bytes, fragment_size: int) -> List[bytes]:
        """Fragment payload into chunks."""
        return [payload[i: i + fragment_size] for i in range(0, len(payload), fragment_size)]

    def _create_version_negotiation_packet(self) -> bytes:
        """Create a QUIC Version Negotiation packet to confuse DPI."""
        header = bytes([0x80 | random.randint(0, 0x3F)])
        dcid = os.urandom(8)
        scid = os.urandom(8)
        versions = [0x00000001, 0xFF00001D, 0xFF00001C, 0xFF00001B]

        packet = header + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        for ver in versions:
            packet += struct.pack("!I", ver)
        return packet
