# recon/core/bypass/attacks/tunneling/quic_fragmentation.py
"""
QUIC Fragmentation Attack

An attack that fragments QUIC Initial packets to evade DPI detection.
"""

import time
import os
import struct
import random
from typing import List, Optional, Dict, Any
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
class QUICFragmentationAttack(BaseAttack):
    """
    QUIC Fragmentation Attack - fragments QUIC Initial packets.
    """

    @property
    def name(self) -> str:
        return "quic_fragmentation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Fragments QUIC Initial packets to bypass DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        params = params or {}
        frag_size = params.get("fragment_size", 100)
        return f"--quic-frag={frag_size}"

    def _create_simple_tls_client_hello(self, domain: str) -> bytes:
        """Create a simplified TLS 1.3 ClientHello for QUIC."""
        # TLS Handshake header
        handshake_type = b"\x01"  # ClientHello
        # Length placeholder (3 bytes)

        # ClientHello fields
        tls_version = b"\x03\x03"  # TLS 1.2 (compatibility)
        client_random = os.urandom(32)
        session_id_len = b"\x20"  # 32 bytes
        session_id = os.urandom(32)

        # Cipher suites
        cipher_suites = b"\x13\x01\x13\x02\x13\x03"  # TLS_AES_128_GCM_SHA256, etc.
        cipher_suites_len = struct.pack("!H", len(cipher_suites))

        # Compression methods
        compression_methods = b"\x01\x00"  # Length 1, null compression

        # Extensions
        extensions = b""

        # Server Name Indication (SNI)
        server_name = domain.encode("utf-8")
        sni_ext = b"\x00\x00"  # Extension type: server_name
        sni_content = (
            struct.pack("!H", len(server_name) + 5)  # Extension length
            + struct.pack("!H", len(server_name) + 3)  # Server name list length
            + b"\x00"  # Server name type: host_name
            + struct.pack("!H", len(server_name))  # Server name length
            + server_name
        )
        sni_ext += struct.pack("!H", len(sni_content)) + sni_content
        extensions += sni_ext

        # Supported Versions (for TLS 1.3)
        supported_versions_ext = b"\x00\x2b"  # Extension type
        supported_versions_content = b"\x02\x03\x04"  # Length 2, TLS 1.3
        supported_versions_ext += (
            struct.pack("!H", len(supported_versions_content))
            + supported_versions_content
        )
        extensions += supported_versions_ext

        # QUIC Transport Parameters
        quic_params_ext = b"\x00\x39"  # Extension type: quic_transport_parameters
        quic_params = (
            b"\x01\x04"
            + struct.pack("!I", 1048576)  # max_idle_timeout
            + b"\x04\x04"
            + struct.pack("!I", 1048576)  # initial_max_data
            + b"\x08\x02"
            + struct.pack("!H", 100)  # initial_max_streams_bidi
        )
        quic_params_ext += struct.pack("!H", len(quic_params)) + quic_params
        extensions += quic_params_ext

        extensions_len = struct.pack("!H", len(extensions))

        # Build ClientHello body
        client_hello_body = (
            tls_version
            + client_random
            + session_id_len
            + session_id
            + cipher_suites_len
            + cipher_suites
            + compression_methods
            + extensions_len
            + extensions
        )

        # Complete handshake message
        handshake_len = struct.pack("!I", len(client_hello_body))[1:]  # 3 bytes
        client_hello = handshake_type + handshake_len + client_hello_body

        return client_hello

    def _create_quic_initial_packet(
        self, domain: str, payload_data: Optional[bytes] = None
    ) -> bytes:
        """
        Create a complete QUIC Initial packet with proper structure.
        Combines logic from http3_bypass and quic_bypass modules.
        """
        # QUIC Long Header for Initial Packet
        # Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Reserved (2) | Packet Number Length (2)
        header_flags = 0b11000000  # Long header, Initial packet type
        version = b"\x00\x00\x00\x01"  # QUIC v1

        # Connection IDs
        dcid_len = 8
        dcid = os.urandom(dcid_len)
        scid_len = 8
        scid = os.urandom(scid_len)

        # Token (empty for initial connection)
        token_length = encode_variable_length(0)

        # Create TLS ClientHello
        client_hello = self._create_simple_tls_client_hello(domain)

        # CRYPTO frame containing ClientHello
        crypto_frame_type = b"\x06"  # CRYPTO frame
        crypto_offset = encode_variable_length(0)  # Offset 0 for first crypto data
        crypto_length = encode_variable_length(len(client_hello))
        crypto_frame = crypto_frame_type + crypto_offset + crypto_length + client_hello

        # Add custom payload if provided (for tunneling)
        frames = crypto_frame
        if payload_data:
            # STREAM frame for additional data
            stream_frame_type = b"\x08"  # STREAM frame with no FIN
            stream_id = encode_variable_length(0)  # Stream 0
            stream_offset = encode_variable_length(0)
            stream_length = encode_variable_length(len(payload_data))
            stream_frame = (
                stream_frame_type
                + stream_id
                + stream_offset
                + stream_length
                + payload_data
            )
            frames += stream_frame

        # Add PADDING frames to reach minimum size (1200 bytes for Initial)
        min_packet_size = 1200
        current_size = (
            1
            + 4
            + 1
            + dcid_len
            + 1
            + scid_len
            + len(token_length)
            + 2
            + 4
            + len(frames)
            + 16
        )
        if current_size < min_packet_size:
            padding_size = min_packet_size - current_size
            padding_frames = b"\x00" * padding_size  # PADDING frame type is 0x00
            frames += padding_frames

        # Packet number (4 bytes for Initial)
        packet_number = b"\x00\x00\x00\x00"  # First packet

        # Length field (includes packet number + frames + AEAD tag)
        payload_length = len(packet_number) + len(frames) + 16  # 16 bytes for AEAD tag
        length_field = encode_variable_length(payload_length)

        # Modify header flags to include packet number length (2 bits)
        # Using 4-byte packet number (11 in binary)
        header_flags |= 0x03

        # Assemble packet
        packet = (
            bytes([header_flags])
            + version
            + bytes([dcid_len])
            + dcid
            + bytes([scid_len])
            + scid
            + token_length
            + length_field
            + packet_number
            + frames
        )

        # Add fake AEAD tag (in real implementation, this would be proper encryption)
        aead_tag = os.urandom(16)
        packet += aead_tag

        # Apply header protection (simplified - just modify some bits)
        if len(packet) > 4:
            # Modify reserved bits for DPI evasion
            header_byte = packet[0]
            header_byte = (header_byte & 0xFC) | random.randint(1, 3)
            packet = bytes([header_byte]) + packet[1:]

        return packet

    def _fragment_with_techniques(
        self, payload: bytes, fragment_size: int
    ) -> List[bytes]:
        """
        Fragment payload with additional techniques from quic_bypass.
        """
        fragments = []

        # Basic fragmentation
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]

            # Randomly apply modifications to some fragments
            if random.random() < 0.3:  # 30% chance
                # Modify QUIC header bits that don't affect functionality
                if len(fragment) > 0:
                    modified = bytearray(fragment)
                    # Change reserved bits
                    modified[0] = (modified[0] & 0xFC) | random.randint(1, 3)
                    fragment = bytes(modified)

            fragments.append(fragment)

        return fragments

    def _create_version_negotiation_packet(self) -> bytes:
        """Create a QUIC Version Negotiation packet to confuse DPI."""
        # Version Negotiation packet format
        header = struct.pack(
            "!B", 0x80 | random.randint(0, 0x3F)
        )  # Long header with random bits

        # Random connection IDs
        dcid_len = 8
        scid_len = 8
        dcid = os.urandom(dcid_len)
        scid = os.urandom(scid_len)

        # Supported versions (including draft versions)
        versions = [
            0x00000001,  # QUIC v1
            0xFF00001D,  # draft-29
            0xFF00001C,  # draft-28
            0xFF00001B,  # draft-27
        ]

        packet = header
        packet += struct.pack("!B", dcid_len) + dcid
        packet += struct.pack("!B", scid_len) + scid

        for ver in versions:
            packet += struct.pack("!I", ver)

        return packet

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC fragmentation attack."""
        start_time = time.time()

        try:
            # Get parameters
            fragment_size = context.params.get("fragment_size", 100)
            domain = context.domain or "example.com"
            use_coalescing = context.params.get("use_coalescing", False)
            add_version_negotiation = context.params.get(
                "add_version_negotiation", False
            )

            # Create QUIC Initial packet
            if context.payload:
                # If we have payload data, include it in the QUIC packet (tunneling)
                full_quic_packet = self._create_quic_initial_packet(
                    domain, context.payload
                )
            else:
                # Otherwise, just create a standard Initial packet
                full_quic_packet = self._create_quic_initial_packet(domain)

            # Fragment the packet
            fragments = self._fragment_with_techniques(full_quic_packet, fragment_size)

            # Build segments for sending
            segments = []

            # Optionally add Version Negotiation packet first
            if add_version_negotiation:
                vn_packet = self._create_version_negotiation_packet()
                segments.append((vn_packet, 0))

            # Add fragments with delays
            for i, fragment in enumerate(fragments):
                # Variable delay between fragments (0-20ms)
                delay = random.randint(0, 20) if i > 0 else 0
                segments.append((fragment, delay))

            # Calculate metrics
            total_bytes = sum(len(seg[0]) for seg in segments)
            packets_sent = len(segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fragment_size": fragment_size,
                    "fragment_count": len(fragments),
                    "original_size": len(full_quic_packet),
                    "version_negotiation_added": add_version_negotiation,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
