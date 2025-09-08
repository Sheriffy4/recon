"""
QUIC Fragmentation Attack

An attack that fragments QUIC Initial packets to evade DPI detection.
"""

import time
import os
import struct
import random
from typing import List, Optional, Dict, Any
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


def encode_variable_length(value: int) -> bytes:
    """Encode integer in QUIC variable-length format."""
    if value < 64:
        return struct.pack("!B", value)
    elif value < 16384:
        return struct.pack("!H", value | 16384)
    elif value < 1073741824:
        return struct.pack("!I", value | 2147483648)
    else:
        return struct.pack("!Q", value | 13835058055282163712)


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
        handshake_type = b"\x01"
        tls_version = b"\x03\x03"
        client_random = os.urandom(32)
        session_id_len = b" "
        session_id = os.urandom(32)
        cipher_suites = b"\x13\x01\x13\x02\x13\x03"
        cipher_suites_len = struct.pack("!H", len(cipher_suites))
        compression_methods = b"\x01\x00"
        extensions = b""
        server_name = domain.encode("utf-8")
        sni_ext = b"\x00\x00"
        sni_content = (
            struct.pack("!H", len(server_name) + 5)
            + struct.pack("!H", len(server_name) + 3)
            + b"\x00"
            + struct.pack("!H", len(server_name))
            + server_name
        )
        sni_ext += struct.pack("!H", len(sni_content)) + sni_content
        extensions += sni_ext
        supported_versions_ext = b"\x00+"
        supported_versions_content = b"\x02\x03\x04"
        supported_versions_ext += (
            struct.pack("!H", len(supported_versions_content))
            + supported_versions_content
        )
        extensions += supported_versions_ext
        quic_params_ext = b"\x009"
        quic_params = (
            b"\x01\x04"
            + struct.pack("!I", 1048576)
            + b"\x04\x04"
            + struct.pack("!I", 1048576)
            + b"\x08\x02"
            + struct.pack("!H", 100)
        )
        quic_params_ext += struct.pack("!H", len(quic_params)) + quic_params
        extensions += quic_params_ext
        extensions_len = struct.pack("!H", len(extensions))
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
        handshake_len = struct.pack("!I", len(client_hello_body))[1:]
        client_hello = handshake_type + handshake_len + client_hello_body
        return client_hello

    def _create_quic_initial_packet(
        self, domain: str, payload_data: Optional[bytes] = None
    ) -> bytes:
        """
        Create a complete QUIC Initial packet with proper structure.
        Combines logic from http3_bypass and quic_bypass modules.
        """
        header_flags = 192
        version = b"\x00\x00\x00\x01"
        dcid_len = 8
        dcid = os.urandom(dcid_len)
        scid_len = 8
        scid = os.urandom(scid_len)
        token_length = encode_variable_length(0)
        client_hello = self._create_simple_tls_client_hello(domain)
        crypto_frame_type = b"\x06"
        crypto_offset = encode_variable_length(0)
        crypto_length = encode_variable_length(len(client_hello))
        crypto_frame = crypto_frame_type + crypto_offset + crypto_length + client_hello
        frames = crypto_frame
        if payload_data:
            stream_frame_type = b"\x08"
            stream_id = encode_variable_length(0)
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
            padding_frames = b"\x00" * padding_size
            frames += padding_frames
        packet_number = b"\x00\x00\x00\x00"
        payload_length = len(packet_number) + len(frames) + 16
        length_field = encode_variable_length(payload_length)
        header_flags |= 3
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
        aead_tag = os.urandom(16)
        packet += aead_tag
        if len(packet) > 4:
            header_byte = packet[0]
            header_byte = header_byte & 252 | random.randint(1, 3)
            packet = bytes([header_byte]) + packet[1:]
        return packet

    def _fragment_with_techniques(
        self, payload: bytes, fragment_size: int
    ) -> List[bytes]:
        """
        Fragment payload with additional techniques from quic_bypass.
        """
        fragments = []
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i : i + fragment_size]
            if random.random() < 0.3:
                if len(fragment) > 0:
                    modified = bytearray(fragment)
                    modified[0] = modified[0] & 252 | random.randint(1, 3)
                    fragment = bytes(modified)
            fragments.append(fragment)
        return fragments

    def _fragment_by_frames(self, payload: bytes, fallback_size: int) -> List[bytes]:
        """Fragment payload on CRYPTO/STREAM frame boundaries when possible."""
        # Очень простой сканер: ищем 0x06(CRYPTO)/0x00(PADDING)/STREAM(0x08..0x0f)
        parts = []
        try:
            # Заголовок long header до PN — возьмем предположительно 20..50 байт.
            # Здесь берём эвристику — работаем на синтетике, где формат нам известен.
            # Для простоты режем «как есть» по целым фреймам.
            p = 0
            n = len(payload)
            # ищем первый CRYPTO
            frames = []
            i = 0
            while i < n:
                ftype = payload[i]
                if ftype == 0x00:
                    j = i + 1
                    while j < n and payload[j] == 0x00: j += 1
                    frames.append((i, j))
                    i = j; continue
                if ftype == 0x06:
                    j = i + 1
                    off, l1 = self._decode_varint(payload[j:]); j += l1
                    ln, l2 = self._decode_varint(payload[j:]); j += l2
                    j = min(n, j + ln)
                    frames.append((i, j)); i = j; continue
                if 0x08 <= ftype <= 0x0F:
                    j = i + 1
                    _, lsid = self._decode_varint(payload[j:]); j += lsid
                    _, loff = self._decode_varint(payload[j:]); j += loff
                    ln, llen = self._decode_varint(payload[j:]); j += llen
                    j = min(n, j + ln)
                    frames.append((i, j)); i = j; continue
                i += 1
            if not frames:
                return self._fragment_with_techniques(payload, fallback_size)
            last = 0
            for (s, e) in frames:
                if s > last:
                    # вставим «межкадровый» кусок
                    parts.append(payload[last:s])
                parts.append(payload[s:e])
                last = e
            if last < n:
                parts.append(payload[last:])
            # выкидываем пустые
            parts = [p for p in parts if p]
            # гарантируем не слишком мелкие куски
            if all(len(p) < 16 for p in parts):
                return self._fragment_with_techniques(payload, fallback_size)
            return parts
        except Exception:
            return self._fragment_with_techniques(payload, fallback_size)

    def _decode_varint(self, data: bytes) -> tuple[int, int]:
        if not data:
            return 0, 0
        fb = data[0]; pref = fb >> 6; length = 1 << pref
        if len(data) < length: return 0, 1
        val = fb & 0x3F
        for i in range(1, length):
            val = (val << 8) | data[i]
        return val, length

    def _create_version_negotiation_packet(self) -> bytes:
        """Create a QUIC Version Negotiation packet to confuse DPI."""
        header = struct.pack("!B", 128 | random.randint(0, 63))
        dcid_len = 8
        scid_len = 8
        dcid = os.urandom(dcid_len)
        scid = os.urandom(scid_len)
        versions = [1, 4278190109, 4278190108, 4278190107]
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
            fragment_size = context.params.get("fragment_size", 100)
            split_by_frames = bool(context.params.get("split_by_frames", True))
            coalesce_count = int(context.params.get("coalesce_count", 0))
            padding_ratio = float(context.params.get("padding_ratio", 0.0))
            domain = context.domain or "example.com"
            use_coalescing = context.params.get("use_coalescing", False)
            add_version_negotiation = context.params.get(
                "add_version_negotiation", False
            )
            if context.payload:
                full_quic_packet = self._create_quic_initial_packet(
                    domain, context.payload
                )
            else:
                full_quic_packet = self._create_quic_initial_packet(domain)
            if split_by_frames:
                fragments = self._fragment_by_frames(full_quic_packet, fragment_size)
            else:
                fragments = self._fragment_with_techniques(full_quic_packet, fragment_size)
            segments = []
            if add_version_negotiation:
                vn_packet = self._create_version_negotiation_packet()
                segments.append((vn_packet, 0))
            # Коалесцирование: объединим несколько небольших фрагментов в один UDP‑датаграм
            if coalesce_count > 1 and len(fragments) > coalesce_count:
                fused = b"".join(fragments[:coalesce_count])
                fragments = [fused] + fragments[coalesce_count:]
            # Padding в конец первого фрагмента
            if padding_ratio > 0 and fragments:
                pad_len = int(len(fragments[0]) * padding_ratio)
                fragments[0] = fragments[0] + (b"\x00" * pad_len)
            for i, fragment in enumerate(fragments):
                delay = random.randint(0, 20) if i > 0 else 0
                segments.append((fragment, delay))
            total_bytes = sum((len(seg[0]) for seg in segments))
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
                    "split_by_frames": split_by_frames,
                    "coalesce_count": coalesce_count,
                    "padding_ratio": padding_ratio,
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
