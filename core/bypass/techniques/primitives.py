import struct
from typing import List, Tuple

class BypassTechniques:
    """Библиотека продвинутых техник обхода DPI."""

    @staticmethod
    def apply_fakeddisorder(
        payload: bytes,
        split_pos: int = 76,
        overlap_size: int = 336,
        fake_ttl: int = 1,
        fooling_methods: List[str] = None
    ) -> List[Tuple[bytes, int, dict]]:
        if fooling_methods is None:
            fooling_methods = []

        if split_pos >= len(payload):
            # If split_pos is beyond payload length, treat as a single segment
            # For fakeddisorder, this usually means the whole payload is the "real" part
            # and no fake part is generated, or the fake part is empty.
            # We'll return the original payload as the real segment.
            # ВАЖНО: TTL для реального сегмента не задаём
            opts_real = {"is_fake": False, "tcp_flags": 0x18}
            return [(payload, 0, opts_real)]

        part1, part2 = (payload[:split_pos], payload[split_pos:])
        ov = int(overlap_size) if isinstance(overlap_size, int) else 336
        if ov <= 0:
            # If no overlap, just send part2 then part1
            opts_real = {"is_fake": False, "tcp_flags": 0x18} # PSH, ACK
            opts_fake = {"is_fake": True, "ttl": fake_ttl, "delay_ms": 2}
            if "badsum" in fooling_methods:
                opts_fake["corrupt_tcp_checksum"] = True
            if "md5sig" in fooling_methods:
                opts_fake["add_md5sig_option"] = True
            return [(part2, split_pos, opts_real), (part1, 0, opts_fake)]

        if ov > 4096:
            ov = 4096

        offset_part2 = split_pos
        offset_part1 = split_pos - ov

        # ВАЖНО: сначала отправляем "правильный" (real) сегмент, затем "фейковый"
        segs = []
        # Real segment (part2)
        opts_real = {"is_fake": False, "tcp_flags": 0x18, "delay_ms": 2}  # PSH, ACK
        segs.append((part2, offset_part2, opts_real))

        # Fake segment (part1)
        opts_fake = {"is_fake": True, "ttl": fake_ttl}
        if "badsum" in fooling_methods:
            opts_fake["corrupt_tcp_checksum"] = True
        if "md5sig" in fooling_methods:
            opts_fake["add_md5sig_option"] = True
        if "badseq" in fooling_methods:
            opts_fake["corrupt_sequence"] = True

        segs.append((part1, offset_part1, opts_fake))

        return segs

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        if not positions:
            return [(payload, 0)]
        segments, last_pos = ([], 0)
        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos))
                last_pos = pos
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos))
        return segments

    @staticmethod
    def apply_multidisorder(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        segments = BypassTechniques.apply_multisplit(payload, positions)
        return segments[::-1] if len(segments) > 1 else segments

    @staticmethod
    def apply_seqovl(
        payload: bytes, split_pos: int = 3, overlap_size: int = 10
    ) -> List[Tuple[bytes, int]]:
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1, part2 = (payload[:split_pos], payload[split_pos:])
        overlap_data = b"\x00" * overlap_size
        part1_with_overlap = overlap_data + part1
        return [(part2, split_pos), (part1_with_overlap, -overlap_size)]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        try:
            if not payload or len(payload) < 5:
                return payload
            if payload[0] != 0x16 or payload[1] != 0x03 or payload[2] not in (0x00, 0x01, 0x02, 0x03):
                return payload
            rec_len = int.from_bytes(payload[3:5], "big")
            content = payload[5:5 + rec_len] if 5 + rec_len <= len(payload) else payload[5:]
            tail = payload[5 + rec_len:] if 5 + rec_len <= len(payload) else b""
            if split_pos < 1 or split_pos >= len(content):
                return payload
            part1, part2 = content[:split_pos], content[split_pos:]
            ver = payload[1:3]
            rec1 = bytes([0x16]) + ver + len(part1).to_bytes(2, "big") + part1
            rec2 = bytes([0x16]) + ver + len(part2).to_bytes(2, "big") + part2
            return rec1 + rec2 + tail
        except Exception:
            return payload

    @staticmethod
    def apply_wssize_limit(
        payload: bytes, window_size: int = 1
    ) -> List[Tuple[bytes, int]]:
        segments, pos = ([], 0)
        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos))
            pos += chunk_size
        return segments

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            # 0xDEAD — как в final_packet_bypass
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xDEAD)
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            # 0xBEEF — как в final_packet_bypass
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xBEEF)
        return packet_data