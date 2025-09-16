import struct
from typing import List, Tuple, Optional

class BypassTechniques:
    """Библиотека продвинутых техник обхода DPI."""

    @staticmethod
    def apply_fakeddisorder(
        payload: bytes,
        split_pos: int = 76,
        overlap_size: int = 336,
        fake_ttl: int = 1,
        fooling_methods: Optional[List[str]] = None,
        segment_order: str = "fake_first",      # "fake_first" | "real_first"
        badseq_delta: Optional[int] = None,     # только если есть "badseq"
        psh_on_fake: bool = False,
        psh_on_real: bool = True,
        fake_delay_ms: int = 1,
        real_delay_ms: int = 1,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Возвращает список сегментов: [(payload, rel_off, opts), ...]
          - opts: {
              is_fake: bool,
              ttl: int (только для fake),
              tcp_flags: int (ACK/PSH|ACK),
              corrupt_tcp_checksum: bool (если "badsum"),
              add_md5sig_option: bool (если "md5sig"),
              seq_offset: int (если "badseq"),
              delay_ms: int (ТОЛЬКО для первого сегмента — пауза перед вторым)
            }
        """
        try:
            if not payload:
                return []
            # Нормализация входов
            if split_pos <= 0:
                split_pos = 1
            if fooling_methods is None:
                fooling_methods = []

            # Если нечего делить — отдаём один «реальный» сегмент
            if split_pos >= len(payload):
                return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]

            # Ограничим overlap
            ov = 0
            try:
                ov = int(overlap_size)
            except Exception:
                ov = 0
            if ov < 0:
                ov = 0

            part1 = payload[:split_pos]
            part2 = payload[split_pos:]

            offset_real = split_pos
            offset_fake = split_pos - ov

            # Сборка опций
            ttl_clamped = int(max(1, min(255, int(fake_ttl) if fake_ttl is not None else 1)))
            opts_fake = {
                "is_fake": True,
                "ttl": ttl_clamped,
                "tcp_flags": (0x10 | (0x08 if psh_on_fake else 0)),
            }
            if "badsum" in fooling_methods:
                opts_fake["corrupt_tcp_checksum"] = True
            if "md5sig" in fooling_methods:
                opts_fake["add_md5sig_option"] = True
            if "badseq" in fooling_methods:
                # Минимальный сдвиг по умолчанию — ближе к zapret
                if badseq_delta is None:
                    badseq_delta = -1
                try:
                    opts_fake["seq_offset"] = int(badseq_delta)
                except Exception:
                    opts_fake["seq_offset"] = -1
                # Для совместимости: помечаем как corrupt_sequence, но в sender приоритет у seq_offset
                opts_fake["corrupt_sequence"] = True

            opts_real = {
                "is_fake": False,
                "tcp_flags": (0x10 | (0x08 if psh_on_real else 0)),
            }

            # Формируем порядок + задержку на первом сегменте
            segs: List[Tuple[bytes, int, dict]] = []
            if segment_order == "real_first":
                first_opts = dict(opts_real)
                if real_delay_ms and real_delay_ms > 0:
                    first_opts["delay_ms"] = int(real_delay_ms)
                segs.append((part2, offset_real, first_opts))
                segs.append((part1, offset_fake, dict(opts_fake)))
            else:
                first_opts = dict(opts_fake)
                if fake_delay_ms and fake_delay_ms > 0:
                    first_opts["delay_ms"] = int(fake_delay_ms)
                segs.append((part1, offset_fake, first_opts))
                segs.append((part2, offset_real, dict(opts_real)))

            return segs
        except Exception:
            # Защитный fallback (никогда не должен понадобиться)
            if split_pos >= len(payload):
                return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
            # «простой» порядок: fake -> real
            return [
                (payload[:split_pos], 0, {
                    "is_fake": True, "ttl": int(fake_ttl or 1), "tcp_flags": 0x10,
                    "corrupt_tcp_checksum": ("badsum" in (fooling_methods or []))
                }),
                (payload[split_pos:], split_pos, {"is_fake": False, "tcp_flags": 0x18}),
            ]

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