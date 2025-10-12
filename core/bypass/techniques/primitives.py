# path: core/bypass/techniques/primitives.py
# ULTIMATE CORRECTED VERSION - Best of both approaches

import struct
import random
import string
from typing import List, Tuple, Dict, Optional

def _gen_fake_sni(original: Optional[str] = None) -> str:
    """Generate fake SNI in zapret style."""
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 14)))
    tld = random.choice(["edu", "com", "net", "org"])
    return f"{label}.{tld}"

class BypassTechniques:
    """
    Библиотека продвинутых техник обхода DPI в стиле zapret.
    Генерирует "рецепты" - последовательности сегментов для отправки.
    
    CRITICAL: Все offset'ы должны быть >= 0 для корректной работы с _recipe_to_specs!
    """

    @staticmethod
    def apply_fake_packet_race(
        payload: bytes,
        ttl: int = 3,
        fooling: List[str] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает race-атаку: фейковый пакет + оригинал.
        
        Args:
            payload: Данные для отправки
            ttl: TTL для фейкового пакета
            fooling: Методы обмана ['badsum', 'md5sig', 'fakesni']
        
        Returns:
            [(fake_payload, 0, opts), (real_payload, 0, opts)]
        """
        if fooling is None:
            fooling = ["badsum"]
        
        opts_fake = {
            "is_fake": True,
            "ttl": ttl,
            "tcp_flags": 0x18,  # PSH+ACK
            "corrupt_tcp_checksum": "badsum" in fooling,
            "add_md5sig_option": "md5sig" in fooling,
            "delay_ms_after": 5
        }

        if "fakesni" in fooling:
            opts_fake["fooling_sni"] = _gen_fake_sni()
        
        opts_real = {
            "is_fake": False,
            "tcp_flags": 0x18  # PSH+ACK
        }
        
        return [
            (payload, 0, opts_fake),  # Фейковый пакет
            (payload, 0, opts_real)   # Оригинальный пакет
        ]

    @staticmethod
    def apply_fakeddisorder(
         payload: bytes,
         split_pos: int = 76,
         overlap_size: int = 0,  # ✅ По умолчанию 0 (не используется в modern zapret)
         fake_ttl: int = 1,
         fooling_methods: List[str] = None,
         delay_ms: int = 0
     ) -> List[Tuple[bytes, int, dict]]:
         """
         CRITICAL FIX: Реализация fakeddisorder в стиле zapret.
         
         Порядок отправки: fake (полный payload, TTL=1) -> part2 -> part1
         
         Args:
             payload: Полный payload для отправки
             split_pos: Позиция разделения (обычно середина SNI)
             overlap_size: Размер перекрытия (обычно 0 для fakeddisorder)
             fake_ttl: TTL для фейкового пакета (обычно 1-4)
             fooling_methods: Список методов обмана ['badsum', 'md5sig', 'badseq', 'fakesni']
             delay_ms: Задержка после фейкового пакета (миллисекунды)
         
         Returns:
             List[Tuple[bytes, int, dict]]: [(payload, offset, options), ...]
         """
         if fooling_methods is None:
             fooling_methods = ["badsum"]
 
         if split_pos >= len(payload):
             opts_real = {"is_fake": False, "tcp_flags": 0x18}
             return [(payload, 0, opts_real)]
 
         part1 = payload[:split_pos]
         part2 = payload[split_pos:]
 
         # Фейковый пакет - это всегда полный payload
         fake_payload = payload
 
         opts_fake = {
             "is_fake": True,
             "ttl": fake_ttl,
             "tcp_flags": 0x18,  # PSH+ACK
             "corrupt_tcp_checksum": "badsum" in fooling_methods,
             "delay_ms_after": delay_ms if delay_ms > 0 else 0
         }
 
         if "md5sig" in fooling_methods:
             opts_fake["add_md5sig_option"] = True
         if "badseq" in fooling_methods:
             # ✅ CRITICAL: Используем corrupt_sequence (читается в _recipe_to_specs)
             opts_fake["corrupt_sequence"] = True
 
         if "fakesni" in fooling_methods:
             opts_fake["fooling_sni"] = _gen_fake_sni()
 
         # ✅ ОБЕ части должны иметь PSH+ACK (0x18) для корректного reassembly
         opts_real1 = {"is_fake": False, "tcp_flags": 0x18}  # PSH+ACK
         opts_real2 = {"is_fake": False, "tcp_flags": 0x18}  # PSH+ACK
         
         # ✅ CRITICAL: Предотвращаем отрицательные offset через max()
         # Если overlap_size > 0, part2 начинается раньше для создания перекрытия
         # Если overlap_size = 0 (обычный случай), part2 начинается точно с split_pos
         real_part2_offset = max(split_pos - overlap_size, 0)
         
         # Правильный порядок отправки: fake, part2, part1
         return [
             (fake_payload, 0, opts_fake),           # offset=0 (начало исходного SEQ)
             (part2, real_part2_offset, opts_real2), # ✅ offset с защитой от отрицательных значений
             (part1, 0, opts_real1)                  # offset=0
         ]

    @staticmethod
    def apply_multidisorder(
        payload: bytes, 
        positions: List[int],
        split_pos: Optional[int] = None,
        overlap_size: int = 0,
        fooling: Optional[List[str]] = None,
        fake_ttl: int = 1
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Enhanced multidisorder attack with proper packet sequencing.
        
        Creates a sequence of packets:
        1. Fake packet with low TTL and fooling methods
        2. Disordered segments (part2 first, then part1)
        
        Args:
            payload: Original payload
            positions: Split positions (uses first for backward compatibility)
            split_pos: Explicit split position (overrides positions[0])
            overlap_size: Размер перекрытия (обычно 0)
            fooling: List of fooling methods ['badseq', 'badsum', 'md5sig', 'fakesni']
            fake_ttl: TTL for fake packet
            
        Returns:
            List of (segment_data, seq_offset, options) tuples
        """
        fooling = fooling or []
        
        # Determine split position
        if split_pos is not None:
            actual_split_pos = split_pos
        elif positions:
            actual_split_pos = positions[0]
        else:
            actual_split_pos = 3
        
        # Ensure split position is valid
        if actual_split_pos >= len(payload):
            actual_split_pos = len(payload) // 2
        
        # Split payload into two parts
        part1 = payload[:actual_split_pos]
        part2 = payload[actual_split_pos:]
        
        segments = []
        
        # Segment 1: Fake packet with low TTL and fooling
        fake_payload = payload  # ✅ Используем весь payload (как в zapret)
        fake_opts = {
            "is_fake": True,
            "ttl": fake_ttl,
            "tcp_flags": 0x18,  # PSH+ACK
            "corrupt_tcp_checksum": "badsum" in fooling,
            # ✅ CRITICAL: Используем corrupt_sequence для совместимости с _recipe_to_specs
            "corrupt_sequence": True if "badseq" in fooling else False,
            "add_md5sig_option": True if "md5sig" in fooling else False,
        }
        
        if "fakesni" in fooling:
            fake_opts["fooling_sni"] = _gen_fake_sni()
        
        segments.append((fake_payload, 0, fake_opts))
        
        # ✅ CRITICAL: Предотвращаем отрицательные offset
        if overlap_size > 0 and len(part1) > 0 and len(part2) > 0:
            actual_overlap = min(overlap_size, len(part1), len(part2))
            part2_seq_offset = max(actual_split_pos - actual_overlap, 0)
        else:
            part2_seq_offset = actual_split_pos
        
        # Segment 2: Part2 (first real segment, creates disorder)
        if len(part2) > 0:
            part2_opts = {
                "is_fake": False,
                "ttl": None,  # Use OS default
                "tcp_flags": 0x18,  # PSH+ACK
            }
            segments.append((part2, part2_seq_offset, part2_opts))
        
        # Segment 3: Part1 (second real segment, completes disorder)
        if len(part1) > 0:
            part1_opts = {
                "is_fake": False,
                "ttl": None,  # Use OS default
                "tcp_flags": 0x18,  # PSH+ACK
            }
            segments.append((part1, 0, part1_opts))
        
        return segments

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Разделяет payload на несколько сегментов по указанным позициям.
        """
        if not positions:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
            
        segments, last_pos = ([], 0)
        opts = {"is_fake": False, "tcp_flags": 0x18}  # PSH+ACK

        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos, opts))
                last_pos = pos
        
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos, opts))
            
        return segments

    @staticmethod
    def apply_seqovl(
        payload: bytes, split_pos: int = 3, overlap_size: int = 10
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает перекрытие последовательностей (sequence overlap).
        
        ✅ CRITICAL FIX: Правильная реализация с предотвращением отрицательных offset.
        """
        # ✅ Проверяем, что split_pos валиден с учетом overlap
        if split_pos >= len(payload) or split_pos - overlap_size < 0:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
        
        part1 = payload[:split_pos]
        
        # ✅ Вторая часть начинается раньше для создания перекрытия
        overlap_start = split_pos - overlap_size
        part2 = payload[overlap_start:]
        
        opts = {"is_fake": False, "tcp_flags": 0x18}  # PSH+ACK

        # ✅ Правильный порядок: part1 сначала, потом part2 с перекрытием
        return [
            (part1, 0, opts),              # Первая часть
            (part2, overlap_start, opts)   # Вторая часть (перекрывает конец первой)
        ]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        """
        Разделяет одну TLS-запись на две. Возвращает измененный payload.
        """
        try:
            if not payload or len(payload) < 5:
                return payload
            # Проверяем, что это TLS Handshake
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
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Эмулирует отправку данных маленькими порциями, как при маленьком TCP-окне.
        """
        segments, pos = ([], 0)
        opts = {"is_fake": False, "tcp_flags": 0x18}

        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos, opts))
            pos += chunk_size
            
        return segments

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        """
        Портит TCP checksum в пакете (legacy method).
        NOTE: Prefer using corrupt_tcp_checksum option in segments.
        """
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xDEAD)
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        """
        Портит TCP checksum значением, характерным для md5sig атак (legacy method).
        NOTE: Prefer using add_md5sig_option in segments.
        """
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xBEEF)
        return packet_data