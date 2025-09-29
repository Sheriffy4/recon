# path: core/bypass/techniques/primitives.py
# CORRECTED VERSION

import struct
import os
import random
import string
from typing import List, Tuple, Dict, Optional

def _gen_fake_sni(original: Optional[str] = None) -> str:
    # zapret-подобный стиль: случайный label + .edu
    # можешь заменить на .com/.net по вкусу или подстраиваться под TLD оригинала
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 14)))
    tld = "edu"
    return f"{label}.{tld}"

class BypassTechniques:
    """
    Библиотека продвинутых техник обхода DPI.
    Генерирует "рецепты" - последовательности сегментов для отправки.
    """

    @staticmethod
    def apply_fake_packet_race(
        payload: bytes,
        ttl: int = 3,
        fooling: List[str] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает race-атаку: фейковый пакет + оригинал.
        """
        if fooling is None:
            fooling = ["badsum"]
        
        opts_fake = {
            "is_fake": True,
            "ttl": ttl,
            "tcp_flags": 0x18,  # PSH+ACK
            "corrupt_tcp_checksum": "badsum" in fooling,
            "add_md5sig_option": "md5sig" in fooling,
            "delay_ms_after": 5  # Небольшая задержка перед отправкой оригинала
        }

        if "fakesni" in (fooling or []):
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
        overlap_size: int = 336,
        fake_ttl: int = 1,
        fooling_methods: List[str] = None,
        delay_ms: int = 5
    ) -> List[Tuple[bytes, int, dict]]:
        """
        CRITICAL FIX: Реализация fakeddisorder в стиле zapret.
        1. Fake-пакет - это ПОЛНЫЙ payload с испорченной checksum.
        2. Реальные пакеты делятся и отправляются в неправильном порядке (disorder).
        3. Второй реальный пакет отправляется со смещением для перекрытия (overlap).
        """
        if fooling_methods is None:
            fooling_methods = ["badsum"]

        if split_pos >= len(payload):
            # Если позиция разделения некорректна, отправляем один нормальный пакет.
            opts_real = {"is_fake": False, "tcp_flags": 0x18}
            return [(payload, 0, opts_real)]

        part1, part2 = (payload[:split_pos], payload[split_pos:])

        # Фейковый пакет - это всегда полный payload.
        fake_payload = payload

        opts_fake = {
            "is_fake": True,
            "ttl": fake_ttl,
            "tcp_flags": 0x18,  # PSH+ACK
            "seq_offset": 0,
            "corrupt_tcp_checksum": True,  # Обязательно для badsum и как базовый fooling
            "delay_ms_after": delay_ms
        }

        # Применяем дополнительные методы fooling к фейковому пакету
        if "md5sig" in fooling_methods:
            opts_fake["add_md5sig_option"] = True
        if "badseq" in fooling_methods:
            opts_fake["corrupt_sequence"] = True # Указываем билдеру, что нужен неверный seq
            opts_fake["seq_offset"] = -1 # Явное смещение для builder'a

        if "fakesni" in fooling_methods:
            opts_fake["fooling_sni"] = _gen_fake_sni()

        # Параметры для реальных сегментов
        opts_real1 = {"is_fake": False, "tcp_flags": 0x10} # ACK
        opts_real2 = {"is_fake": False, "tcp_flags": 0x18} # PSH+ACK
        
        # Правильный расчет смещения для второго реального пакета с учетом overlap
        real_part2_offset = len(part1) - overlap_size

        # Правильный порядок отправки: fake, real_part2, real_part1
        return [
            (fake_payload, 0, opts_fake),            # 1. Фейковый пакет (полный)
            (part2, real_part2_offset, opts_real2),  # 2. Вторая часть (с перекрытием)
            (part1, 0, opts_real1)                   # 3. Первая часть (отправляется последней)
        ]

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Разделяет payload на несколько сегментов по указанным позициям.
        """
        if not positions:
            return [(payload, 0, {"is_fake": False})]
            
        segments, last_pos = ([], 0)
        opts = {"is_fake": False, "tcp_flags": 0x18} # PSH+ACK

        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos, opts))
                last_pos = pos
        
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos, opts))
            
        return segments

    @staticmethod
    def apply_multidisorder(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Разделяет payload и отправляет сегменты в обратном порядке.
        """
        segments = BypassTechniques.apply_multisplit(payload, positions)
        return segments[::-1] if len(segments) > 1 else segments

    @staticmethod
    def apply_seqovl(
        payload: bytes, split_pos: int = 3, overlap_size: int = 10
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Создает перекрытие последовательностей (sequence overlap).
        """
        if split_pos >= len(payload):
            return [(payload, 0, {"is_fake": False})]
            
        part1, part2 = (payload[:split_pos], payload[split_pos:])
        overlap_data = b"\x00" * overlap_size
        part1_with_overlap = overlap_data + part1
        
        opts = {"is_fake": False, "tcp_flags": 0x18}

        return [
            (part2, split_pos, opts), 
            (part1_with_overlap, -overlap_size, opts)
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
        Портит TCP checksum в пакете.
        """
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xDEAD)
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        """
        Портит TCP checksum значением, характерным для md5sig атак.
        """
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xBEEF)
        return packet_data