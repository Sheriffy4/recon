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
         
         Returns:
             List[Tuple[bytes, int, dict]]: List of (payload, offset, options)
         """
         if fooling_methods is None:
             fooling_methods = ["badsum"]
 
         if split_pos >= len(payload):
             opts_real = {"is_fake": False, "tcp_flags": 0x18}
             return [(payload, 0, opts_real)]
 
         part1, part2 = (payload[:split_pos], payload[split_pos:])
 
         # Фейковый пакет - это всегда полный payload.
         fake_payload = payload
 
         opts_fake = {
             "is_fake": True,
             "ttl": fake_ttl,
             "tcp_flags": 0x18,  # PSH+ACK
             "corrupt_tcp_checksum": "badsum" in fooling_methods,
             "delay_ms_after": delay_ms
         }
 
         if "md5sig" in fooling_methods:
             opts_fake["add_md5sig_option"] = True
         if "badseq" in fooling_methods:
             opts_fake["seq_extra"] = -1
 
         if "fakesni" in fooling_methods:
             opts_fake["fooling_sni"] = _gen_fake_sni()
 
         opts_real1 = {"is_fake": False, "tcp_flags": 0x10}  # ACK
         opts_real2 = {"is_fake": False, "tcp_flags": 0x18}  # PSH+ACK
         
         real_part2_offset = len(part1) - overlap_size
 
         # Правильный порядок отправки: fake, real_part2, real_part1
         return [
             (fake_payload, 0, opts_fake),
             (part2, real_part2_offset, opts_real2),
             (part1, 0, opts_real1)
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
        1. Fake packet with low TTL and fooling methods (badseq, badsum, etc.)
        2. Overlapping segments in disorder (part2 first, then part1)
        
        This matches the Zapret multidisorder behavior for x.com bypass.
        
        Args:
            payload: Original payload to split
            positions: Split positions (for backward compatibility, uses first position)
            split_pos: Explicit split position (overrides positions[0])
            overlap_size: Size of sequence overlap between segments
            fooling: List of fooling methods to apply (badseq, badsum, md5sig)
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
        fake_payload = BypassTechniques._generate_fake_payload(payload, len(part1))
        fake_opts = {
            "is_fake": True,
            "ttl": fake_ttl,
            "tcp_flags": 0x18,  # PSH+ACK
            "corrupt_tcp_checksum": "badsum" in fooling,
            "seq_offset": -10000 if "badseq" in fooling else 0,
            "add_md5sig": "md5sig" in fooling,
        }
        segments.append((fake_payload, 0, fake_opts))
        
        # Calculate sequence offset for overlapping segments
        if overlap_size > 0 and len(part1) > 0 and len(part2) > 0:
            # Overlap: part2 starts earlier to create sequence overlap
            actual_overlap = min(overlap_size, len(part1), len(part2))
            part2_seq_offset = actual_split_pos - actual_overlap
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
    def _generate_fake_payload(original_payload: bytes, target_size: int) -> bytes:
        """
        Generate a fake payload for the fake packet.
        
        Creates a plausible-looking payload that will be dropped by DPI
        due to low TTL, but looks legitimate enough to trigger DPI inspection.
        
        Args:
            original_payload: Original payload to base fake on
            target_size: Target size for fake payload
            
        Returns:
            Fake payload bytes
        """
        if len(original_payload) < 6:
            # Too short, just return some generic data
            return b'\x16\x03\x01\x00\x00' + b'\x00' * max(0, target_size - 5)
        
        # Check if it's TLS
        if original_payload[0] == 0x16 and original_payload[1] == 0x03:
            # TLS - create a fake TLS record
            tls_version = original_payload[1:3]
            fake_content = b'\x00' * min(target_size, 100)
            fake_len = len(fake_content).to_bytes(2, 'big')
            return b'\x16' + tls_version + fake_len + fake_content
        
        # Generic fake - slightly modify original
        fake_size = min(len(original_payload), target_size)
        fake_payload = bytearray(original_payload[:fake_size])
        
        # Modify every 10th byte to make it "fake"
        for i in range(0, len(fake_payload), 10):
            fake_payload[i] = (fake_payload[i] + 1) % 256
        
        return bytes(fake_payload)

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