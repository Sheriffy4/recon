# path: core/bypass/techniques/primitives.py
# ULTIMATE CORRECTED VERSION - Best of both approaches

import struct
import random
import string
import logging
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
    """
    
    # Маркер версии для диагностики
    API_VER = "primitives ULTIMATE-2025-10-17"

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
            "tcp_flags": 0x18,
            "corrupt_tcp_checksum": "badsum" in fooling,
            "add_md5sig_option": "md5sig" in fooling,
            "delay_ms_after": 5
        }

        if "fakesni" in fooling:
            opts_fake["fooling_sni"] = _gen_fake_sni()
        
        opts_real = { "is_fake": False, "tcp_flags": 0x18 }
        
        return [
            (payload, 0, opts_fake),
            (payload, 0, opts_real)
        ]

    # --- START OF FIX: UNIFIED AND CORRECTED fakeddisorder LOGIC ---
    @staticmethod
    def apply_fakeddisorder(
        payload: bytes,
        split_pos: int,
        fake_ttl: int,
        fooling_methods: Optional[List[str]] = None,
        **kwargs # Принимаем и игнорируем лишние параметры, такие как overlap_size
    ) -> List[Tuple[bytes, int, dict]]:
        """
        ОКОНЧАТЕЛЬНАЯ УНИФИЦИРОВАННАЯ ВЕРСИЯ:
        Эта функция теперь реализует ТОЛЬКО доказанно работающую логику "fakeddisorder",
        которая помогла в режиме службы:
        1. Отправляется фейковый пакет, содержащий ВЕСЬ ClientHello.
        2. Затем отправляются два реальных сегмента в неправильном порядке (disorder).
        3. Параметр `overlap_size` намеренно игнорируется, чтобы предотвратить активацию
           ошибочной логики `seqovl`.
        """
        log = logging.getLogger("BypassTechniques")
        L = len(payload)
        
        if L < 2:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]

        if split_pos >= L:
            log.warning(f"split_pos {split_pos} >= payload size {L}, adjusting to {L // 2}")
            split_pos = L // 2
            
        sp = max(1, min(int(split_pos), L - 1))
        
        fool = fooling_methods if fooling_methods is not None else ["badsum"]
        if not fool:
            fool = ["badsum"]

        opts_fake = {
            "is_fake": True, "ttl": int(fake_ttl), "tcp_flags": 0x18,
            "corrupt_tcp_checksum": "badsum" in fool,
            "add_md5sig_option": "md5sig" in fool,
            "seq_extra": -1 if "badseq" in fool else 0,
            "delay_ms_after": 5
        }
        opts_real = {"is_fake": False, "tcp_flags": 0x18}

        # --- ЕДИНСТВЕННАЯ ПРАВИЛЬНАЯ ЛОГИКА ДЛЯ FAKEDDISORDER ---
        part1 = payload[:sp]
        part2 = payload[sp:]
        
        # Ключ к успеху для x.com: фейковый пакет содержит ВЕСЬ ClientHello.
        fake_payload = payload 
        
        log.info(
            f"✅ UNIFIED fakeddisorder: "
            f"fake_full_payload={len(fake_payload)}b@0 (ttl={fake_ttl}), "
            f"real_part2={len(part2)}b@{sp}, "
            f"real_part1={len(part1)}b@0"
        )
        
        return [
            (fake_payload, 0, opts_fake),
            (part2, sp, opts_real),
            (part1, 0, opts_real),
        ]
    # --- END OF FIX ---

    @staticmethod
    def apply_seqovl(
        payload: bytes,
        split_pos: int,
        overlap_size: int,
        fake_ttl: int,
        fooling_methods: Optional[List[str]] = None,
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Правильная, отдельная реализация атаки Sequence Overlap (seqovl).
        """
        log = logging.getLogger("BypassTechniques")
        L = len(payload)
        
        if L < 2:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]

        sp = max(1, min(int(split_pos), L - 1))
        ovl = max(1, int(overlap_size)) # seqovl должен иметь перекрытие

        fool = fooling_methods if fooling_methods is not None else ["badsum"]

        opts_fake = {
            "is_fake": True, "ttl": int(fake_ttl), "tcp_flags": 0x18,
            "corrupt_tcp_checksum": "badsum" in fool,
            "add_md5sig_option": "md5sig" in fool,
            "seq_extra": -1 if "badseq" in fool else 0,
            "delay_ms_after": 5
        }
        opts_real = {"is_fake": False, "tcp_flags": 0x18}

        # Правильный расчет для seqovl
        start_offset = max(0, sp - ovl)
        overlap_part = payload[start_offset : sp]
        real_full = payload
        
        log.info(
            f"✅ Corrected Seqovl: "
            f"fake_ovl={len(overlap_part)}b@{start_offset} (ttl={fake_ttl}), "
            f"real_full={len(real_full)}b@0"
        )
        
        return [
            (overlap_part, start_offset, opts_fake),
            (real_full, 0, opts_real),
        ]

    @staticmethod
    def apply_multidisorder(
        payload: bytes,
        positions: List[int],
        fooling: Optional[List[str]] = None,
        fake_ttl: int = 1
    ) -> List[Tuple[bytes, int, dict]]:
        """
        РЕАЛИЗАЦИЯ V15 (True Multidisorder):
        - Нарезает payload на множество фрагментов по списку positions.
        - Отправляет маленький "отравляющий" фейковый пакет.
        - Отправляет реальные фрагменты в обратном порядке для максимального хаоса.
        """
        log = logging.getLogger("BypassTechniques")
        fooling = fooling if fooling is not None else ["badsum", "badseq"]
        L = len(payload)

        if not positions or L < 2:
            log.warning("Multidisorder called with no positions, falling back to simple disorder.")
            return BypassTechniques.apply_fakeddisorder(payload, L // 2, fake_ttl, fooling)

        # 1. Создаем "отравляющий" фейковый пакет (очень маленький)
        fake_size = min(positions) if positions else 1
        fake_payload = payload[:fake_size]
        opts_fake = {
            "is_fake": True, "ttl": int(fake_ttl), "tcp_flags": 0x18,
            "corrupt_tcp_checksum": "badsum" in fooling,
            "add_md5sig_option": "md5sig" in fooling,
            "seq_extra": -1 if "badseq" in fooling else 0,
            "delay_ms_after": 5
        }
        segments = [(fake_payload, 0, opts_fake)]

        # 2. Нарезаем реальный payload на фрагменты
        all_splits = sorted(list(set([0] + [p for p in positions if 0 < p < L] + [L])))
        real_fragments = []
        for i in range(len(all_splits) - 1):
            start, end = all_splits[i], all_splits[i+1]
            if start < end:
                real_fragments.append((payload[start:end], start))

        # 3. Добавляем реальные фрагменты в ОБРАТНОМ порядке
        log.info(
            f"✅ V15 True Multidisorder: fake_part={len(fake_payload)}b, "
            f"then {len(real_fragments)} real fragments in reverse order."
        )
        opts_real = {"is_fake": False, "tcp_flags": 0x18}
        for data, offset in reversed(real_fragments):
            segments.append((data, offset, opts_real))
            
        return segments

    @staticmethod
    def apply_multisplit(
        payload: bytes, 
        positions: List[int],
        fooling: Optional[List[str]] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Улучшенная версия multisplit:
        - Добавляет небольшие задержки между сегментами.
        - Позволяет использовать badsum на первом сегменте для создания "фрагментированной гонки".
        """
        if not positions:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
        
        fooling = fooling or []
        flags_pattern = [0x10, 0x18]
        
        segments, last_pos = ([], 0)
        opts_base = {"is_fake": False}
        
        sorted_positions = sorted(list(set(p for p in positions if 0 < p < len(payload))))
        
        if not sorted_positions:
             return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]

        all_positions = [0] + sorted_positions + [len(payload)]

        for i in range(len(all_positions) - 1):
            start_pos = all_positions[i]
            end_pos = all_positions[i+1]
            
            segment_data = payload[start_pos:end_pos]
            if not segment_data:
                continue

            tcp_flags = flags_pattern[i % len(flags_pattern)]
            opts = {**opts_base, "tcp_flags": tcp_flags}

            # Добавляем задержку после каждого сегмента, кроме последнего
            if i < len(all_positions) - 2:
                opts["delay_ms_after"] = random.randint(5, 15)

            # Применяем badsum к первому сегменту, если указано
            if i == 0 and "badsum" in fooling:
                opts["corrupt_tcp_checksum"] = True
                logging.getLogger("BypassTechniques").info("🔥 Multisplit with badsum race enabled.")

            segments.append((segment_data, start_pos, opts))
            
        return segments
    
    @staticmethod
    def apply_disorder(
        payload: bytes,
        split_pos: int,
        ack_first: bool = False
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Простой disorder без фейкового пакета.
        Отправляет два реальных сегмента в неправильном порядке.
        """
        log = logging.getLogger("BypassTechniques")
        L = len(payload)
        
        if L < 2:
            return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
            
        sp = max(1, min(int(split_pos), L - 1))
        part1 = payload[:sp]
        part2 = payload[sp:]
        
        # Определяем флаги TCP для первого пакета
        first_flags = 0x10 if ack_first else 0x18  # ACK или PSH+ACK
        
        opts_real = {"is_fake": False, "tcp_flags": 0x18}
        opts_first = {"is_fake": False, "tcp_flags": first_flags}
        
        log.info(f"✅ Simple disorder: part2={len(part2)}b@{sp}, part1={len(part1)}b@0 (ack_first={ack_first})")
        
        return [
            (part2, sp, opts_first),
            (part1, 0, opts_real),
        ]

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
    ) -> List[Tuple[bytes, int, dict]]:
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
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xDEAD)
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack("!H", 0xBEEF)
        return packet_data