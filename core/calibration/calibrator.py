# core/calibration/calibrator.py
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional

@dataclass
class CalibCandidate:
    split_pos: int
    overlap_size: int

class Calibrator:
    @staticmethod
    def estimate_split_pos_from_ch(payload: bytes) -> int:
        # Упрощенная эвристика для TLS ClientHello:
        # record hdr(5) + handshake hdr(4) + version(2) + random(32) = 43
        # session_id_len (1) + session_id(var)
        # попробуем дать чуть дальше 76 как стартовую точку
        if len(payload) < 64:
            return max(20, len(payload) // 2)
        return 76

    @staticmethod
    def estimate_overlap_size(part1_len: int, part2_len: int, split_pos: int) -> int:
        # Берём безопасное пересечение, ограниченное длиной part1/part2 и split_pos
        # а также даём разумный максимум 336
        if part1_len <= 0 or part2_len <= 0:
            return 0
        return min(336, part1_len, part2_len, split_pos)

    @staticmethod
    def prepare_candidates(payload: bytes, initial_split_pos: Optional[int] = None) -> List[CalibCandidate]:
        # Сформировать маленькую сетку: (sp±8) x overlap {64, 160, 336} (+ защита по длинам)
        est_sp = initial_split_pos if initial_split_pos else Calibrator.estimate_split_pos_from_ch(payload)
        sps = [max(16, est_sp - 8), est_sp, est_sp + 8]
        candidates: List[CalibCandidate] = []
        for sp in sps:
            sp = min(sp, len(payload) - 1) if len(payload) > 1 else sp
            part1_len = sp
            part2_len = max(0, len(payload) - sp)
            for ov in [64, 160, 336]:
                eff_ov = min(ov, part1_len, part2_len, sp)
                if eff_ov > 0:
                    candidates.append(CalibCandidate(split_pos=sp, overlap_size=eff_ov))
        # Уникализируем и сохраняем порядок
        seen = set()
        uniq: List[CalibCandidate] = []
        for c in candidates:
            key = (c.split_pos, c.overlap_size)
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        return uniq[:6]  # ограничим 6-ю комбинациями
