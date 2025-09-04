"""Калибратор для подбора оптимальных параметров обхода DPI."""

from dataclasses import dataclass
from typing import List, Optional
from core.protocols.tls import TLSParser, ClientHelloInfo

@dataclass
class CalibCandidate:
    """Кандидат для калибровки."""

    split_pos: int
    overlap_size: int

class Calibrator:
    """Калибратор для fakeddisorder."""

    @staticmethod
    def prepare_candidates(payload: bytes, initial_split_pos: int = 76) -> List[CalibCandidate]:
        """
        Подготавливает список кандидатов для тестирования.
        Теперь с учетом структуры TLS ClientHello.
        """
        candidates = []

        # Анализируем TLS структуру для умных позиций
        tls_parser = TLSParser()
        client_hello = tls_parser.parse_client_hello(payload)

        if client_hello:
            # Стратегические позиции на основе TLS структуры
            strategic_positions = []

            # Перед extensions - очень эффективная позиция
            if client_hello.extensions_start_pos > 0:
                strategic_positions.append(client_hello.extensions_start_pos - 1)

            # После session_id
            if hasattr(client_hello, 'session_id') and len(client_hello.session_id) > 0:
                # Позиция после session_id тоже хорошая
                strategic_positions.append(43 + 1 + len(client_hello.session_id))

            # Добавляем стратегические позиции как приоритетные кандидаты
            for pos in strategic_positions:
                if 10 < pos < len(payload) - 10:
                    candidates.append(CalibCandidate(split_pos=pos, overlap_size=336))
                    candidates.append(CalibCandidate(split_pos=pos, overlap_size=160))

        # Добавляем стандартные кандидаты
        candidates = []

        # Кандидаты по split_pos
        split_positions = [initial_split_pos] + [p for p in [3, 5, 8, 16, 32, 64, 76, 128, 256] if p != initial_split_pos]

        # Кандидаты по overlap_size
        overlap_sizes = [336, 160, 96, 64, 32, 16, 8]

        for sp in split_positions:
            if sp >= len(payload):
                continue
            part1_len = sp
            part2_len = len(payload) - sp

            for ov in overlap_sizes:
                if ov < min(part1_len, part2_len, sp):
                    candidates.append(CalibCandidate(split_pos=sp, overlap_size=ov))

        # Убираем дубликаты, сохраняя порядок
        seen = set()
        unique_candidates = []
        for c in candidates:
            if (c.split_pos, c.overlap_size) not in seen:
                seen.add((c.split_pos, c.overlap_size))
                unique_candidates.append(c)

        return unique_candidates[:20]  # Ограничиваем количество кандидатов
