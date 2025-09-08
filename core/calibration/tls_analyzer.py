"""
Анализатор структуры TLS ClientHello для интеллектуального выбора split_pos
"""

import struct
from typing import Optional, List
from dataclasses import dataclass

@dataclass
class TlsStructure:
    """Структура TLS ClientHello"""
    record_header_end: int = 5
    handshake_header_end: int = 9
    version_end: int = 11
    random_end: int = 43
    session_id_end: Optional[int] = None
    cipher_suites_end: Optional[int] = None
    compression_end: Optional[int] = None
    extensions_start: Optional[int] = None
    sni_start: Optional[int] = None
    sni_end: Optional[int] = None

    def get_strategic_split_positions(self) -> List[int]:
        """Возвращает стратегические позиции для разделения"""
        positions = []
        positions.append(self.record_header_end)
        positions.append(self.handshake_header_end)
        positions.append((self.version_end + self.random_end) // 2)
        if self.session_id_end:
            positions.append(self.session_id_end)
        if self.extensions_start and self.extensions_start > 50:
            positions.append(self.extensions_start - 1)
        if self.sni_start and self.sni_end:
            positions.append((self.sni_start + self.sni_end) // 2)
        return sorted(set(positions))

class TlsAnalyzer:
    """Анализатор TLS пакетов"""

    @staticmethod
    def analyze_clienthello(payload: bytes) -> Optional[TlsStructure]:
        """Анализирует структуру TLS ClientHello"""
        if len(payload) < 43 or payload[0] != 22 or payload[5] != 1:
            return None
        structure = TlsStructure()
        try:
            pos = 43
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len
                structure.session_id_end = pos
            if pos + 2 <= len(payload):
                cipher_suites_len = struct.unpack('>H', payload[pos:pos+2])[0]
                pos += 2 + cipher_suites_len
                structure.cipher_suites_end = pos
            if pos < len(payload):
                compression_len = payload[pos]
                pos += 1 + compression_len
                structure.compression_end = pos
            if pos + 2 <= len(payload):
                structure.extensions_start = pos
        except Exception:
            pass
        return structure

    @staticmethod
    def estimate_optimal_split_pos(payload: bytes) -> int:
        """Оценивает оптимальную позицию разделения"""
        structure = TlsAnalyzer.analyze_clienthello(payload)
        if not structure:
            return min(76, len(payload) // 2)
        positions = structure.get_strategic_split_positions()
        if not positions:
            return 76
        target = 76
        return min(positions, key=lambda x: abs(x - target))
