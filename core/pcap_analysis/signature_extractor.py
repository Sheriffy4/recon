"""
DPI Signature Extractor - извлечение DPI сигнатур из PCAP трафика.

Этот модуль реализует:
- Извлечение сигнатур RST инъекций
- Извлечение сигнатур тайминга блокировок
- Извлечение сигнатур контента (TLS паттерны)
- Стабильное хеширование для signature_id (SHA256 вместо hash())

Requirements: FR-13.2, FR-13.3
Extracted from: intelligent_pcap_analyzer.py (Step 2 refactoring)

SECURITY FIX: Replaced hash() with hashlib.sha256() for stable signature IDs
- hash() can produce different values across Python sessions
- SHA256 provides stable, collision-resistant hashing
"""

import hashlib
import logging
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

# Попытка импорта Scapy с fallback
try:
    from scapy.all import TCP, IP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    TCP = IP = Raw = None

LOG = logging.getLogger("DPISignatureExtractor")


@dataclass
class DPISignature:
    """DPI сигнатура, извлеченная из трафика."""

    signature_id: str
    signature_type: str  # "rst_pattern", "timing_pattern", "content_pattern"
    pattern_data: Dict[str, Any]
    confidence: float
    detection_method: str
    samples_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass
class FlowAnalysis:
    """Минимальное определение FlowAnalysis для типизации."""

    blocking_detected: bool = False
    duration: float = 0.0


class DPISignatureExtractor:
    """
    Экстрактор DPI сигнатур.

    Извлекает характерные паттерны DPI блокировок для:
    - Создания профилей DPI систем
    - Обнаружения повторяющихся паттернов
    - Адаптации стратегий обхода
    """

    def __init__(self):
        """Инициализация экстрактора."""
        self.scapy_available = SCAPY_AVAILABLE
        if not self.scapy_available:
            LOG.warning("Scapy недоступен - извлечение сигнатур ограничено")

    async def extract_rst_signatures(self, packets: List) -> List[DPISignature]:
        """
        Извлечение сигнатур RST инъекций.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Список DPI сигнатур RST паттернов
        """
        if not self.scapy_available:
            return []

        signatures = []
        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]

        if rst_packets:
            # Создание сигнатуры RST паттерна
            ttl_values = [p[IP].ttl for p in rst_packets if IP in p]

            # FIX SR7: Используем SHA256 вместо hash() для стабильного ID
            signature_id = self._generate_stable_id("rst_pattern", ttl_values)

            signature = DPISignature(
                signature_id=signature_id,
                signature_type="rst_pattern",
                pattern_data={
                    "rst_count": len(rst_packets),
                    "ttl_values": ttl_values,
                    "timing_pattern": [p.time for p in rst_packets],
                },
                confidence=0.8,
                detection_method="rst_analysis",
                samples_count=len(rst_packets),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )

            signatures.append(signature)

        return signatures

    async def extract_timing_signatures(
        self, flow_analyses: List[FlowAnalysis]
    ) -> List[DPISignature]:
        """
        Извлечение сигнатур тайминга.

        Args:
            flow_analyses: Список анализов потоков

        Returns:
            Список DPI сигнатур тайминга
        """
        signatures = []

        # Анализ паттернов тайминга блокировок
        blocking_timings = []
        for flow in flow_analyses:
            if flow.blocking_detected and flow.duration > 0:
                blocking_timings.append(flow.duration)

        if blocking_timings:
            avg_timing = sum(blocking_timings) / len(blocking_timings)

            # FIX SR8: Используем SHA256 вместо hash() для стабильного ID
            signature_id = self._generate_stable_id("timing_pattern", blocking_timings)

            signature = DPISignature(
                signature_id=signature_id,
                signature_type="timing_pattern",
                pattern_data={
                    "average_blocking_time": avg_timing,
                    "timing_samples": blocking_timings,
                    "sample_count": len(blocking_timings),
                },
                confidence=0.6,
                detection_method="timing_analysis",
                samples_count=len(blocking_timings),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )

            signatures.append(signature)

        return signatures

    async def extract_content_signatures(self, packets: List) -> List[DPISignature]:
        """
        Извлечение сигнатур контента.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Список DPI сигнатур контента
        """
        if not self.scapy_available:
            return []

        signatures = []

        # Поиск паттернов в TLS трафике
        tls_patterns = []
        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                    tls_patterns.append(payload[:20])  # Первые 20 байт

        if tls_patterns:
            # FIX SR9: Используем SHA256 вместо hash() для стабильного ID
            signature_id = self._generate_stable_id("content_pattern", tls_patterns)

            signature = DPISignature(
                signature_id=signature_id,
                signature_type="content_pattern",
                pattern_data={
                    "tls_patterns": [p.hex() for p in tls_patterns],
                    "pattern_count": len(tls_patterns),
                },
                confidence=0.5,
                detection_method="content_analysis",
                samples_count=len(tls_patterns),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )

            signatures.append(signature)

        return signatures

    def _generate_stable_id(self, prefix: str, data: List) -> str:
        """
        Генерация стабильного ID на основе SHA256.

        Args:
            prefix: Префикс для ID (тип сигнатуры)
            data: Данные для хеширования

        Returns:
            Стабильный ID в формате "prefix_hash16"

        Note:
            Использует SHA256 вместо hash() для:
            - Стабильности между запусками Python
            - Отсутствия коллизий
            - Воспроизводимости результатов
        """
        # Конвертируем данные в строку для хеширования
        data_str = str(sorted(data)).encode("utf-8")

        # Вычисляем SHA256 хеш
        hash_obj = hashlib.sha256(data_str)
        hash_hex = hash_obj.hexdigest()

        # Берем первые 16 символов для компактности
        return f"{prefix}_{hash_hex[:16]}"
