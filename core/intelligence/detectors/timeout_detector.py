"""
Детектор connection timeout паттернов

Реализует детекцию:
- Connection timeout
- Большие паузы в трафике
- Повторные попытки соединения
"""

from __future__ import annotations

import logging
from typing import List, Dict

from .base import BaseDetector

# Scapy imports with fallback
SCAPY_AVAILABLE = False
try:
    from scapy.all import TCP

    SCAPY_AVAILABLE = True
except ImportError:
    TCP = None

LOG = logging.getLogger("TimeoutDetector")


class TimeoutDetector(BaseDetector):
    """Детектор connection timeout паттернов"""

    def __init__(self):
        self.min_confidence = 0.3
        self.large_gap_threshold_s = 5.0
        self.long_duration_threshold_s = 30.0

    async def detect(
        self, packets: List, domain: str, target_ip: str
    ) -> List:  # List[BlockingEvidence]
        """Детекция connection timeout паттернов"""
        # Import here to avoid circular dependency
        from ..blocking_pattern_detector import BlockingEvidence, BlockingPattern

        evidence_list = []

        if not SCAPY_AVAILABLE or TCP is None:
            return evidence_list

        try:
            if not packets:
                return evidence_list

            # Анализируем временные интервалы
            timestamps = [float(p.time) for p in packets]
            timestamps.sort()

            # Ищем большие паузы в трафике
            large_gaps = []
            for i in range(1, len(timestamps)):
                gap = timestamps[i] - timestamps[i - 1]
                if gap > self.large_gap_threshold_s:
                    large_gaps.append(gap)

            # Анализируем TCP флаги для поиска повторных попыток
            syn_packets = [p for p in packets if TCP in p and p[TCP].flags.S]
            retransmissions = len(syn_packets) - 1 if len(syn_packets) > 1 else 0

            confidence = 0.0
            timeout_indicators = []

            if large_gaps:
                timeout_indicators.append(f"large_gaps_count_{len(large_gaps)}")
                confidence += min(len(large_gaps) * 0.2, 0.6)

            if retransmissions > 0:
                timeout_indicators.append(f"syn_retransmissions_{retransmissions}")
                confidence += min(retransmissions * 0.1, 0.4)

            # Проверяем общую продолжительность соединения
            if timestamps:
                total_duration = max(timestamps) - min(timestamps)
                if (
                    total_duration > self.long_duration_threshold_s and len(packets) < 10
                ):  # Долгое соединение с малым количеством пакетов
                    timeout_indicators.append("long_duration_few_packets")
                    confidence += 0.3

            # Создаем evidence если найдены индикаторы
            if timeout_indicators and confidence > self.min_confidence:
                evidence = BlockingEvidence(
                    pattern=BlockingPattern.CONNECTION_TIMEOUT,
                    confidence=min(confidence, 1.0),
                    evidence_data={
                        "domain": domain,
                        "target_ip": target_ip,
                        "timeout_indicators": timeout_indicators,
                        "large_gaps_count": len(large_gaps),
                        "syn_retransmissions": retransmissions,
                        "total_duration": max(timestamps) - min(timestamps) if timestamps else 0,
                    },
                    timing_analysis={
                        "large_gaps": large_gaps[:5],  # Первые 5 больших пауз
                        "total_packets": len(packets),
                        "syn_packets": len(syn_packets),
                    },
                )
                evidence_list.append(evidence)

        except Exception as e:
            LOG.exception("Ошибка детекции connection timeout")

        return evidence_list
