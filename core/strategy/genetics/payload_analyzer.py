"""
Payload analysis for intelligent split position selection.
"""

from __future__ import annotations

import logging
import random
from typing import List, Optional
from dataclasses import dataclass, field

LOG = logging.getLogger("PayloadAnalyzer")


@dataclass
class PayloadAnalysisResult:
    """Результат анализа payload для интеллектуального выбора позиций split."""

    payload_type: str  # "tls_client_hello", "http_request", "generic"
    total_length: int

    # Критические позиции
    critical_positions: List[int] = field(default_factory=list)
    safe_split_positions: List[int] = field(default_factory=list)
    avoid_positions: List[int] = field(default_factory=list)

    # Анализ содержимого
    contains_sni: bool = False
    sni_position: Optional[int] = None
    contains_host_header: bool = False
    host_header_position: Optional[int] = None

    # Рекомендации
    recommended_split_positions: List[int] = field(default_factory=list)
    split_strategy: str = "random"  # "random", "targeted", "multi_point"


class PayloadAnalyzer:
    """Анализатор payload для выбора оптимальных позиций split."""

    def detect_payload_type(self, payload: bytes) -> str:
        """Автоопределение типа payload."""
        if len(payload) > 5:
            # TLS Client Hello
            if payload[0] == 0x16 and payload[1] == 0x03:
                return "tls_client_hello"

            # HTTP запрос
            if (
                payload.startswith(b"GET ")
                or payload.startswith(b"POST ")
                or payload.startswith(b"PUT ")
            ):
                return "http_request"

        return "generic"

    async def analyze_tls_client_hello(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ TLS Client Hello для выбора позиций split."""
        try:
            avoid = set(analysis.avoid_positions)
            # Поиск SNI extension
            sni_position = payload.find(b"\x00\x00")  # Упрощенный поиск SNI
            if sni_position != -1:
                analysis.contains_sni = True
                analysis.sni_position = sni_position
                if sni_position not in analysis.critical_positions:
                    analysis.critical_positions.append(sni_position)

                # Позиции до и после SNI - критические
                for p in (sni_position - 1, sni_position, sni_position + 1):
                    if 0 <= p < len(payload):
                        avoid.add(p)

            # Безопасные позиции для split
            safe_positions = []
            for i in range(5, len(payload) - 5, 10):  # Каждые 10 байт, избегая краев
                if i not in avoid:
                    safe_positions.append(i)

            analysis.safe_split_positions = safe_positions[:10]  # Максимум 10 позиций
            analysis.avoid_positions = sorted(avoid)

        except Exception as e:
            LOG.error("TLS Client Hello analysis failed: %s", e, exc_info=True)

    async def analyze_http_request(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ HTTP запроса для выбора позиций split."""
        try:
            payload_str = payload.decode("utf-8", errors="ignore")
            avoid = set(analysis.avoid_positions)

            # Поиск Host заголовка
            host_match = payload_str.find("Host:")
            if host_match != -1:
                analysis.contains_host_header = True
                analysis.host_header_position = host_match
                if host_match not in analysis.critical_positions:
                    analysis.critical_positions.append(host_match)

                # Избегаем split в области Host заголовка
                start = max(host_match - 5, 0)
                end = min(host_match + 50, len(payload_str))
                avoid.update(range(start, end))

            # Безопасные позиции - между заголовками
            lines = payload_str.split("\r\n")
            current_pos = 0

            for line in lines:
                if line and not line.startswith("Host:"):
                    # Позиция в конце строки - безопасна для split
                    line_end = current_pos + len(line)
                    if line_end not in avoid:
                        analysis.safe_split_positions.append(line_end)

                current_pos += len(line) + 2  # +2 для \r\n
            analysis.avoid_positions = sorted(avoid)

        except Exception as e:
            LOG.error("HTTP request analysis failed: %s", e, exc_info=True)

    async def analyze_generic_payload(self, payload: bytes, analysis: PayloadAnalysisResult):
        """Анализ общего payload для выбора позиций split."""
        # Простая стратегия - равномерное распределение позиций
        step = max(len(payload) // 10, 1)

        for i in range(step, len(payload) - step, step):
            analysis.safe_split_positions.append(i)

    def generate_split_recommendations(self, analysis: PayloadAnalysisResult):
        """Генерация рекомендаций по позициям split."""
        if analysis.contains_sni or analysis.contains_host_header:
            # Целевая стратегия - избегаем критических позиций
            analysis.split_strategy = "targeted"
            analysis.recommended_split_positions = analysis.safe_split_positions[:5]
        else:
            # Случайная стратегия
            analysis.split_strategy = "random"
            if analysis.safe_split_positions:
                analysis.recommended_split_positions = random.sample(
                    analysis.safe_split_positions, min(5, len(analysis.safe_split_positions))
                )
            else:
                # Fallback - равномерное распределение
                step = max(analysis.total_length // 5, 1)
                analysis.recommended_split_positions = list(
                    range(step, analysis.total_length, step)
                )[:5]
