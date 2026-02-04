"""
RST Analyzer - анализ RST пакетов для детекции DPI инъекций.

Этот модуль предоставляет функциональность для анализа RST (Reset) пакетов
и определения признаков активной инъекции RST со стороны DPI систем.
"""

import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict

from core.packet.raw_packet_engine import RawPacket, TCPHeader
from core.packet.packet_parser_utils import (
    parse_tcp_packet_headers,
    get_tcp_sequence_numbers,
    get_ip_ttl,
)

LOG = logging.getLogger("RSTAnalyzer")


class RSTAnalyzer:
    """
    Анализатор RST пакетов для детекции DPI инъекций.

    Основные индикаторы инъекции:
    - Множественные RST пакеты
    - Подозрительные TTL значения
    - Невалидные sequence/acknowledgment номера
    - Нереалистичное время прихода RST
    - Множественные источники RST для одного соединения
    """

    def analyze_rst_injection(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Детальный анализ RST пакетов для определения инъекции DPI.

        Args:
            rst_packets: Список RST пакетов (RawPacket)
            all_tcp_packets: Все TCP пакеты (RawPacket)

        Returns:
            Dict с результатами анализа RST инъекции
        """
        analysis = {
            "is_injection": False,
            "rst_count": len(rst_packets),
            "injection_indicators": [],
            "confidence": 0.0,
        }

        if not rst_packets:
            return analysis

        # Индикатор 1: Множественные RST пакеты
        if len(rst_packets) > 1:
            analysis["injection_indicators"].append("multiple_rst_packets")
            analysis["confidence"] += 0.3

        # Индикатор 2: Анализ TTL значений
        ttl_analysis = self.analyze_rst_ttl(rst_packets, all_tcp_packets)
        if ttl_analysis["suspicious_ttl"]:
            analysis["injection_indicators"].append("suspicious_ttl")
            analysis["confidence"] += 0.4

        # Индикатор 3: Анализ seq/ack номеров
        seq_analysis = self.analyze_rst_sequence_numbers(rst_packets, all_tcp_packets)
        if seq_analysis["invalid_sequence"]:
            analysis["injection_indicators"].append("invalid_sequence_numbers")
            analysis["confidence"] += 0.5

        # Индикатор 4: Временной анализ (RST приходит слишком быстро)
        timing_analysis = self.analyze_rst_timing(rst_packets, all_tcp_packets)
        if timing_analysis["too_fast"]:
            analysis["injection_indicators"].append("unrealistic_timing")
            analysis["confidence"] += 0.3

        # Индикатор 5: Анализ источника RST (разные IP для одного соединения)
        source_analysis = self.analyze_rst_sources(rst_packets)
        if source_analysis["multiple_sources"]:
            analysis["injection_indicators"].append("multiple_rst_sources")
            analysis["confidence"] += 0.6

        # Определяем инъекцию при уверенности > 0.5
        analysis["is_injection"] = analysis["confidence"] > 0.5

        return analysis

    def analyze_rst_ttl(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ TTL значений в RST пакетах для детекции инъекций.

        Args:
            rst_packets: Список RST пакетов
            all_tcp_packets: Все TCP пакеты для сравнения

        Returns:
            Dict с результатами анализа TTL
        """
        # Собираем базовые TTL по src для не-RST пакетов
        base_ttl = defaultdict(list)
        for p in all_tcp_packets:
            # Парсим заголовки используя утилиту
            headers = parse_tcp_packet_headers(p)
            if headers is None:
                continue

            ip_header, tcp_header, _ = headers

            # Проверяем, что это не RST пакет
            if not (tcp_header.flags & TCPHeader.FLAG_RST):
                base_ttl[p.src_ip].append(ip_header.ttl)

        base_ttl_median = {k: (sorted(v)[len(v) // 2] if v else None) for k, v in base_ttl.items()}

        suspicious = 0
        ttl_values = []
        for rst in rst_packets:
            ttl = get_ip_ttl(rst)
            if ttl is None:
                continue

            ttl_values.append(ttl)
            src = rst.src_ip
            ref = base_ttl_median.get(src)
            if ref is not None and abs(int(ttl) - int(ref)) >= 16:  # расхождение > ~16 хопов
                suspicious += 1

        return {
            "suspicious_ttl": suspicious > 0,
            "ttl_values": ttl_values,
            "suspicious_count": suspicious,
        }

    def analyze_rst_sequence_numbers(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ seq/ack номеров в RST пакетах.

        Args:
            rst_packets: Список RST пакетов
            all_tcp_packets: Все TCP пакеты для сравнения

        Returns:
            Dict с результатами анализа sequence номеров
        """
        # Собираем легитимные seq/ack номера из соединения
        legitimate_seqs = set()
        legitimate_acks = set()

        for pkt in all_tcp_packets:
            headers = parse_tcp_packet_headers(pkt)
            if headers is None:
                continue

            _, tcp_header, _ = headers

            # Исключаем RST пакеты
            if not (tcp_header.flags & TCPHeader.FLAG_RST):
                legitimate_seqs.add(tcp_header.seq_num)
                legitimate_acks.add(tcp_header.ack_num)

        invalid_count = 0
        for rst in rst_packets:
            seq_ack = get_tcp_sequence_numbers(rst)
            if seq_ack is None:
                continue

            seq_num, ack_num = seq_ack

            # RST должен иметь валидные seq/ack номера
            if seq_num not in legitimate_seqs and ack_num not in legitimate_acks:
                invalid_count += 1

        return {
            "invalid_sequence": invalid_count > 0,
            "invalid_count": invalid_count,
            "total_rst": len(rst_packets),
        }

    def analyze_rst_timing(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ временных характеристик RST пакетов.

        Note: RawPacket не содержит временные метки, поэтому анализ времени ограничен.
        Возвращаем консервативные результаты.

        Args:
            rst_packets: Список RST пакетов
            all_tcp_packets: Все TCP пакеты

        Returns:
            Dict с результатами временного анализа
        """
        # TODO: Добавить поддержку временных меток в RawPacket для точного анализа
        return {
            "too_fast": False,
            "fast_rst_count": 0,
            "note": "Timing analysis requires timestamp support in RawPacket",
        }

    def analyze_rst_sources(self, rst_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Анализ источников RST пакетов.

        Args:
            rst_packets: Список RST пакетов (RawPacket)

        Returns:
            Dict с информацией об источниках RST
        """
        sources = set()

        for rst in rst_packets:
            sources.add(rst.src_ip)

        return {
            "multiple_sources": len(sources) > 1,
            "source_count": len(sources),
            "sources": list(sources),
        }

    def compute_block_index(self, tcp_packets: List[RawPacket]) -> Optional[int]:
        """
        Индекс пакета после которого произошла блокировка (первый RST или конец данных).

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            Индекс первого RST пакета или None
        """
        for idx, p in enumerate(tcp_packets):
            headers = parse_tcp_packet_headers(p)
            if headers is None:
                continue

            _, tcp_header, _ = headers

            if tcp_header.flags & TCPHeader.FLAG_RST:
                return idx
        return None
