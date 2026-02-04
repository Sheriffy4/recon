"""
Fragmentation Analyzer - анализ эффективности стратегий фрагментации.

Этот модуль предоставляет функциональность для анализа фрагментации пакетов
и определения, собирает ли DPI фрагменты обратно.
"""

import logging
from typing import Dict, List, Any

from core.packet.raw_packet_engine import RawPacket, IPHeader, TCPHeader
from core.packet.packet_parser_utils import has_tcp_flag

LOG = logging.getLogger("FragmentationAnalyzer")


class FragmentationAnalyzer:
    """
    Анализатор эффективности стратегий фрагментации.

    Основные функции:
    - Детекция фрагментированных пакетов
    - Определение сборки фрагментов DPI
    - Анализ блокировки после reassembly
    """

    def is_fragmentation_strategy(self, strategy) -> bool:
        """
        Проверка, является ли стратегия основанной на фрагментации.

        Args:
            strategy: Объект стратегии с атрибутами name и attack_name

        Returns:
            bool - True если стратегия использует фрагментацию
        """
        fragmentation_keywords = [
            "split",
            "frag",
            "multisplit",
            "disorder",
            "fragment",
            "chunk",
            "piece",
        ]

        strategy_name = strategy.name.lower()
        attack_name = strategy.attack_name.lower()

        return any(
            keyword in strategy_name or keyword in attack_name for keyword in fragmentation_keywords
        )

    def analyze_fragmentation_effectiveness(
        self, tcp_packets: List[RawPacket], strategy
    ) -> Dict[str, Any]:
        """
        Анализ эффективности стратегий фрагментации.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            strategy: Стратегия обхода

        Returns:
            Dict с результатами анализа фрагментации
        """
        analysis = {
            "fragments_reassembled": False,
            "fragmented_packets_count": 0,
            "reassembly_indicators": [],
            "confidence": 0.0,
        }

        # Подсчет фрагментированных пакетов (избегаем двойного счета)
        fragmented_packets = []
        fragmented_ids = set()

        for packet in tcp_packets:
            if len(packet.data) >= 20:
                try:
                    ip_header = IPHeader.unpack(packet.data[:20])
                    # IP фрагментация (MF flag or fragment offset)
                    if (ip_header.flags & 0x1) or ip_header.fragment_offset > 0:
                        if id(packet) not in fragmented_ids:
                            fragmented_ids.add(id(packet))
                            fragmented_packets.append(packet)
                except Exception:
                    LOG.debug(
                        "Ошибка парсинга IP заголовка при анализе фрагментации", exc_info=True
                    )

            # TCP сегментация (малые пакеты) - только если еще не учтен
            if packet.payload and len(packet.payload) < 100:
                fragmented_ids.add(id(packet))

        analysis["fragmented_packets_count"] = len(fragmented_ids)

        # Если есть фрагменты, но соединение заблокировано - DPI собирает фрагменты
        if analysis["fragmented_packets_count"] > 0:
            # Проверяем признаки сборки фрагментов DPI

            # Индикатор 1: Блокировка происходит после получения всех фрагментов
            if self.block_after_reassembly(tcp_packets, fragmented_packets):
                analysis["reassembly_indicators"].append("block_after_reassembly")
                analysis["confidence"] += 0.4

            # Индикатор 2: Нормальная TCP сборка, но блокировка на уровне приложения
            if self.normal_tcp_reassembly_but_blocked(tcp_packets):
                analysis["reassembly_indicators"].append("tcp_reassembly_blocked")
                analysis["confidence"] += 0.3

            # Индикатор 3: Фрагменты приходят в правильном порядке, но блокируются
            if self.ordered_fragments_blocked(fragmented_packets):
                analysis["reassembly_indicators"].append("ordered_fragments_blocked")
                analysis["confidence"] += 0.2

        analysis["fragments_reassembled"] = analysis["confidence"] > 0.3

        return analysis

    def block_after_reassembly(
        self, tcp_packets: List[RawPacket], fragmented_packets: List[RawPacket]
    ) -> bool:
        """
        Проверка блокировки после сборки фрагментов.

        Args:
            tcp_packets: Все TCP пакеты (RawPacket)
            fragmented_packets: Фрагментированные пакеты (RawPacket)

        Returns:
            True если обнаружена блокировка после сборки фрагментов
        """
        if not fragmented_packets:
            return False

        # Без временных меток, проверяем наличие RST после фрагментов в последовательности
        # Используем set для O(1) проверки вместо O(n)
        fragmented_set = {id(p) for p in fragmented_packets}
        frag_indices = []
        for i, p in enumerate(tcp_packets):
            if id(p) in fragmented_set:
                frag_indices.append(i)

        if not frag_indices:
            return False

        last_frag_index = max(frag_indices)

        # Проверяем, есть ли RST после последнего фрагмента - используем утилиту
        for i in range(last_frag_index + 1, len(tcp_packets)):
            p = tcp_packets[i]
            if has_tcp_flag(p, TCPHeader.FLAG_RST):
                return True

        return False

    def normal_tcp_reassembly_but_blocked(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка нормальной TCP сборки, но блокировки на уровне приложения.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            True если TCP сборка нормальная, но есть блокировка
        """
        # Проверяем наличие нормального TCP потока (ACK пакеты)
        ack_count = 0
        rst_count = 0

        for p in tcp_packets:
            if has_tcp_flag(p, TCPHeader.FLAG_ACK):
                ack_count += 1
            if has_tcp_flag(p, TCPHeader.FLAG_RST):
                rst_count += 1

        # Если есть ACK пакеты (нормальная сборка) и RST (блокировка)
        return ack_count > 2 and rst_count > 0

    def ordered_fragments_blocked(self, fragmented_packets: List[RawPacket]) -> bool:
        """
        Проверка блокировки упорядоченных фрагментов.

        Args:
            fragmented_packets: Список фрагментированных пакетов

        Returns:
            True если фрагменты упорядочены, но заблокированы
        """
        if len(fragmented_packets) < 2:
            return False

        # Проверяем, что фрагменты имеют последовательные offset'ы
        offsets = []
        for p in fragmented_packets:
            if len(p.data) >= 20:
                ip_header = IPHeader.unpack(p.data[:20])
                offsets.append(ip_header.fragment_offset)

        if not offsets:
            return False

        # Проверяем упорядоченность
        sorted_offsets = sorted(offsets)
        return offsets == sorted_offsets
