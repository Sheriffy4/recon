"""
Failure Detector - детекция различных типов блокировок и неудач.

Этот модуль предоставляет функциональность для определения специфических
типов блокировок: stateful tracking, connection refused и др.
"""

import logging
from typing import List

from core.packet.raw_packet_engine import RawPacket, TCPHeader, ProtocolType
from core.packet.packet_parser_utils import parse_tcp_packet_headers, extract_rst_packets

LOG = logging.getLogger("FailureDetector")


class FailureDetector:
    """
    Детектор различных типов неудач и блокировок.

    Основные функции:
    - Детекция stateful tracking
    - Детекция connection refused
    - Фильтрация релевантных пакетов
    """

    def detect_stateful_tracking(self, tcp_packets: List[RawPacket], strategy) -> bool:
        """
        Детекция stateful отслеживания DPI.

        Args:
            tcp_packets: Список TCP пакетов
            strategy: Стратегия обхода

        Returns:
            bool - True если обнаружено stateful отслеживание
        """
        # Простая эвристика: если стратегия основана на нарушении состояния,
        # но все равно блокируется
        stateful_evasion_keywords = ["disorder", "fake", "badseq", "badsum"]

        strategy_name = strategy.name.lower()
        attack_name = strategy.attack_name.lower()

        uses_stateful_evasion = any(
            keyword in strategy_name or keyword in attack_name
            for keyword in stateful_evasion_keywords
        )

        if uses_stateful_evasion:
            # Если используется stateful evasion, но есть блокировка - DPI stateful
            rst_count = 0
            for p in tcp_packets:
                headers = parse_tcp_packet_headers(p)
                if headers is None:
                    continue

                _, tcp_header, _ = headers

                if tcp_header.flags & TCPHeader.FLAG_RST:
                    rst_count += 1

            return rst_count > 0

        return False

    def is_connection_refused(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка отклонения соединения.

        Args:
            tcp_packets: Список TCP пакетов

        Returns:
            bool - True если соединение было отклонено
        """
        syn = []
        syn_ack = []
        rst = []

        for p in tcp_packets:
            headers = parse_tcp_packet_headers(p)
            if headers is None:
                continue

            _, tcp_header, _ = headers

            # SYN без ACK
            if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (
                tcp_header.flags & TCPHeader.FLAG_ACK
            ):
                syn.append(p)
            # SYN-ACK
            elif (tcp_header.flags & TCPHeader.FLAG_SYN) and (
                tcp_header.flags & TCPHeader.FLAG_ACK
            ):
                syn_ack.append(p)
            # RST
            elif tcp_header.flags & TCPHeader.FLAG_RST:
                rst.append(p)

        # Если был ClientHello, не уводим в refused
        saw_client_hello = any(p.payload and self._is_client_hello(p.payload) for p in tcp_packets)
        if saw_client_hello:
            return False

        return len(syn) > 0 and (len(syn_ack) == 0 or len(rst) > 0)

    def _is_client_hello(self, payload: bytes) -> bool:
        """Быстрая проверка ClientHello."""
        try:
            if len(payload) < 6:
                return False
            return payload[0] == 0x16 and payload[5] == 0x01
        except Exception:
            return False

    def filter_relevant_packets(
        self, packets: List[RawPacket], domain: str = None
    ) -> List[RawPacket]:
        """
        Фильтрация релевантных пакетов для анализа.

        Args:
            packets: Все пакеты
            domain: Целевой домен (опционально)

        Returns:
            List[RawPacket] - отфильтрованные пакеты
        """
        relevant = []

        for packet in packets:
            proto = getattr(packet, "protocol", None)
            proto_name = getattr(proto, "name", str(proto))

            # Включаем все TCP пакеты
            if proto == ProtocolType.TCP or proto_name == "TCP":
                relevant.append(packet)
                continue

            # Если указан домен, фильтруем по IP
            if domain:
                # Простая фильтрация - можно расширить DNS резолвингом
                relevant.append(packet)

        return relevant if relevant else packets
