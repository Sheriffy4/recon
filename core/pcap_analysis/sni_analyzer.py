"""
SNI Analyzer - анализ SNI (Server Name Indication) фильтрации.

Этот модуль предоставляет функциональность для анализа SNI в TLS handshake
и определения блокировок на основе SNI.
"""

import logging
from typing import Dict, List, Any, Optional

from core.packet.raw_packet_engine import RawPacket
from core.packet.packet_parser_utils import parse_tcp_packet_headers, has_tcp_flag

LOG = logging.getLogger("SNIAnalyzer")


class SNIAnalyzer:
    """
    Анализатор SNI фильтрации для детекции блокировок.

    Основные функции:
    - Извлечение SNI из ClientHello
    - Детекция SNI-based блокировок
    - Проверка паттернов заблокированных доменов
    """

    def analyze_sni_filtering(self, tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Анализ SNI фильтрации в TCP пакетах.

        Args:
            tcp_packets: Список TCP пакетов

        Returns:
            Dict с результатами анализа SNI
        """
        analysis = {
            "sni_blocked": False,
            "sni_domains": [],
            "client_hello_count": 0,
            "rst_after_client_hello": False,
        }

        client_hello_packets = []

        # Ищем ClientHello пакеты и извлекаем SNI
        for packet in tcp_packets:
            if packet.payload:
                # Проверка на ClientHello
                if self._is_client_hello(packet.payload):
                    analysis["client_hello_count"] += 1
                    client_hello_packets.append(packet)

                    # Извлекаем SNI
                    sni = self.extract_sni_from_client_hello(packet.payload)
                    if sni:
                        analysis["sni_domains"].append(sni)

        # Проверяем RST после ClientHello
        if client_hello_packets:
            analysis["rst_after_client_hello"] = self.rst_after_client_hello(
                client_hello_packets, tcp_packets
            )

        # Проверяем паттерны заблокированных доменов
        if analysis["sni_domains"]:
            analysis["sni_blocked"] = (
                self.is_blocked_domain_pattern(analysis["sni_domains"])
                and analysis["rst_after_client_hello"]
            )

        return analysis

    def _is_client_hello(self, payload: bytes) -> bool:
        """Быстрая проверка ClientHello."""
        try:
            if len(payload) < 6:
                return False
            # TLS Handshake (0x16) + ClientHello (0x01)
            return payload[0] == 0x16 and payload[5] == 0x01
        except Exception:
            return False

    def extract_sni_from_client_hello(self, payload: bytes) -> Optional[str]:
        """
        Извлечение SNI из ClientHello пакета.

        Args:
            payload: Байты ClientHello

        Returns:
            str - SNI hostname или None
        """
        try:
            if len(payload) < 43:
                return None

            # TLS Record Header (5 bytes)
            offset = 5

            # Handshake Type (1 byte) + Length (3 bytes)
            offset += 4

            # Client Version (2 bytes)
            offset += 2

            # Random (32 bytes)
            offset += 32

            # Session ID Length (1 byte)
            if offset >= len(payload):
                return None
            session_id_length = payload[offset]
            offset += 1 + session_id_length

            if offset > len(payload):
                return None

            # Cipher Suites Length (2 bytes)
            if offset + 2 > len(payload):
                return None
            cipher_suites_length = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_length

            if offset > len(payload):
                return None

            # Compression Methods Length (1 byte)
            if offset >= len(payload):
                return None
            compression_methods_length = payload[offset]
            offset += 1 + compression_methods_length

            if offset > len(payload):
                return None

            # Extensions Length (2 bytes)
            if offset + 2 >= len(payload):
                return None
            extensions_length = (payload[offset] << 8) | payload[offset + 1]
            offset += 2

            # Ищем SNI extension
            extensions_end = offset + extensions_length
            while offset + 4 < extensions_end and offset + 4 < len(payload):
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_length = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4

                if ext_type == 0x0000:  # SNI extension
                    end = offset + ext_length
                    if end > len(payload):
                        return None
                    return self.parse_sni_extension(payload[offset:end])

                offset += ext_length

            return None
        except Exception as e:
            LOG.debug(f"Ошибка извлечения SNI: {e}")
            return None

    def parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """
        Парсинг SNI extension.

        Args:
            sni_data: Байты SNI extension

        Returns:
            str - hostname или None
        """
        try:
            if len(sni_data) < 5:
                return None

            # SNI List Length (2 bytes)
            offset = 2
            if offset >= len(sni_data):
                return None

            # SNI Type (1 byte) - должен быть 0x00 для hostname
            if sni_data[offset] != 0x00:
                return None
            offset += 1

            if offset + 2 > len(sni_data):
                return None

            # SNI Length (2 bytes)
            sni_length = (sni_data[offset] << 8) | sni_data[offset + 1]
            offset += 2

            if offset + sni_length > len(sni_data):
                return None

            # SNI Hostname
            hostname = sni_data[offset : offset + sni_length].decode("utf-8", errors="ignore")
            return hostname
        except Exception as e:
            LOG.debug(f"Ошибка парсинга SNI extension: {e}")
            return None

    def rst_after_client_hello(
        self, client_hello_packets: List[RawPacket], tcp_packets: List[RawPacket]
    ) -> bool:
        """
        Проверка RST после ClientHello.

        Args:
            client_hello_packets: Список пакетов с ClientHello
            tcp_packets: Все TCP пакеты

        Returns:
            bool - True если найдены RST после ClientHello
        """
        from core.packet.raw_packet_engine import TCPHeader

        if not client_hello_packets:
            return False

        # Находим индексы ClientHello пакетов
        client_hello_indices = []
        for i, p in enumerate(tcp_packets):
            if p in client_hello_packets:
                client_hello_indices.append(i)

        if not client_hello_indices:
            return False

        last_client_hello_index = max(client_hello_indices)

        # Ищем RST пакеты после последнего ClientHello
        for i in range(last_client_hello_index + 1, len(tcp_packets)):
            p = tcp_packets[i]
            if has_tcp_flag(p, TCPHeader.FLAG_RST):
                return True

        return False

    def is_blocked_domain_pattern(self, domains: List[str]) -> bool:
        """
        Проверка паттернов заблокированных доменов.

        Args:
            domains: Список доменов для проверки

        Returns:
            bool - True если найден паттерн заблокированного домена
        """
        blocked_patterns = [
            "twitter.com",
            "x.com",
            "facebook.com",
            "instagram.com",
            "youtube.com",
            "telegram.org",
            "discord.com",
        ]

        for domain in domains:
            for pattern in blocked_patterns:
                if pattern in domain.lower():
                    return True

        return False
