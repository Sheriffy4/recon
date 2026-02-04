"""
PCAP Analysis Detectors - специализированные детекторы для анализа DPI блокировок.

Этот модуль содержит детекторы для:
- RST инъекций
- TLS handshake проблем
- SNI фильтрации
- Фрагментации пакетов
- Timeout'ов соединений

Requirements: FR-13.1, FR-13.2, FR-13.3
Extracted from: intelligent_pcap_analyzer.py (Step 1 refactoring)
"""

import logging
from typing import Dict, List, Any, Optional
from enum import Enum

# Попытка импорта Scapy с fallback
try:
    from scapy.all import TCP, IP, IPv6, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Заглушки для типов
    TCP = IP = IPv6 = Raw = None

LOG = logging.getLogger("PCAPDetectors")


class BlockingType(Enum):
    """Типы блокировок DPI."""

    RST_INJECTION = "rst_injection"
    CONNECTION_TIMEOUT = "connection_timeout"
    TLS_HANDSHAKE_BLOCKING = "tls_handshake_blocking"
    SNI_FILTERING = "sni_filtering"
    DNS_POISONING = "dns_poisoning"
    PACKET_DROP = "packet_drop"
    CONTENT_FILTERING = "content_filtering"
    FRAGMENTATION_REASSEMBLY = "fragmentation_reassembly"
    STATEFUL_TRACKING = "stateful_tracking"
    NO_BLOCKING = "no_blocking"
    UNKNOWN = "unknown"


class RSTInjectionDetector:
    """Детектор RST инъекций."""

    async def detect_rst_injection(self, packets: List) -> bool:
        """
        Детекция RST инъекций.

        Args:
            packets: Список пакетов для анализа

        Returns:
            True если обнаружена RST инъекция
        """
        if not SCAPY_AVAILABLE:
            LOG.warning("Scapy недоступен - RST детекция ограничена")
            return False

        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]

        if not rst_packets:
            return False

        # Анализ множественных RST
        if len(rst_packets) > 1:
            return True

        # Анализ TTL (низкий TTL указывает на инъекцию)
        for rst in rst_packets:
            if IP in rst and rst[IP].ttl < 64:
                return True

        return False

    async def get_rst_details(self, packets: List) -> Dict[str, Any]:
        """
        Получение деталей RST инъекции.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Словарь с деталями RST инъекции
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy недоступен"}

        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]

        details = {
            "rst_count": len(rst_packets),
            "rst_ttls": [],
            "rst_sources": [],
            "rst_timings": [],
        }

        for rst in rst_packets:
            if IP in rst:
                details["rst_ttls"].append(rst[IP].ttl)
                details["rst_sources"].append(rst[IP].src)
            details["rst_timings"].append(rst.time)

        return details


class TLSHandshakeAnalyzer:
    """Анализатор TLS handshake."""

    async def is_handshake_completed(self, packets: List) -> bool:
        """
        Проверка завершения TLS handshake.

        Args:
            packets: Список пакетов для анализа

        Returns:
            True если handshake завершен
        """
        if not SCAPY_AVAILABLE:
            return False

        has_client_hello = False
        has_server_hello = False

        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if self._is_client_hello(payload):
                    has_client_hello = True
                elif self._is_server_hello(payload):
                    has_server_hello = True

        return has_client_hello and has_server_hello

    async def detect_tls_blocking(self, packets: List) -> BlockingType:
        """
        Детекция блокировки TLS.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Тип блокировки TLS
        """
        if not SCAPY_AVAILABLE:
            return BlockingType.UNKNOWN

        has_client_hello = False
        has_server_hello = False
        has_tls_alert = False

        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if self._is_client_hello(payload):
                    has_client_hello = True
                elif self._is_server_hello(payload):
                    has_server_hello = True
                elif self._is_tls_alert(payload):
                    has_tls_alert = True

        if has_client_hello and not has_server_hello:
            return BlockingType.TLS_HANDSHAKE_BLOCKING
        elif has_tls_alert:
            return BlockingType.TLS_HANDSHAKE_BLOCKING

        return BlockingType.NO_BLOCKING

    async def get_tls_details(self, packets: List) -> Dict[str, Any]:
        """
        Получение деталей TLS анализа.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Словарь с деталями TLS
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy недоступен"}

        details = {
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_alerts": [],
            "handshake_messages": [],
        }

        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if self._is_client_hello(payload):
                    details["client_hello_count"] += 1
                    details["handshake_messages"].append("ClientHello")
                elif self._is_server_hello(payload):
                    details["server_hello_count"] += 1
                    details["handshake_messages"].append("ServerHello")
                elif self._is_tls_alert(payload):
                    alert_info = self._parse_tls_alert(payload)
                    details["tls_alerts"].append(alert_info)

        return details

    def _is_client_hello(self, payload: bytes) -> bool:
        """Проверка ClientHello."""
        return (
            len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01  # Handshake
        )  # ClientHello

    def _is_server_hello(self, payload: bytes) -> bool:
        """Проверка ServerHello."""
        return (
            len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x02  # Handshake
        )  # ServerHello

    def _is_tls_alert(self, payload: bytes) -> bool:
        """Проверка TLS Alert."""
        return len(payload) >= 1 and payload[0] == 0x15

    def _parse_tls_alert(self, payload: bytes) -> Dict[str, Any]:
        """Парсинг TLS Alert."""
        if len(payload) >= 7:
            return {"level": payload[5], "description": payload[6]}
        return {"level": "unknown", "description": "unknown"}


class SNIFilteringDetector:
    """Детектор SNI фильтрации."""

    async def detect_sni_filtering(self, packets: List) -> bool:
        """
        Детекция SNI фильтрации.

        Args:
            packets: Список пакетов для анализа

        Returns:
            True если обнаружена SNI фильтрация
        """
        if not SCAPY_AVAILABLE:
            return False

        has_sni = False
        has_response = False

        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if self._contains_sni(payload):
                    has_sni = True
                elif TCP in packet and packet[TCP].sport == 443:  # Ответ от сервера
                    has_response = True

        return has_sni and not has_response

    async def get_sni_details(self, packets: List) -> Dict[str, Any]:
        """
        Получение деталей SNI анализа.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Словарь с деталями SNI
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy недоступен"}

        details = {"sni_domains": [], "sni_packets": 0, "server_responses": 0}

        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                sni_domain = self._extract_sni(payload)
                if sni_domain:
                    details["sni_domains"].append(sni_domain)
                    details["sni_packets"] += 1
                elif TCP in packet and packet[TCP].sport == 443:
                    details["server_responses"] += 1

        return details

    def _contains_sni(self, payload: bytes) -> bool:
        """Проверка наличия SNI в payload."""
        # Упрощенная проверка SNI extension
        return b"\x00\x00" in payload and len(payload) > 50

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Извлечение SNI из payload."""
        # Упрощенное извлечение SNI
        try:
            if b"\x00\x00" in payload:  # SNI extension type
                # Поиск доменного имени в payload
                for i in range(len(payload) - 10):
                    if payload[i : i + 2] == b"\x00\x00":
                        # Попытка извлечь доменное имя
                        domain_start = i + 10
                        domain_end = domain_start + 20
                        if domain_end < len(payload):
                            potential_domain = payload[domain_start:domain_end]
                            # Простая проверка на доменное имя
                            if b"." in potential_domain:
                                return potential_domain.decode("utf-8", errors="ignore")
        except Exception as e:
            LOG.debug(f"Ошибка извлечения SNI: {e}")
        return None


class FragmentationAnalyzer:
    """Анализатор фрагментации."""

    async def detect_fragmentation_issues(self, packets: List) -> bool:
        """
        Детекция проблем с фрагментацией.

        Args:
            packets: Список пакетов для анализа

        Returns:
            True если обнаружены проблемы с фрагментацией
        """
        if not SCAPY_AVAILABLE:
            return False

        fragmented_packets = 0
        small_packets = 0

        for packet in packets:
            # IP фрагментация
            if IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0):
                fragmented_packets += 1

            # Малые TCP сегменты
            if TCP in packet and Raw in packet:
                payload_size = len(bytes(packet[Raw]))
                if payload_size < 100:
                    small_packets += 1

        # Если много фрагментов, но соединение не работает
        return fragmented_packets > 2 or small_packets > 5

    async def get_fragmentation_details(self, packets: List) -> Dict[str, Any]:
        """
        Получение деталей фрагментации.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Словарь с деталями фрагментации
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy недоступен"}

        details = {
            "fragmented_packets": 0,
            "small_packets": 0,
            "fragment_sizes": [],
            "reassembly_indicators": [],
        }

        for packet in packets:
            if IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0):
                details["fragmented_packets"] += 1
                details["fragment_sizes"].append(len(packet))

            if TCP in packet and Raw in packet:
                payload_size = len(bytes(packet[Raw]))
                if payload_size < 100:
                    details["small_packets"] += 1

        return details


class TimeoutDetector:
    """Детектор timeout'ов."""

    async def detect_timeout(self, packets: List) -> bool:
        """
        Детекция timeout'ов.

        Args:
            packets: Список пакетов для анализа

        Returns:
            True если обнаружен timeout
        """
        if not SCAPY_AVAILABLE:
            return False

        if len(packets) < 2:
            return True

        # Проверка на отсутствие ответов
        last_outgoing = None
        has_response = False

        for packet in packets:
            if TCP in packet:
                if packet[TCP].dport == 443:  # Исходящий
                    last_outgoing = packet.time
                elif packet[TCP].sport == 443:  # Входящий
                    has_response = True

        return last_outgoing is not None and not has_response

    async def get_timeout_details(self, packets: List) -> Dict[str, Any]:
        """
        Получение деталей timeout.

        Args:
            packets: Список пакетов для анализа

        Returns:
            Словарь с деталями timeout
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy недоступен"}

        details = {
            "total_packets": len(packets),
            "outgoing_packets": 0,
            "incoming_packets": 0,
            "last_packet_time": 0,
        }

        for packet in packets:
            if TCP in packet:
                if packet[TCP].dport == 443:
                    details["outgoing_packets"] += 1
                else:
                    details["incoming_packets"] += 1
                details["last_packet_time"] = max(details["last_packet_time"], packet.time)

        return details
