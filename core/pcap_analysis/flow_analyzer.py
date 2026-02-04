"""
Flow Analyzer - анализ TCP потоков в PCAP файлах.

Этот модуль реализует:
- Группировку пакетов по TCP потокам
- Анализ отдельных потоков (Scapy)
- Анализ потоков из JSON данных
- Анализ отдельных пакетов
- Детекцию подозрительных пакетов
- Извлечение TLS информации

Requirements: FR-13.1, FR-13.2
Extracted from: intelligent_pcap_analyzer.py (Step 3 refactoring)
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

# Попытка импорта Scapy с fallback
try:
    from scapy.all import TCP, IP, IPv6, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    TCP = IP = IPv6 = Raw = None

LOG = logging.getLogger("FlowAnalyzer")


# Минимальные определения для типизации
from enum import Enum


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


@dataclass
class PacketAnalysis:
    """Результат анализа пакета."""

    packet_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: List[str]
    payload_size: int
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    tls_info: Optional[Dict[str, Any]] = None
    tcp_info: Optional[Dict[str, Any]] = None


@dataclass
class FlowAnalysis:
    """Результат анализа TCP потока."""

    flow_id: str
    src_endpoint: str
    dst_endpoint: str
    packet_count: int
    total_bytes: int
    duration: float
    connection_established: bool
    tls_handshake_completed: bool
    blocking_detected: bool
    blocking_type: BlockingType
    blocking_details: Dict[str, Any] = field(default_factory=dict)
    packets: List[PacketAnalysis] = field(default_factory=list)


class FlowAnalyzer:
    """
    Анализатор TCP потоков.

    Группирует пакеты по потокам и анализирует каждый поток отдельно.
    """

    def __init__(self, tls_analyzer=None, blocking_detector=None):
        """
        Инициализация анализатора потоков.

        Args:
            tls_analyzer: Анализатор TLS (опционально)
            blocking_detector: Детектор блокировок (опционально)
        """
        self.scapy_available = SCAPY_AVAILABLE
        self.tls_analyzer = tls_analyzer
        self.blocking_detector = blocking_detector

        if not self.scapy_available:
            LOG.warning("Scapy недоступен - анализ потоков ограничен")

    def group_packets_by_flow(self, packets) -> Dict[str, List]:
        """
        Группировка пакетов по TCP потокам.

        Args:
            packets: Список пакетов Scapy

        Returns:
            Словарь {flow_id: [packets]}
        """
        if not self.scapy_available:
            return {}

        flows = {}

        for packet in packets:
            if not (TCP in packet and (IP in packet or IPv6 in packet)):
                continue

            # Создание идентификатора потока
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:  # IPv6
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Нормализация потока (двунаправленный)
            endpoint1 = f"{src_ip}:{src_port}"
            endpoint2 = f"{dst_ip}:{dst_port}"
            flow_id = " <-> ".join(sorted([endpoint1, endpoint2]))

            if flow_id not in flows:
                flows[flow_id] = []

            flows[flow_id].append(packet)

        return flows

    async def analyze_flow(self, flow_id: str, packets: List) -> FlowAnalysis:
        """
        Анализ отдельного TCP потока.

        Args:
            flow_id: Идентификатор потока
            packets: Список пакетов потока

        Returns:
            FlowAnalysis с результатами анализа
        """
        if not self.scapy_available or not packets:
            return FlowAnalysis(
                flow_id=flow_id,
                src_endpoint="unknown",
                dst_endpoint="unknown",
                packet_count=0,
                total_bytes=0,
                duration=0,
                connection_established=False,
                tls_handshake_completed=False,
                blocking_detected=False,
                blocking_type=BlockingType.NO_BLOCKING,
            )

        # Базовая информация о потоке
        first_packet = packets[0]
        last_packet = packets[-1]

        if IP in first_packet:
            src_ip = first_packet[IP].src
            dst_ip = first_packet[IP].dst
        else:
            src_ip = first_packet[IPv6].src
            dst_ip = first_packet[IPv6].dst

        src_port = first_packet[TCP].sport
        dst_port = first_packet[TCP].dport

        src_endpoint = f"{src_ip}:{src_port}"
        dst_endpoint = f"{dst_ip}:{dst_port}"

        packet_count = len(packets)
        total_bytes = sum(len(p) for p in packets)
        duration = last_packet.time - first_packet.time

        # Анализ пакетов
        packet_analyses = []
        for i, packet in enumerate(packets):
            packet_analysis = self.analyze_packet(i + 1, packet)
            packet_analyses.append(packet_analysis)

        # Анализ соединения
        connection_established = self.is_connection_established(packets)

        # TLS handshake анализ (если доступен анализатор)
        tls_handshake_completed = False
        if self.tls_analyzer:
            tls_handshake_completed = await self.tls_analyzer.is_handshake_completed(packets)

        # Детекция блокировки (если доступен детектор)
        blocking_type = BlockingType.NO_BLOCKING
        blocking_details = {}
        if self.blocking_detector:
            blocking_type = await self.blocking_detector.detect_flow_blocking(packets)
            blocking_detected = blocking_type != BlockingType.NO_BLOCKING
            if blocking_detected:
                blocking_details = await self.blocking_detector.collect_flow_blocking_details(
                    packets, blocking_type
                )
        else:
            blocking_detected = False

        return FlowAnalysis(
            flow_id=flow_id,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            packet_count=packet_count,
            total_bytes=total_bytes,
            duration=duration,
            connection_established=connection_established,
            tls_handshake_completed=tls_handshake_completed,
            blocking_detected=blocking_detected,
            blocking_type=blocking_type,
            blocking_details=blocking_details,
            packets=packet_analyses,
        )

    async def analyze_flow_from_json(self, flow_name: str, packets: List[Dict]) -> FlowAnalysis:
        """
        Анализ потока из JSON данных.

        Args:
            flow_name: Имя потока
            packets: Список пакетов в JSON формате

        Returns:
            FlowAnalysis с результатами анализа
        """
        if not packets:
            return FlowAnalysis(
                flow_id=flow_name,
                src_endpoint="unknown",
                dst_endpoint="unknown",
                packet_count=0,
                total_bytes=0,
                duration=0,
                connection_established=False,
                tls_handshake_completed=False,
                blocking_detected=False,
                blocking_type=BlockingType.NO_BLOCKING,
            )

        # Извлечение информации из JSON
        first_packet = packets[0]
        last_packet = packets[-1]

        src_endpoint = f"{first_packet.get('src_ip', 'unknown')}:{first_packet.get('src_port', 0)}"
        dst_endpoint = f"{first_packet.get('dst_ip', 'unknown')}:{first_packet.get('dst_port', 0)}"

        packet_count = len(packets)
        total_bytes = sum(p.get("len", 0) for p in packets)
        duration = last_packet.get("timestamp", 0) - first_packet.get("timestamp", 0)

        # Простой анализ блокировки на основе флагов
        rst_count = sum(1 for p in packets if "RST" in p.get("flags", ""))
        has_data = any(p.get("payload_len", 0) > 0 for p in packets)

        if rst_count > 0:
            blocking_type = BlockingType.RST_INJECTION
            blocking_detected = True
        elif not has_data and packet_count < 5:
            blocking_type = BlockingType.CONNECTION_TIMEOUT
            blocking_detected = True
        else:
            blocking_type = BlockingType.NO_BLOCKING
            blocking_detected = False

        return FlowAnalysis(
            flow_id=flow_name,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            packet_count=packet_count,
            total_bytes=total_bytes,
            duration=duration,
            connection_established=packet_count > 2,
            tls_handshake_completed=False,  # Сложно определить из JSON
            blocking_detected=blocking_detected,
            blocking_type=blocking_type,
            blocking_details={"rst_count": rst_count, "has_data": has_data},
        )

    def analyze_packet(self, packet_number: int, packet) -> PacketAnalysis:
        """
        Анализ отдельного пакета.

        Args:
            packet_number: Номер пакета в потоке
            packet: Пакет Scapy

        Returns:
            PacketAnalysis с результатами анализа
        """
        if not self.scapy_available:
            return PacketAnalysis(
                packet_number=packet_number,
                timestamp=0,
                src_ip="unknown",
                dst_ip="unknown",
                src_port=0,
                dst_port=0,
                protocol="TCP",
                flags=[],
                payload_size=0,
            )

        # Извлечение базовой информации
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        timestamp = packet.time

        # Анализ флагов TCP
        tcp_flags = []
        if packet[TCP].flags.S:
            tcp_flags.append("SYN")
        if packet[TCP].flags.A:
            tcp_flags.append("ACK")
        if packet[TCP].flags.F:
            tcp_flags.append("FIN")
        if packet[TCP].flags.R:
            tcp_flags.append("RST")
        if packet[TCP].flags.P:
            tcp_flags.append("PSH")
        if packet[TCP].flags.U:
            tcp_flags.append("URG")

        # Размер payload
        payload_size = len(packet[TCP].payload) if packet[TCP].payload else 0

        # Анализ подозрительности
        is_suspicious, suspicious_reasons = self.is_packet_suspicious(packet)

        # TLS информация
        tls_info = None
        if Raw in packet:
            tls_info = self.extract_tls_info(packet[Raw].load)

        # TCP информация
        tcp_info = {
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "window": packet[TCP].window,
            "checksum": packet[TCP].chksum,
        }

        return PacketAnalysis(
            packet_number=packet_number,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            flags=tcp_flags,
            payload_size=payload_size,
            is_suspicious=is_suspicious,
            suspicious_reasons=suspicious_reasons,
            tls_info=tls_info,
            tcp_info=tcp_info,
        )

    def is_packet_suspicious(self, packet) -> Tuple[bool, List[str]]:
        """
        Определение подозрительности пакета.

        Args:
            packet: Пакет Scapy

        Returns:
            Tuple (is_suspicious, reasons)
        """
        if not self.scapy_available:
            return False, []

        suspicious_reasons = []

        # Проверка TTL
        if IP in packet:
            ttl = packet[IP].ttl
            if ttl < 32:  # Очень низкий TTL
                suspicious_reasons.append("low_ttl")
            elif ttl in [64, 128, 255]:  # Стандартные значения DPI
                suspicious_reasons.append("standard_dpi_ttl")

        # Проверка TCP флагов
        if packet[TCP].flags.R:  # RST пакет
            suspicious_reasons.append("rst_packet")

        # Проверка размера окна
        if packet[TCP].window == 0:
            suspicious_reasons.append("zero_window")

        # Проверка checksum
        if packet[TCP].chksum == 0:
            suspicious_reasons.append("zero_checksum")

        return len(suspicious_reasons) > 0, suspicious_reasons

    def extract_tls_info(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Извлечение TLS информации из payload.

        Args:
            payload: Payload пакета

        Returns:
            Словарь с TLS информацией или None
        """
        if not payload or len(payload) < 5:
            return None

        try:
            # Проверка TLS Record Header
            if payload[0] not in [0x14, 0x15, 0x16, 0x17]:  # TLS Content Types
                return None

            content_type = payload[0]
            version = (payload[1] << 8) | payload[2]
            length = (payload[3] << 8) | payload[4]

            tls_info = {
                "content_type": content_type,
                "version": version,
                "length": length,
                "is_handshake": content_type == 0x16,
                "is_alert": content_type == 0x15,
                "is_application_data": content_type == 0x17,
            }

            # Дополнительный анализ для handshake
            if content_type == 0x16 and len(payload) > 9:
                handshake_type = payload[5]
                tls_info["handshake_type"] = handshake_type
                tls_info["is_client_hello"] = handshake_type == 0x01
                tls_info["is_server_hello"] = handshake_type == 0x02

            return tls_info

        except Exception as e:
            LOG.debug(f"Ошибка извлечения TLS информации: {e}")
            return None

    def is_connection_established(self, packets: List) -> bool:
        """
        Проверка установления TCP соединения (3-way handshake).

        Args:
            packets: Список пакетов потока

        Returns:
            True если соединение установлено
        """
        if not self.scapy_available:
            return False

        syn_sent = False
        syn_ack_received = False
        ack_sent = False

        for packet in packets:
            if TCP not in packet:
                continue

            flags = packet[TCP].flags

            if flags.S and not flags.A:  # SYN
                syn_sent = True
            elif flags.S and flags.A:  # SYN-ACK
                syn_ack_received = True
            elif flags.A and not flags.S:  # ACK
                if syn_sent and syn_ack_received:
                    ack_sent = True
                    break

        return syn_sent and syn_ack_received and ack_sent
