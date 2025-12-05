"""
Intelligent PCAP Analyzer - автоматический анализ PCAP файлов для выявления DPI блокировок.

Этот модуль реализует интеллектуальный анализ PCAP файлов для:
- Автоматического обнаружения DPI блокировок
- Детекции RST-атак, timeout'ов и других паттернов блокировки
- Анализа TLS handshake для выявления проблем с SNI
- Детекции фрагментации пакетов и их влияния на блокировку
- Извлечения DPI сигнатур из трафика

Requirements: FR-13.1, FR-13.2, FR-13.3
"""

import os
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Попытка импорта Scapy с fallback
try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw, TLS, UDP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Интеграция с существующими модулями
try:
    from ...pcap_to_json_analyzer import analyze_pcap, SCAPY_AVAILABLE as PCAP_JSON_AVAILABLE
    from ...strategy_failure_analyzer import FailureCause, StrategyFailureAnalyzer
except ImportError:
    PCAP_JSON_AVAILABLE = False
    FailureCause = None

LOG = logging.getLogger("IntelligentPCAPAnalyzer")


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


class DPIBehavior(Enum):
    """Поведение DPI системы."""
    PASSIVE_MONITORING = "passive_monitoring"
    ACTIVE_RST_INJECTION = "active_rst_injection"
    ACTIVE_PACKET_DROP = "active_packet_drop"
    STATEFUL_INSPECTION = "stateful_inspection"
    STATELESS_FILTERING = "stateless_filtering"
    DEEP_PACKET_INSPECTION = "deep_packet_inspection"
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
class PCAPAnalysisResult:
    """Результат анализа PCAP файла."""
    pcap_file: str
    analysis_timestamp: datetime
    total_packets: int
    total_flows: int
    analysis_duration: float
    
    # Основные результаты
    blocking_detected: bool
    primary_blocking_type: BlockingType
    dpi_behavior: DPIBehavior
    confidence: float
    
    # Детальные результаты
    flows: List[FlowAnalysis] = field(default_factory=list)
    dpi_signatures: List[DPISignature] = field(default_factory=list)
    blocking_evidence: Dict[str, Any] = field(default_factory=dict)
    technical_details: Dict[str, Any] = field(default_factory=dict)
    
    # Рекомендации
    bypass_recommendations: List[str] = field(default_factory=list)
    strategy_hints: List[str] = field(default_factory=list)


class IntelligentPCAPAnalyzer:
    """
    Интеллектуальный анализатор PCAP файлов для выявления DPI блокировок.
    
    Основные возможности:
    - Автоматическое обнаружение различных типов блокировок
    - Детекция RST-инъекций с анализом источников и таймингов
    - Анализ TLS handshake и SNI фильтрации
    - Обнаружение фрагментации и её влияния на блокировку
    - Извлечение DPI сигнатур для создания профилей
    - Генерация рекомендаций по обходу
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Инициализация анализатора.
        
        Args:
            config: Конфигурация анализатора
        """
        self.config = config or {}
        
        # Настройки анализа
        self.enable_deep_analysis = self.config.get("enable_deep_analysis", True)
        self.enable_signature_extraction = self.config.get("enable_signature_extraction", True)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)
        self.max_packets_to_analyze = self.config.get("max_packets_to_analyze", 10000)
        
        # Проверка доступности зависимостей
        self.scapy_available = SCAPY_AVAILABLE
        self.pcap_json_available = PCAP_JSON_AVAILABLE
        
        if not self.scapy_available:
            LOG.warning("Scapy недоступен - будет использован ограниченный анализ")
        
        # Инициализация компонентов
        self.rst_detector = RSTInjectionDetector()
        self.tls_analyzer = TLSHandshakeAnalyzer()
        self.sni_detector = SNIFilteringDetector()
        self.fragmentation_analyzer = FragmentationAnalyzer()
        self.signature_extractor = DPISignatureExtractor()
        self.timeout_detector = TimeoutDetector()
        
        LOG.info("IntelligentPCAPAnalyzer инициализирован")
    
    async def analyze_pcap(self, pcap_file: str) -> PCAPAnalysisResult:
        """
        Основной метод анализа PCAP файла.
        
        Args:
            pcap_file: Путь к PCAP файлу
            
        Returns:
            PCAPAnalysisResult с результатами анализа
        """
        start_time = datetime.now()
        LOG.info(f"Начало анализа PCAP файла: {pcap_file}")
        
        try:
            # Проверка существования файла
            if not os.path.exists(pcap_file):
                raise FileNotFoundError(f"PCAP файл не найден: {pcap_file}")
            
            # Выбор метода анализа
            if self.scapy_available:
                result = await self._analyze_with_scapy(pcap_file)
            elif self.pcap_json_available:
                result = await self._analyze_with_json_converter(pcap_file)
            else:
                result = await self._analyze_fallback(pcap_file)
            
            # Вычисление времени анализа
            analysis_duration = (datetime.now() - start_time).total_seconds()
            result.analysis_duration = analysis_duration
            
            LOG.info(f"Анализ завершен за {analysis_duration:.2f}с. "
                    f"Блокировка: {result.blocking_detected}, "
                    f"Тип: {result.primary_blocking_type.value}")
            
            return result
            
        except Exception as e:
            LOG.error(f"Ошибка анализа PCAP: {e}")
            return self._create_error_result(pcap_file, str(e))
    
    async def _analyze_with_scapy(self, pcap_file: str) -> PCAPAnalysisResult:
        """Анализ с использованием Scapy."""
        try:
            # Загрузка пакетов
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            
            # Ограничение количества пакетов для анализа
            if total_packets > self.max_packets_to_analyze:
                LOG.warning(f"Слишком много пакетов ({total_packets}), "
                           f"анализируем первые {self.max_packets_to_analyze}")
                packets = packets[:self.max_packets_to_analyze]
            
            LOG.info(f"Загружено {len(packets)} пакетов для анализа")
            
            # Группировка пакетов по потокам
            flows = self._group_packets_by_flow(packets)
            LOG.info(f"Обнаружено {len(flows)} TCP потоков")
            
            # Анализ каждого потока
            flow_analyses = []
            for flow_id, flow_packets in flows.items():
                flow_analysis = await self._analyze_flow(flow_id, flow_packets)
                flow_analyses.append(flow_analysis)
            
            # Определение основного типа блокировки
            primary_blocking_type, confidence = self._determine_primary_blocking_type(flow_analyses)
            
            # Определение поведения DPI
            dpi_behavior = self._determine_dpi_behavior(flow_analyses)
            
            # Извлечение DPI сигнатур
            dpi_signatures = []
            if self.enable_signature_extraction:
                dpi_signatures = await self._extract_dpi_signatures(packets, flow_analyses)
            
            # Сбор доказательств блокировки
            blocking_evidence = self._collect_blocking_evidence(flow_analyses)
            
            # Генерация рекомендаций
            bypass_recommendations = self._generate_bypass_recommendations(
                primary_blocking_type, dpi_behavior, flow_analyses
            )
            
            # Создание результата
            result = PCAPAnalysisResult(
                pcap_file=pcap_file,
                analysis_timestamp=datetime.now(),
                total_packets=total_packets,
                total_flows=len(flows),
                analysis_duration=0,  # Будет установлено в основном методе
                blocking_detected=primary_blocking_type != BlockingType.NO_BLOCKING,
                primary_blocking_type=primary_blocking_type,
                dpi_behavior=dpi_behavior,
                confidence=confidence,
                flows=flow_analyses,
                dpi_signatures=dpi_signatures,
                blocking_evidence=blocking_evidence,
                bypass_recommendations=bypass_recommendations,
                technical_details={
                    "analysis_method": "scapy",
                    "packets_analyzed": len(packets),
                    "flows_analyzed": len(flows)
                }
            )
            
            return result
            
        except Exception as e:
            LOG.error(f"Ошибка Scapy анализа: {e}")
            return self._create_error_result(pcap_file, str(e))
    
    async def _analyze_with_json_converter(self, pcap_file: str) -> PCAPAnalysisResult:
        """Анализ с использованием JSON конвертера."""
        try:
            # Конвертация PCAP в JSON
            json_data = analyze_pcap(pcap_file)
            
            # Анализ JSON данных
            flows = json_data.get("flows", {})
            total_flows = len(flows)
            
            # Простой анализ на основе JSON данных
            flow_analyses = []
            for flow_name, packets in flows.items():
                flow_analysis = await self._analyze_flow_from_json(flow_name, packets)
                flow_analyses.append(flow_analysis)
            
            # Определение типа блокировки
            primary_blocking_type, confidence = self._determine_primary_blocking_type(flow_analyses)
            
            # Создание результата
            result = PCAPAnalysisResult(
                pcap_file=pcap_file,
                analysis_timestamp=datetime.now(),
                total_packets=sum(len(packets) for packets in flows.values()),
                total_flows=total_flows,
                analysis_duration=0,
                blocking_detected=primary_blocking_type != BlockingType.NO_BLOCKING,
                primary_blocking_type=primary_blocking_type,
                dpi_behavior=DPIBehavior.UNKNOWN,
                confidence=confidence * 0.8,  # Снижаем уверенность для JSON анализа
                flows=flow_analyses,
                technical_details={
                    "analysis_method": "json_converter",
                    "flows_analyzed": total_flows
                }
            )
            
            return result
            
        except Exception as e:
            LOG.error(f"Ошибка JSON анализа: {e}")
            return self._create_error_result(pcap_file, str(e))
    
    async def _analyze_fallback(self, pcap_file: str) -> PCAPAnalysisResult:
        """Fallback анализ без внешних зависимостей."""
        try:
            # Простой анализ на основе размера файла и метаданных
            file_size = os.path.getsize(pcap_file)
            file_stat = os.stat(pcap_file)
            
            # Эвристический анализ
            if file_size == 0:
                blocking_type = BlockingType.CONNECTION_TIMEOUT
                confidence = 0.8
            elif file_size < 1000:
                blocking_type = BlockingType.PACKET_DROP
                confidence = 0.6
            else:
                blocking_type = BlockingType.UNKNOWN
                confidence = 0.3
            
            result = PCAPAnalysisResult(
                pcap_file=pcap_file,
                analysis_timestamp=datetime.now(),
                total_packets=0,
                total_flows=0,
                analysis_duration=0,
                blocking_detected=blocking_type != BlockingType.NO_BLOCKING,
                primary_blocking_type=blocking_type,
                dpi_behavior=DPIBehavior.UNKNOWN,
                confidence=confidence,
                technical_details={
                    "analysis_method": "fallback",
                    "file_size": file_size,
                    "file_mtime": file_stat.st_mtime
                }
            )
            
            return result
            
        except Exception as e:
            LOG.error(f"Ошибка fallback анализа: {e}")
            return self._create_error_result(pcap_file, str(e))
    
    def _group_packets_by_flow(self, packets) -> Dict[str, List]:
        """Группировка пакетов по TCP потокам."""
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
    
    async def _analyze_flow(self, flow_id: str, packets: List) -> FlowAnalysis:
        """Анализ отдельного TCP потока."""
        if not packets:
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
                blocking_type=BlockingType.NO_BLOCKING
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
            packet_analysis = self._analyze_packet(i + 1, packet)
            packet_analyses.append(packet_analysis)
        
        # Анализ соединения
        connection_established = self._is_connection_established(packets)
        tls_handshake_completed = await self.tls_analyzer.is_handshake_completed(packets)
        
        # Детекция блокировки
        blocking_type = await self._detect_flow_blocking(packets)
        blocking_detected = blocking_type != BlockingType.NO_BLOCKING
        
        # Сбор деталей блокировки
        blocking_details = await self._collect_flow_blocking_details(packets, blocking_type)
        
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
            packets=packet_analyses
        )
    
    async def _analyze_flow_from_json(self, flow_name: str, packets: List[Dict]) -> FlowAnalysis:
        """Анализ потока из JSON данных."""
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
                blocking_type=BlockingType.NO_BLOCKING
            )
        
        # Извлечение информации из JSON
        first_packet = packets[0]
        last_packet = packets[-1]
        
        src_endpoint = f"{first_packet.get('src_ip', 'unknown')}:{first_packet.get('src_port', 0)}"
        dst_endpoint = f"{first_packet.get('dst_ip', 'unknown')}:{first_packet.get('dst_port', 0)}"
        
        packet_count = len(packets)
        total_bytes = sum(p.get('len', 0) for p in packets)
        duration = last_packet.get('timestamp', 0) - first_packet.get('timestamp', 0)
        
        # Простой анализ блокировки на основе флагов
        rst_count = sum(1 for p in packets if 'RST' in p.get('flags', ''))
        has_data = any(p.get('payload_len', 0) > 0 for p in packets)
        
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
            blocking_details={"rst_count": rst_count, "has_data": has_data}
        )
    
    def _analyze_packet(self, packet_number: int, packet) -> PacketAnalysis:
        """Анализ отдельного пакета."""
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
        is_suspicious, suspicious_reasons = self._is_packet_suspicious(packet)
        
        # TLS информация
        tls_info = None
        if Raw in packet:
            tls_info = self._extract_tls_info(packet[Raw].load)
        
        # TCP информация
        tcp_info = {
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "window": packet[TCP].window,
            "checksum": packet[TCP].chksum
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
            tcp_info=tcp_info
        )
    
    def _is_packet_suspicious(self, packet) -> Tuple[bool, List[str]]:
        """Определение подозрительности пакета."""
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
    
    def _extract_tls_info(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Извлечение TLS информации из payload."""
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
                "is_application_data": content_type == 0x17
            }
            
            # Дополнительный анализ для handshake
            if content_type == 0x16 and len(payload) > 9:
                handshake_type = payload[5]
                tls_info["handshake_type"] = handshake_type
                tls_info["is_client_hello"] = handshake_type == 0x01
                tls_info["is_server_hello"] = handshake_type == 0x02
            
            return tls_info
            
        except Exception:
            return None
    
    def _is_connection_established(self, packets: List) -> bool:
        """Проверка установления TCP соединения."""
        syn_sent = False
        syn_ack_received = False
        ack_sent = False
        
        for packet in packets:
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
    
    async def _detect_flow_blocking(self, packets: List) -> BlockingType:
        """Детекция типа блокировки в потоке."""
        # Детекция RST инъекций
        if await self.rst_detector.detect_rst_injection(packets):
            return BlockingType.RST_INJECTION
        
        # Детекция timeout'ов
        if await self.timeout_detector.detect_timeout(packets):
            return BlockingType.CONNECTION_TIMEOUT
        
        # Детекция TLS проблем
        tls_blocking = await self.tls_analyzer.detect_tls_blocking(packets)
        if tls_blocking != BlockingType.NO_BLOCKING:
            return tls_blocking
        
        # Детекция SNI фильтрации
        if await self.sni_detector.detect_sni_filtering(packets):
            return BlockingType.SNI_FILTERING
        
        # Детекция проблем с фрагментацией
        if await self.fragmentation_analyzer.detect_fragmentation_issues(packets):
            return BlockingType.FRAGMENTATION_REASSEMBLY
        
        # Проверка на packet drop
        if self._detect_packet_drop(packets):
            return BlockingType.PACKET_DROP
        
        return BlockingType.NO_BLOCKING
    
    def _detect_packet_drop(self, packets: List) -> bool:
        """Детекция потери пакетов."""
        if len(packets) < 3:
            return True  # Слишком мало пакетов
        
        # Проверка на отсутствие ответов
        outgoing_packets = []
        incoming_packets = []
        
        for packet in packets:
            if packet[TCP].dport == 443:  # Исходящий трафик
                outgoing_packets.append(packet)
            else:  # Входящий трафик
                incoming_packets.append(packet)
        
        # Если есть исходящие пакеты, но нет входящих - возможно packet drop
        return len(outgoing_packets) > 0 and len(incoming_packets) == 0
    
    async def _collect_flow_blocking_details(self, packets: List, blocking_type: BlockingType) -> Dict[str, Any]:
        """Сбор деталей блокировки для потока."""
        details = {"blocking_type": blocking_type.value}
        
        if blocking_type == BlockingType.RST_INJECTION:
            details.update(await self.rst_detector.get_rst_details(packets))
        elif blocking_type == BlockingType.TLS_HANDSHAKE_BLOCKING:
            details.update(await self.tls_analyzer.get_tls_details(packets))
        elif blocking_type == BlockingType.SNI_FILTERING:
            details.update(await self.sni_detector.get_sni_details(packets))
        elif blocking_type == BlockingType.FRAGMENTATION_REASSEMBLY:
            details.update(await self.fragmentation_analyzer.get_fragmentation_details(packets))
        elif blocking_type == BlockingType.CONNECTION_TIMEOUT:
            details.update(await self.timeout_detector.get_timeout_details(packets))
        
        return details
    
    def _determine_primary_blocking_type(self, flow_analyses: List[FlowAnalysis]) -> Tuple[BlockingType, float]:
        """Определение основного типа блокировки."""
        if not flow_analyses:
            return BlockingType.UNKNOWN, 0.0
        
        # Подсчет типов блокировок
        blocking_counts = {}
        total_flows = len(flow_analyses)
        blocked_flows = 0
        
        for flow in flow_analyses:
            if flow.blocking_detected:
                blocked_flows += 1
                blocking_type = flow.blocking_type
                blocking_counts[blocking_type] = blocking_counts.get(blocking_type, 0) + 1
        
        if blocked_flows == 0:
            return BlockingType.NO_BLOCKING, 1.0
        
        # Находим наиболее частый тип блокировки
        primary_type = max(blocking_counts.items(), key=lambda x: x[1])[0]
        
        # Вычисляем уверенность
        confidence = blocking_counts[primary_type] / total_flows
        
        return primary_type, confidence
    
    def _determine_dpi_behavior(self, flow_analyses: List[FlowAnalysis]) -> DPIBehavior:
        """Определение поведения DPI системы."""
        if not flow_analyses:
            return DPIBehavior.UNKNOWN
        
        # Анализ паттернов блокировки
        has_rst_injection = any(f.blocking_type == BlockingType.RST_INJECTION for f in flow_analyses)
        has_packet_drop = any(f.blocking_type == BlockingType.PACKET_DROP for f in flow_analyses)
        has_content_filtering = any(f.blocking_type == BlockingType.CONTENT_FILTERING for f in flow_analyses)
        has_stateful_issues = any(f.blocking_type == BlockingType.STATEFUL_TRACKING for f in flow_analyses)
        
        if has_rst_injection:
            return DPIBehavior.ACTIVE_RST_INJECTION
        elif has_packet_drop:
            return DPIBehavior.ACTIVE_PACKET_DROP
        elif has_content_filtering:
            return DPIBehavior.DEEP_PACKET_INSPECTION
        elif has_stateful_issues:
            return DPIBehavior.STATEFUL_INSPECTION
        else:
            return DPIBehavior.PASSIVE_MONITORING
    
    async def _extract_dpi_signatures(self, packets: List, flow_analyses: List[FlowAnalysis]) -> List[DPISignature]:
        """Извлечение DPI сигнатур из трафика."""
        if not self.enable_signature_extraction:
            return []
        
        signatures = []
        
        # Извлечение сигнатур RST инъекций
        rst_signatures = await self.signature_extractor.extract_rst_signatures(packets)
        signatures.extend(rst_signatures)
        
        # Извлечение сигнатур тайминга
        timing_signatures = await self.signature_extractor.extract_timing_signatures(flow_analyses)
        signatures.extend(timing_signatures)
        
        # Извлечение сигнатур контента
        content_signatures = await self.signature_extractor.extract_content_signatures(packets)
        signatures.extend(content_signatures)
        
        return signatures
    
    def _collect_blocking_evidence(self, flow_analyses: List[FlowAnalysis]) -> Dict[str, Any]:
        """Сбор доказательств блокировки."""
        evidence = {
            "total_flows": len(flow_analyses),
            "blocked_flows": sum(1 for f in flow_analyses if f.blocking_detected),
            "blocking_types": {},
            "suspicious_patterns": [],
            "timing_anomalies": [],
            "technical_indicators": {}
        }
        
        # Подсчет типов блокировок
        for flow in flow_analyses:
            if flow.blocking_detected:
                blocking_type = flow.blocking_type.value
                evidence["blocking_types"][blocking_type] = evidence["blocking_types"].get(blocking_type, 0) + 1
        
        # Сбор подозрительных паттернов
        for flow in flow_analyses:
            for packet in flow.packets:
                if packet.is_suspicious:
                    evidence["suspicious_patterns"].extend(packet.suspicious_reasons)
        
        # Удаление дубликатов
        evidence["suspicious_patterns"] = list(set(evidence["suspicious_patterns"]))
        
        return evidence
    
    def _generate_bypass_recommendations(self, 
                                       primary_blocking_type: BlockingType,
                                       dpi_behavior: DPIBehavior,
                                       flow_analyses: List[FlowAnalysis]) -> List[str]:
        """Генерация рекомендаций по обходу блокировки."""
        recommendations = []
        
        # Рекомендации на основе типа блокировки
        if primary_blocking_type == BlockingType.RST_INJECTION:
            recommendations.extend([
                "Используйте пакеты с низким TTL для обхода RST инъекций",
                "Попробуйте атаки с нарушением порядка пакетов (disorder)",
                "Рассмотрите использование fake пакетов с badseq/badsum"
            ])
        
        elif primary_blocking_type == BlockingType.SNI_FILTERING:
            recommendations.extend([
                "Фрагментируйте TLS ClientHello на уровне SNI",
                "Используйте fake SNI пакеты перед настоящим",
                "Попробуйте multisplit для разбиения SNI"
            ])
        
        elif primary_blocking_type == BlockingType.TLS_HANDSHAKE_BLOCKING:
            recommendations.extend([
                "Фрагментируйте TLS записи на мелкие части",
                "Используйте обфускацию TLS handshake",
                "Попробуйте изменение порядка TLS расширений"
            ])
        
        elif primary_blocking_type == BlockingType.FRAGMENTATION_REASSEMBLY:
            recommendations.extend([
                "DPI собирает фрагменты - переключитесь на timing атаки",
                "Используйте packet reordering вместо фрагментации",
                "Попробуйте sequence overlap атаки"
            ])
        
        elif primary_blocking_type == BlockingType.CONNECTION_TIMEOUT:
            recommendations.extend([
                "Проверьте доступность целевого сервера",
                "Попробуйте альтернативные порты или протоколы",
                "Рассмотрите использование proxy или VPN"
            ])
        
        # Рекомендации на основе поведения DPI
        if dpi_behavior == DPIBehavior.ACTIVE_RST_INJECTION:
            recommendations.append("DPI активно инжектирует RST - используйте TTL манипуляции")
        
        elif dpi_behavior == DPIBehavior.STATEFUL_INSPECTION:
            recommendations.append("DPI отслеживает состояние - используйте stateless обходы")
        
        elif dpi_behavior == DPIBehavior.DEEP_PACKET_INSPECTION:
            recommendations.append("DPI анализирует содержимое - используйте обфускацию payload")
        
        # Удаление дубликатов
        return list(set(recommendations))
    
    def _create_error_result(self, pcap_file: str, error_msg: str) -> PCAPAnalysisResult:
        """Создание результата с ошибкой."""
        return PCAPAnalysisResult(
            pcap_file=pcap_file,
            analysis_timestamp=datetime.now(),
            total_packets=0,
            total_flows=0,
            analysis_duration=0,
            blocking_detected=False,
            primary_blocking_type=BlockingType.UNKNOWN,
            dpi_behavior=DPIBehavior.UNKNOWN,
            confidence=0.0,
            technical_details={"error": error_msg, "analysis_method": "error"}
        )
    
    async def save_analysis_result(self, result: PCAPAnalysisResult, output_file: str) -> bool:
        """Сохранение результата анализа в файл."""
        try:
            # Конвертация в JSON-совместимый формат
            result_dict = {
                "pcap_file": result.pcap_file,
                "analysis_timestamp": result.analysis_timestamp.isoformat(),
                "total_packets": result.total_packets,
                "total_flows": result.total_flows,
                "analysis_duration": result.analysis_duration,
                "blocking_detected": result.blocking_detected,
                "primary_blocking_type": result.primary_blocking_type.value,
                "dpi_behavior": result.dpi_behavior.value,
                "confidence": result.confidence,
                "flows": [
                    {
                        "flow_id": f.flow_id,
                        "src_endpoint": f.src_endpoint,
                        "dst_endpoint": f.dst_endpoint,
                        "packet_count": f.packet_count,
                        "total_bytes": f.total_bytes,
                        "duration": f.duration,
                        "connection_established": f.connection_established,
                        "tls_handshake_completed": f.tls_handshake_completed,
                        "blocking_detected": f.blocking_detected,
                        "blocking_type": f.blocking_type.value,
                        "blocking_details": f.blocking_details
                    }
                    for f in result.flows
                ],
                "dpi_signatures": [
                    {
                        "signature_id": s.signature_id,
                        "signature_type": s.signature_type,
                        "pattern_data": s.pattern_data,
                        "confidence": s.confidence,
                        "detection_method": s.detection_method,
                        "samples_count": s.samples_count,
                        "first_seen": s.first_seen.isoformat(),
                        "last_seen": s.last_seen.isoformat()
                    }
                    for s in result.dpi_signatures
                ],
                "blocking_evidence": result.blocking_evidence,
                "bypass_recommendations": result.bypass_recommendations,
                "strategy_hints": result.strategy_hints,
                "technical_details": result.technical_details
            }
            
            # Сохранение в файл
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Результат анализа сохранен в {output_file}")
            return True
            
        except Exception as e:
            LOG.error(f"Ошибка сохранения результата: {e}")
            return False


# Специализированные детекторы
class RSTInjectionDetector:
    """Детектор RST инъекций."""
    
    async def detect_rst_injection(self, packets: List) -> bool:
        """Детекция RST инъекций."""
        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]
        
        if not rst_packets:
            return False
        
        # Анализ множественных RST
        if len(rst_packets) > 1:
            return True
        
        # Анализ TTL
        for rst in rst_packets:
            if IP in rst and rst[IP].ttl < 64:
                return True
        
        return False
    
    async def get_rst_details(self, packets: List) -> Dict[str, Any]:
        """Получение деталей RST инъекции."""
        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]
        
        details = {
            "rst_count": len(rst_packets),
            "rst_ttls": [],
            "rst_sources": [],
            "rst_timings": []
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
        """Проверка завершения TLS handshake."""
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
        """Детекция блокировки TLS."""
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
        """Получение деталей TLS анализа."""
        details = {
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_alerts": [],
            "handshake_messages": []
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
        return (len(payload) >= 6 and 
                payload[0] == 0x16 and  # Handshake
                payload[5] == 0x01)     # ClientHello
    
    def _is_server_hello(self, payload: bytes) -> bool:
        """Проверка ServerHello."""
        return (len(payload) >= 6 and 
                payload[0] == 0x16 and  # Handshake
                payload[5] == 0x02)     # ServerHello
    
    def _is_tls_alert(self, payload: bytes) -> bool:
        """Проверка TLS Alert."""
        return len(payload) >= 1 and payload[0] == 0x15
    
    def _parse_tls_alert(self, payload: bytes) -> Dict[str, Any]:
        """Парсинг TLS Alert."""
        if len(payload) >= 7:
            return {
                "level": payload[5],
                "description": payload[6]
            }
        return {"level": "unknown", "description": "unknown"}


class SNIFilteringDetector:
    """Детектор SNI фильтрации."""
    
    async def detect_sni_filtering(self, packets: List) -> bool:
        """Детекция SNI фильтрации."""
        has_sni = False
        has_response = False
        
        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if self._contains_sni(payload):
                    has_sni = True
                elif packet[TCP].sport == 443:  # Ответ от сервера
                    has_response = True
        
        return has_sni and not has_response
    
    async def get_sni_details(self, packets: List) -> Dict[str, Any]:
        """Получение деталей SNI анализа."""
        details = {
            "sni_domains": [],
            "sni_packets": 0,
            "server_responses": 0
        }
        
        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                sni_domain = self._extract_sni(payload)
                if sni_domain:
                    details["sni_domains"].append(sni_domain)
                    details["sni_packets"] += 1
                elif packet[TCP].sport == 443:
                    details["server_responses"] += 1
        
        return details
    
    def _contains_sni(self, payload: bytes) -> bool:
        """Проверка наличия SNI в payload."""
        # Упрощенная проверка SNI extension
        return b'\x00\x00' in payload and len(payload) > 50
    
    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Извлечение SNI из payload."""
        # Упрощенное извлечение SNI
        try:
            if b'\x00\x00' in payload:  # SNI extension type
                # Поиск доменного имени в payload
                for i in range(len(payload) - 10):
                    if payload[i:i+2] == b'\x00\x00':
                        # Попытка извлечь доменное имя
                        domain_start = i + 10
                        domain_end = domain_start + 20
                        if domain_end < len(payload):
                            potential_domain = payload[domain_start:domain_end]
                            # Простая проверка на доменное имя
                            if b'.' in potential_domain:
                                return potential_domain.decode('utf-8', errors='ignore')
        except:
            pass
        return None


class FragmentationAnalyzer:
    """Анализатор фрагментации."""
    
    async def detect_fragmentation_issues(self, packets: List) -> bool:
        """Детекция проблем с фрагментацией."""
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
        """Получение деталей фрагментации."""
        details = {
            "fragmented_packets": 0,
            "small_packets": 0,
            "fragment_sizes": [],
            "reassembly_indicators": []
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
        """Детекция timeout'ов."""
        if len(packets) < 2:
            return True
        
        # Проверка на отсутствие ответов
        last_outgoing = None
        has_response = False
        
        for packet in packets:
            if packet[TCP].dport == 443:  # Исходящий
                last_outgoing = packet.time
            elif packet[TCP].sport == 443:  # Входящий
                has_response = True
        
        return last_outgoing is not None and not has_response
    
    async def get_timeout_details(self, packets: List) -> Dict[str, Any]:
        """Получение деталей timeout."""
        details = {
            "total_packets": len(packets),
            "outgoing_packets": 0,
            "incoming_packets": 0,
            "last_packet_time": 0
        }
        
        for packet in packets:
            if packet[TCP].dport == 443:
                details["outgoing_packets"] += 1
            else:
                details["incoming_packets"] += 1
            details["last_packet_time"] = max(details["last_packet_time"], packet.time)
        
        return details


class DPISignatureExtractor:
    """Экстрактор DPI сигнатур."""
    
    async def extract_rst_signatures(self, packets: List) -> List[DPISignature]:
        """Извлечение сигнатур RST инъекций."""
        signatures = []
        rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]
        
        if rst_packets:
            # Создание сигнатуры RST паттерна
            ttl_values = [p[IP].ttl for p in rst_packets if IP in p]
            
            signature = DPISignature(
                signature_id=f"rst_pattern_{hash(tuple(ttl_values))}",
                signature_type="rst_pattern",
                pattern_data={
                    "rst_count": len(rst_packets),
                    "ttl_values": ttl_values,
                    "timing_pattern": [p.time for p in rst_packets]
                },
                confidence=0.8,
                detection_method="rst_analysis",
                samples_count=len(rst_packets),
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
            signatures.append(signature)
        
        return signatures
    
    async def extract_timing_signatures(self, flow_analyses: List[FlowAnalysis]) -> List[DPISignature]:
        """Извлечение сигнатур тайминга."""
        signatures = []
        
        # Анализ паттернов тайминга блокировок
        blocking_timings = []
        for flow in flow_analyses:
            if flow.blocking_detected and flow.duration > 0:
                blocking_timings.append(flow.duration)
        
        if blocking_timings:
            avg_timing = sum(blocking_timings) / len(blocking_timings)
            
            signature = DPISignature(
                signature_id=f"timing_pattern_{hash(tuple(blocking_timings))}",
                signature_type="timing_pattern",
                pattern_data={
                    "average_blocking_time": avg_timing,
                    "timing_samples": blocking_timings,
                    "sample_count": len(blocking_timings)
                },
                confidence=0.6,
                detection_method="timing_analysis",
                samples_count=len(blocking_timings),
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
            signatures.append(signature)
        
        return signatures
    
    async def extract_content_signatures(self, packets: List) -> List[DPISignature]:
        """Извлечение сигнатур контента."""
        signatures = []
        
        # Поиск паттернов в TLS трафике
        tls_patterns = []
        for packet in packets:
            if Raw in packet:
                payload = bytes(packet[Raw])
                if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                    tls_patterns.append(payload[:20])  # Первые 20 байт
        
        if tls_patterns:
            signature = DPISignature(
                signature_id=f"content_pattern_{hash(tuple(tls_patterns))}",
                signature_type="content_pattern",
                pattern_data={
                    "tls_patterns": [p.hex() for p in tls_patterns],
                    "pattern_count": len(tls_patterns)
                },
                confidence=0.5,
                detection_method="content_analysis",
                samples_count=len(tls_patterns),
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
            signatures.append(signature)
        
        return signatures


# Удобные функции для использования
async def analyze_pcap_file(pcap_file: str, config: Optional[Dict[str, Any]] = None) -> PCAPAnalysisResult:
    """
    Удобная функция для анализа PCAP файла.
    
    Args:
        pcap_file: Путь к PCAP файлу
        config: Конфигурация анализатора
        
    Returns:
        PCAPAnalysisResult с результатами анализа
    """
    analyzer = IntelligentPCAPAnalyzer(config)
    return await analyzer.analyze_pcap(pcap_file)


async def batch_analyze_pcap_files(pcap_files: List[str], 
                                 config: Optional[Dict[str, Any]] = None) -> List[PCAPAnalysisResult]:
    """
    Пакетный анализ нескольких PCAP файлов.
    
    Args:
        pcap_files: Список путей к PCAP файлам
        config: Конфигурация анализатора
        
    Returns:
        Список результатов анализа
    """
    analyzer = IntelligentPCAPAnalyzer(config)
    results = []
    
    for pcap_file in pcap_files:
        try:
            result = await analyzer.analyze_pcap(pcap_file)
            results.append(result)
        except Exception as e:
            LOG.error(f"Ошибка анализа {pcap_file}: {e}")
            error_result = analyzer._create_error_result(pcap_file, str(e))
            results.append(error_result)
    
    return results


if __name__ == "__main__":
    # Пример использования
    async def main():
        # Настройка логирования
        logging.basicConfig(level=logging.INFO)
        
        # Конфигурация анализатора
        config = {
            "enable_deep_analysis": True,
            "enable_signature_extraction": True,
            "confidence_threshold": 0.7,
            "max_packets_to_analyze": 5000
        }
        
        # Анализ PCAP файла
        pcap_file = "test.pcap"
        if os.path.exists(pcap_file):
            result = await analyze_pcap_file(pcap_file, config)
            
            print(f"Анализ завершен: {result.pcap_file}")
            print(f"Блокировка обнаружена: {result.blocking_detected}")
            print(f"Тип блокировки: {result.primary_blocking_type.value}")
            print(f"Поведение DPI: {result.dpi_behavior.value}")
            print(f"Уверенность: {result.confidence:.2f}")
            print(f"Рекомендации: {result.bypass_recommendations}")
            
            # Сохранение результата
            await IntelligentPCAPAnalyzer().save_analysis_result(result, "analysis_result.json")
        else:
            print(f"PCAP файл {pcap_file} не найден")
    
    # Запуск примера
    asyncio.run(main())