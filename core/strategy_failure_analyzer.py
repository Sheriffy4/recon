"""
Strategy Failure Analyzer - анализ причин неудач стратегий обхода DPI.

Этот модуль реализует анализ временных PCAP файлов для понимания причин неудач
стратегий обхода и генерации рекомендаций для улучшения.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Импорт RawPCAPReader вместо Scapy
from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket, RawPacketEngine, ProtocolType

# Интеграция с существующими модулями
try:
    from pcap_to_json_analyzer import analyze_pcap as analyze_pcap_json
    PCAP_JSON_AVAILABLE = True
except ImportError:
    analyze_pcap_json = None
    PCAP_JSON_AVAILABLE = False

LOG = logging.getLogger("StrategyFailureAnalyzer")


class FailureCause(Enum):
    """Типы причин неудач стратегий."""
    DPI_ACTIVE_RST_INJECTION = "dpi_active_rst_injection"
    DPI_REASSEMBLES_FRAGMENTS = "dpi_reassembles_fragments"
    DPI_STATEFUL_TRACKING = "dpi_stateful_tracking"
    DPI_SNI_FILTERING = "dpi_sni_filtering"
    DPI_CONTENT_INSPECTION = "dpi_content_inspection"
    NETWORK_TIMEOUT = "network_timeout"
    CONNECTION_REFUSED = "connection_refused"
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
    UNKNOWN = "unknown"


@dataclass
class TrialArtifacts:
    """Артефакты тестирования стратегии."""
    pcap_file: Optional[str] = None
    engine_logs: List[str] = field(default_factory=list)
    network_events: List[Dict] = field(default_factory=list)
    test_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Результат тестирования стратегии."""
    success: bool
    response_time: Optional[float] = None
    error: Optional[str] = None
    artifacts: Optional[TrialArtifacts] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Strategy:
    """Стратегия обхода."""
    name: str
    attack_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    id: Optional[str] = None


@dataclass
class Recommendation:
    """Рекомендация по улучшению стратегии."""
    action: str
    rationale: str
    priority: float = 0.5
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FailureReport:
    """Отчет об анализе неудачи стратегии."""
    strategy_id: str
    domain: str
    analyzed_at: datetime
    
    # Причина неудачи
    root_cause: FailureCause
    root_cause_details: str
    
    # Детали анализа
    failure_details: Dict[str, Any] = field(default_factory=dict)
    block_timing: Optional[float] = None
    blocked_after_packet: Optional[int] = None
    
    # Рекомендации
    recommendations: List[Recommendation] = field(default_factory=list)
    suggested_intents: List[str] = field(default_factory=list)
    
    # Confidence
    confidence: float = 0.0


class StrategyFailureAnalyzer:
    """
    Анализатор причин неудач стратегий обхода DPI.
    
    Основные функции:
    - Анализ временных PCAP файлов
    - Детекция основных причин блокировок (RST injection, blackhole, SNI filtering)
    - Интеграция с pcap_to_json_analyzer.py для конвертации PCAP
    - Генерация рекомендаций для улучшения стратегий
    """
    
    def __init__(self, temp_dir: str = "temp_pcap"):
        """
        Инициализация анализатора.
        
        Args:
            temp_dir: Директория для временных PCAP файлов
        """
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(exist_ok=True)
        
        # Инициализация RawPCAPReader и RawPacketEngine
        self.pcap_reader = RawPCAPReader()
        self.packet_engine = RawPacketEngine()
        self.pcap_json_available = PCAP_JSON_AVAILABLE
        
        LOG.info("ℹ️ Используется RawPCAPReader для анализа PCAP")
        
        # НОВОЕ: Маппинг root_cause → intent'ы для замкнутого цикла обучения
        self.cause_to_intents = {
            FailureCause.DPI_SNI_FILTERING: [
                "conceal_sni",
                "record_fragmentation", 
                "fake_sni"
            ],
            FailureCause.DPI_ACTIVE_RST_INJECTION: [
                "short_ttl_decoy",
                "sequence_overlap",
                "timing_manipulation"
            ],
            FailureCause.DPI_CONTENT_INSPECTION: [
                "payload_obfuscation",
                "tls_extension_manipulation",
                "record_fragmentation"
            ],
            FailureCause.DPI_REASSEMBLES_FRAGMENTS: [
                "packet_reordering",
                "sequence_overlap", 
                "timing_manipulation"
            ],
            FailureCause.DPI_STATEFUL_TRACKING: [
                "sequence_overlap",
                "out_of_order_decoy",
                "timing_manipulation"
            ],
            FailureCause.NETWORK_TIMEOUT: [
                "timeout_adjustment",
                "ipv6_fallback"
            ],
            FailureCause.CONNECTION_REFUSED: [
                "port_randomization",
                "ipv6_fallback"
            ],
            FailureCause.TLS_HANDSHAKE_FAILURE: [
                "tls_extension_manipulation",
                "record_fragmentation"
            ],
            FailureCause.UNKNOWN: [
                "basic_fragmentation",
                "simple_reordering",
                "basic_sni_concealment"
            ]
        }
        
        LOG.info(f"StrategyFailureAnalyzer инициализирован. Temp dir: {self.temp_dir}")
    
    async def analyze_pcap(self, pcap_file: str, strategy: Strategy, domain: Optional[str] = None) -> FailureReport:
        """
        Анализ PCAP файла для определения причин неудачи стратегии.
        
        Args:
            pcap_file: Путь к PCAP файлу
            strategy: Стратегия, которая была протестирована
            
        Returns:
            FailureReport с результатами анализа
        """
        LOG.info(f"Анализ PCAP файла: {pcap_file} для стратегии: {strategy.name}")
        
        try:
            # Проверка существования файла
            if not os.path.exists(pcap_file):
                return self._create_error_report(strategy, FailureCause.UNKNOWN, f"PCAP файл не найден: {pcap_file}")

            # Используем RawPCAPReader для анализа
            return await self._analyze_with_raw_engine(pcap_file, strategy, domain=domain)
                
        except Exception as e:
            LOG.error(f"Ошибка анализа PCAP: {e}")
            return self._create_error_report(
                strategy,
                FailureCause.UNKNOWN,
                f"Ошибка анализа: {str(e)}"
            )
        finally:
            # Автоочистка временного файла
            await self._cleanup_pcap_file(pcap_file)
    
    def _convert_generated_strategy_to_strategy(self, generated_strategy: Any) -> 'Strategy':
        """
        ИСПРАВЛЕНИЕ: Конвертация GeneratedStrategy в Strategy
        
        Проблема: GeneratedStrategy не имеет attack_name и id атрибутов
        Решение: Создаем Strategy объект с правильными атрибутами
        """
        try:
            # Извлекаем attack_name из attack_combination
            if hasattr(generated_strategy, 'attack_combination') and generated_strategy.attack_combination:
                attack_name = generated_strategy.attack_combination[0]  # Берем первую атаку
            elif hasattr(generated_strategy, 'attack_name'):
                attack_name = generated_strategy.attack_name
            else:
                attack_name = "unknown"
            
            # Создаем Strategy объект
            strategy = Strategy(
                name=getattr(generated_strategy, 'name', 'unknown'),
                attack_name=attack_name,
                parameters=getattr(generated_strategy, 'parameters', {}),
                id=getattr(generated_strategy, 'name', None)  # Используем name как id
            )
            
            LOG.debug(f"[CONVERT] GeneratedStrategy -> Strategy: {strategy.name} ({strategy.attack_name})")
            return strategy
                
        except Exception as e:
            LOG.error(f"[CONVERT] Ошибка конвертации GeneratedStrategy: {e}")
            # Создаем fallback Strategy
            return Strategy(
                name="unknown",
                attack_name="unknown", 
                parameters={},
                id="unknown"
            )

    async def _analyze_with_raw_engine(self, pcap_file: str, strategy: Any, domain: Optional[str] = None) -> FailureReport:
        import asyncio
        try:
            # ИСПРАВЛЕНИЕ: Конвертируем GeneratedStrategy в Strategy если нужно
            if hasattr(strategy, 'attack_combination') and not hasattr(strategy, 'attack_name'):
                LOG.debug(f"[FIX] Конвертируем GeneratedStrategy в Strategy для анализа")
                strategy = self._convert_generated_strategy_to_strategy(strategy)
            
            loop = asyncio.get_event_loop()
            
            # Загрузка PCAP файла через RawPCAPReader
            LOG.info(f"Загрузка PCAP файла через RawPCAPReader: {pcap_file}")
            packets = await loop.run_in_executor(None, self.pcap_reader.read_pcap_file, pcap_file)
            
            LOG.info(f"📦 Загружено {len(packets)} пакетов из PCAP")

            # Анализируем все типы пакетов, не только TCP
            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
            udp_packets = [p for p in packets if p.protocol == ProtocolType.UDP]
            icmp_packets = [p for p in packets if p.protocol == ProtocolType.ICMP]
            
            LOG.info(f"Статистика пакетов: TCP={len(tcp_packets)}, UDP={len(udp_packets)}, ICMP={len(icmp_packets)}, Всего={len(packets)}")
            
            # Ищем релевантные пакеты для анализа
            relevant_packets = self._filter_relevant_packets(packets, domain)
            LOG.info(f"Найдено {len(relevant_packets)} релевантных пакетов для анализа")
            
            # Если нет релевантных пакетов, используем все
            if not relevant_packets:
                LOG.debug("Нет релевантных пакетов, используем все пакеты для анализа")
                relevant_packets = packets
            
            sni_analysis = self._analyze_sni_filtering(tcp_packets)

            # Детекция причин неудач
            failure_cause = self._detect_failure_cause(packets, strategy)
            failure_details = self._extract_failure_details(packets, failure_cause, strategy)

            # Определим домен: приоритет domain аргумента, затем SNI
            target_domain = domain or (sni_analysis["sni_domains"][0] if sni_analysis["sni_domains"] else "unknown")
            failure_details["target_domain"] = target_domain

            # Генерация рекомендаций
            recommendations = self._generate_recommendations(failure_cause, failure_details, strategy)

            # НОВОЕ: Генерация suggested_intents для замкнутого цикла обучения
            suggested_intents = self._generate_suggested_intents(
                failure_cause, 
                failure_details, 
                recommendations
            )

            return FailureReport(
                strategy_id=getattr(strategy, 'id', None) or getattr(strategy, 'name', 'unknown'),
                domain=target_domain,
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=failure_details.get("details", ""),
                failure_details=failure_details,
                recommendations=recommendations,
                suggested_intents=suggested_intents,  # НОВОЕ
                confidence=self._calculate_confidence(packets, failure_cause),
                block_timing=self._compute_block_timing(tcp_packets),
                blocked_after_packet=self._compute_block_index(tcp_packets)
            )
        except Exception as e:
            LOG.error(f"Ошибка Scapy анализа: {e}")
            return self._create_error_report(strategy, FailureCause.UNKNOWN, str(e))
    
    async def _analyze_with_json_converter(self, pcap_file: str, strategy: Any, domain: Optional[str] = None) -> FailureReport:
        import asyncio
        try:
            if not analyze_pcap_json:
                raise RuntimeError("pcap_to_json_analyzer недоступен")

            loop = asyncio.get_event_loop()
            json_data = await loop.run_in_executor(None, analyze_pcap_json, pcap_file)

            # Анализ JSON данных
            failure_cause = self._detect_failure_from_json(json_data, strategy)
            failure_details = self._extract_details_from_json(json_data, failure_cause, strategy)

            target_domain = domain or failure_details.get("target_domain", "unknown")

            recommendations = self._generate_recommendations(failure_cause, failure_details, strategy)

            # НОВОЕ: Генерация suggested_intents для замкнутого цикла обучения
            suggested_intents = self._generate_suggested_intents(
                failure_cause, 
                failure_details, 
                recommendations
            )

            return FailureReport(
                strategy_id=strategy.id or strategy.name,
                domain=target_domain,
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=failure_details.get("details", ""),
                failure_details=failure_details,
                recommendations=recommendations,
                suggested_intents=suggested_intents,  # НОВОЕ
                confidence=failure_details.get("confidence", 0.5)
            )
        except Exception as e:
            LOG.error(f"Ошибка JSON анализа: {e}")
            return self._create_error_report(strategy, FailureCause.UNKNOWN, str(e))
    
    async def _analyze_fallback(self, pcap_file: str, strategy: Strategy) -> FailureReport:
        """Fallback анализ без внешних зависимостей."""
        try:
            # Простой анализ на основе размера файла и метаданных
            file_size = os.path.getsize(pcap_file)
            
            if file_size == 0:
                failure_cause = FailureCause.NETWORK_TIMEOUT
                details = "Пустой PCAP файл - возможно, соединение не установлено"
            elif file_size < 1000:
                failure_cause = FailureCause.CONNECTION_REFUSED
                details = "Малый размер PCAP - возможно, соединение отклонено"
            else:
                failure_cause = FailureCause.UNKNOWN
                details = "Требуется детальный анализ с Scapy"
            
            recommendations = self._generate_recommendations(failure_cause, {"details": details}, strategy)
            
            # НОВОЕ: Генерация suggested_intents для замкнутого цикла обучения
            suggested_intents = self._generate_suggested_intents(
                failure_cause, 
                {"details": details}, 
                recommendations
            )

            return FailureReport(
                strategy_id=strategy.id or strategy.name,
                domain="unknown",
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=details,
                failure_details={"file_size": file_size, "analysis_method": "fallback"},
                recommendations=recommendations,
                suggested_intents=suggested_intents,  # НОВОЕ
                confidence=0.3  # Низкая уверенность для fallback анализа
            )
            
        except Exception as e:
            LOG.error(f"Ошибка fallback анализа: {e}")
            return self._create_error_report(strategy, FailureCause.UNKNOWN, str(e))
    
    def _detect_failure_cause(self, packets: List[RawPacket], strategy: Strategy) -> FailureCause:
        """
        Определение основной причины неудачи на основе пакетов RawPacket.
        Расширенная классификация с детальным анализом.
        
        Args:
            packets: Список пакетов (RawPacket)
            strategy: Стратегия обхода
        
        Returns:
            FailureCause - причина неудачи
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        if not packets:
            return FailureCause.NETWORK_TIMEOUT
        
        # Анализ TCP пакетов
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        if not tcp_packets:
            return FailureCause.NETWORK_TIMEOUT
        
        # 1. Детектор RST инъекций (приоритет 1)
        rst_packets = []
        for p in tcp_packets:
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                if tcp_header.flags & TCPHeader.FLAG_RST:
                    rst_packets.append(p)
        
        if rst_packets:
            rst_analysis = self._analyze_rst_injection(rst_packets, tcp_packets)
            if rst_analysis["is_injection"]:
                return FailureCause.DPI_ACTIVE_RST_INJECTION
        
        # 2. Детектор "черной дыры" - нет ответа на ClientHello (приоритет 2)
        tls_analysis = self._analyze_tls_handshake(tcp_packets)
        if tls_analysis["has_client_hello"] and not tls_analysis["has_server_hello"]:
            # Дополнительная проверка - если есть SYN-ACK, но нет ServerHello
            if tls_analysis["connection_established"]:
                return FailureCause.DPI_CONTENT_INSPECTION
        
        # 3. Детектор проблем с фрагментацией (приоритет 3)
        if self._is_fragmentation_strategy(strategy):
            frag_analysis = self._analyze_fragmentation_effectiveness(tcp_packets, strategy)
            if frag_analysis["fragments_reassembled"]:
                return FailureCause.DPI_REASSEMBLES_FRAGMENTS
        
        # 4. Детектор SNI фильтрации (приоритет 4)
        sni_analysis = self._analyze_sni_filtering(tcp_packets)
        if sni_analysis["sni_blocked"]:
            return FailureCause.DPI_SNI_FILTERING
        
        # 5. Детектор stateful tracking (приоритет 5)
        if self._detect_stateful_tracking(tcp_packets, strategy):
            return FailureCause.DPI_STATEFUL_TRACKING
        
        # 6. Анализ TLS handshake проблем
        if tls_analysis["handshake_failed"]:
            return FailureCause.TLS_HANDSHAKE_FAILURE
        
        # 7. Проверка на connection refused
        if self._is_connection_refused(tcp_packets):
            return FailureCause.CONNECTION_REFUSED
        
        return FailureCause.UNKNOWN
    
    def _detect_failure_from_json(self, json_data: Dict, strategy: Strategy) -> FailureCause:
        """Определение причины неудачи из JSON данных."""
        flows = json_data.get("flows", {})
        
        if not flows:
            return FailureCause.NETWORK_TIMEOUT
        
        # Анализ потоков для поиска RST пакетов
        for flow_name, packets in flows.items():
            rst_count = sum(1 for p in packets if "RST" in p.get("flags", ""))
            if rst_count > 0:
                return FailureCause.DPI_ACTIVE_RST_INJECTION
        
        # Поиск TLS проблем
        tls_issues = self._analyze_tls_from_json(json_data)
        if tls_issues:
            return FailureCause.TLS_HANDSHAKE_FAILURE
        
        return FailureCause.UNKNOWN
    
    def _analyze_rst_injection(self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]) -> Dict[str, Any]:
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
            "confidence": 0.0
        }
        
        if not rst_packets:
            return analysis
        
        # Индикатор 1: Множественные RST пакеты
        if len(rst_packets) > 1:
            analysis["injection_indicators"].append("multiple_rst_packets")
            analysis["confidence"] += 0.3
        
        # Индикатор 2: Анализ TTL значений
        ttl_analysis = self._analyze_rst_ttl(rst_packets, all_tcp_packets)
        if ttl_analysis["suspicious_ttl"]:
            analysis["injection_indicators"].append("suspicious_ttl")
            analysis["confidence"] += 0.4
        
        # Индикатор 3: Анализ seq/ack номеров
        seq_analysis = self._analyze_rst_sequence_numbers(rst_packets, all_tcp_packets)
        if seq_analysis["invalid_sequence"]:
            analysis["injection_indicators"].append("invalid_sequence_numbers")
            analysis["confidence"] += 0.5
        
        # Индикатор 4: Временной анализ (RST приходит слишком быстро)
        timing_analysis = self._analyze_rst_timing(rst_packets, all_tcp_packets)
        if timing_analysis["too_fast"]:
            analysis["injection_indicators"].append("unrealistic_timing")
            analysis["confidence"] += 0.3
        
        # Индикатор 5: Анализ источника RST (разные IP для одного соединения)
        source_analysis = self._analyze_rst_sources(rst_packets)
        if source_analysis["multiple_sources"]:
            analysis["injection_indicators"].append("multiple_rst_sources")
            analysis["confidence"] += 0.6
        
        # Определяем инъекцию при уверенности > 0.5
        analysis["is_injection"] = analysis["confidence"] > 0.5
        
        return analysis
    
    def _analyze_rst_ttl(self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """Анализ TTL значений в RST пакетах для детекции инъекций."""
        from collections import defaultdict
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        # Собираем базовые TTL по src для не-RST пакетов
        base_ttl = defaultdict(list)
        for p in all_tcp_packets:
            # Парсим IP и TCP заголовки
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                # Проверяем, что это не RST пакет
                if not (tcp_header.flags & TCPHeader.FLAG_RST):
                    base_ttl[p.src_ip].append(ip_header.ttl)
        
        base_ttl_median = {k: (sorted(v)[len(v)//2] if v else None) for k, v in base_ttl.items()}

        suspicious = 0
        ttl_values = []
        for rst in rst_packets:
            if len(rst.data) >= 20:
                ip_header = IPHeader.unpack(rst.data[:20])
                ttl = ip_header.ttl
                ttl_values.append(ttl)
                src = rst.src_ip
                ref = base_ttl_median.get(src)
                if ref is not None and abs(int(ttl) - int(ref)) >= 16:  # расхождение > ~16 хопов
                    suspicious += 1

        return {
            "suspicious_ttl": suspicious > 0,
            "ttl_values": ttl_values,
            "suspicious_count": suspicious
        }
    
    def _compute_block_timing(self, tcp_packets: List[RawPacket]) -> Optional[float]:
        """
        Вычисление времени блокировки (разница между RST и ClientHello).
        
        Note: RawPacket не содержит временные метки, поэтому возвращаем None.
        Для точного анализа времени требуется расширение RawPacket.
        """
        # TODO: Добавить поддержку временных меток в RawPacket
        return None

    def _compute_block_index(self, tcp_packets: List[RawPacket]) -> Optional[int]:
        """
        Индекс пакета после которого произошла блокировка (первый RST или конец данных).
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            
        Returns:
            Индекс первого RST пакета или None
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        for idx, p in enumerate(tcp_packets):
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                if tcp_header.flags & TCPHeader.FLAG_RST:
                    return idx
        return None
    
    def _analyze_rst_sequence_numbers(self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """Анализ seq/ack номеров в RST пакетах."""
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        # Собираем легитимные seq/ack номера из соединения
        legitimate_seqs = set()
        legitimate_acks = set()
        
        for pkt in all_tcp_packets:
            if len(pkt.data) >= 40:
                ip_header = IPHeader.unpack(pkt.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(pkt.data[ip_header_size:])
                
                # Исключаем RST пакеты
                if not (tcp_header.flags & TCPHeader.FLAG_RST):
                    legitimate_seqs.add(tcp_header.seq_num)
                    legitimate_acks.add(tcp_header.ack_num)
        
        invalid_count = 0
        for rst in rst_packets:
            if len(rst.data) >= 40:
                ip_header = IPHeader.unpack(rst.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(rst.data[ip_header_size:])
                
                # RST должен иметь валидные seq/ack номера
                if (tcp_header.seq_num not in legitimate_seqs and 
                    tcp_header.ack_num not in legitimate_acks):
                    invalid_count += 1
        
        return {
            "invalid_sequence": invalid_count > 0,
            "invalid_count": invalid_count,
            "total_rst": len(rst_packets)
        }
    
    def _analyze_rst_timing(self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Анализ временных характеристик RST пакетов.
        
        Note: RawPacket не содержит временные метки, поэтому анализ времени ограничен.
        Возвращаем консервативные результаты.
        """
        # TODO: Добавить поддержку временных меток в RawPacket для точного анализа
        return {
            "too_fast": False,
            "fast_rst_count": 0,
            "note": "Timing analysis requires timestamp support in RawPacket"
        }
    
    def _analyze_rst_sources(self, rst_packets: List[RawPacket]) -> Dict[str, Any]:
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
            "sources": list(sources)
        }
    
    def _analyze_tls_handshake(self, tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Детальный анализ TLS handshake для обнаружения блокировок.
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
        
        Returns:
            Dict с результатами анализа TLS handshake
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        analysis = {
            "has_client_hello": False,
            "has_server_hello": False,
            "connection_established": False,
            "handshake_failed": False,
            "client_hello_count": 0,
            "server_hello_count": 0,
            "tls_alerts": []
        }
        
        # Проверяем установление TCP соединения
        syn_packets = []
        syn_ack_packets = []
        
        for p in tcp_packets:
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                # SYN без ACK
                if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (tcp_header.flags & TCPHeader.FLAG_ACK):
                    syn_packets.append(p)
                # SYN-ACK
                elif (tcp_header.flags & TCPHeader.FLAG_SYN) and (tcp_header.flags & TCPHeader.FLAG_ACK):
                    syn_ack_packets.append(p)
        
        if syn_packets and syn_ack_packets:
            analysis["connection_established"] = True
        
        # Анализируем TLS пакеты
        for packet in tcp_packets:
            if packet.payload:
                payload = packet.payload
                
                # ClientHello detection
                if self._is_client_hello_payload(payload):
                    analysis["has_client_hello"] = True
                    analysis["client_hello_count"] += 1
                
                # ServerHello detection
                elif self._is_server_hello_payload(payload):
                    analysis["has_server_hello"] = True
                    analysis["server_hello_count"] += 1
                
                # TLS Alert detection
                elif self._is_tls_alert(payload):
                    alert_info = self._parse_tls_alert(payload)
                    analysis["tls_alerts"].append(alert_info)
        
        # Определяем неудачу handshake
        if analysis["has_client_hello"] and not analysis["has_server_hello"]:
            if analysis["connection_established"]:
                # TCP соединение есть, но TLS handshake не завершен - блокировка контента
                analysis["handshake_failed"] = True
        
        return analysis
    
    def _is_client_hello_payload(self, payload: bytes) -> bool:
        """Проверка, является ли payload TLS ClientHello."""
        try:
            # TLS Record: Type(1) + Version(2) + Length(2) + Handshake Header
            # Handshake: Type(1) + Length(3) + ...
            if len(payload) < 6:
                return False
            
            # TLS Record Type: Handshake (0x16)
            if payload[0] != 0x16:
                return False
            
            # TLS Version (обычно 0x0301, 0x0302, 0x0303)
            if len(payload) < 3 or payload[1] not in [0x03]:
                return False
            
            # Handshake Type: ClientHello (0x01)
            if len(payload) < 6 or payload[5] != 0x01:
                return False
            
            return True
        except:
            return False
    
    def _is_server_hello_payload(self, payload: bytes) -> bool:
        """Проверка, является ли payload TLS ServerHello."""
        try:
            if len(payload) < 6:
                return False
            
            # TLS Record Type: Handshake (0x16)
            if payload[0] != 0x16:
                return False
            
            # Handshake Type: ServerHello (0x02)
            if payload[5] != 0x02:
                return False
            
            return True
        except:
            return False
    
    def _is_tls_alert(self, payload: bytes) -> bool:
        """Проверка, является ли payload TLS Alert."""
        try:
            # TLS Record Type: Alert (0x15)
            return len(payload) >= 1 and payload[0] == 0x15
        except:
            return False
    
    def _parse_tls_alert(self, payload: bytes) -> Dict[str, Any]:
        """Парсинг TLS Alert сообщения."""
        try:
            if len(payload) >= 7:
                alert_level = payload[5]  # Warning (1) or Fatal (2)
                alert_description = payload[6]
                
                return {
                    "level": "warning" if alert_level == 1 else "fatal",
                    "description_code": alert_description,
                    "description": self._get_tls_alert_description(alert_description)
                }
        except:
            pass
        
        return {"level": "unknown", "description": "parse_error"}
    
    def _get_tls_alert_description(self, code: int) -> str:
        """Получение описания TLS Alert по коду."""
        alert_descriptions = {
            0: "close_notify",
            10: "unexpected_message",
            20: "bad_record_mac",
            21: "decryption_failed",
            22: "record_overflow",
            30: "decompression_failure",
            40: "handshake_failure",
            41: "no_certificate",
            42: "bad_certificate",
            43: "unsupported_certificate",
            44: "certificate_revoked",
            45: "certificate_expired",
            46: "certificate_unknown",
            47: "illegal_parameter",
            48: "unknown_ca",
            49: "access_denied",
            50: "decode_error",
            51: "decrypt_error",
            70: "protocol_version",
            71: "insufficient_security",
            80: "internal_error",
            90: "user_canceled",
            100: "no_renegotiation",
            110: "unsupported_extension"
        }
        
        return alert_descriptions.get(code, f"unknown_alert_{code}")
    
    def _is_fragmentation_strategy(self, strategy: Strategy) -> bool:
        """Проверка, является ли стратегия основанной на фрагментации."""
        fragmentation_keywords = [
            "split", "frag", "multisplit", "disorder", 
            "fragment", "chunk", "piece"
        ]
        
        strategy_name = strategy.name.lower()
        attack_name = strategy.attack_name.lower()
        
        return any(keyword in strategy_name or keyword in attack_name 
                  for keyword in fragmentation_keywords)
    
    def _analyze_fragmentation_effectiveness(self, tcp_packets: List[RawPacket], strategy: Strategy) -> Dict[str, Any]:
        """
        Анализ эффективности стратегий фрагментации.
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            strategy: Стратегия обхода
        
        Returns:
            Dict с результатами анализа фрагментации
        """
        from core.packet.raw_packet_engine import IPHeader
        
        analysis = {
            "fragments_reassembled": False,
            "fragmented_packets_count": 0,
            "reassembly_indicators": [],
            "confidence": 0.0
        }
        
        # Подсчет фрагментированных пакетов
        fragmented_packets = []
        for packet in tcp_packets:
            if len(packet.data) >= 20:
                ip_header = IPHeader.unpack(packet.data[:20])
                
                # IP фрагментация
                if ip_header.flags & 0x1 or ip_header.fragment_offset > 0:  # MF flag or fragment offset
                    fragmented_packets.append(packet)
                    analysis["fragmented_packets_count"] += 1
            
            # TCP сегментация (малые пакеты)
            if packet.payload:
                payload_size = len(packet.payload)
                if payload_size < 100:  # Малые сегменты
                    analysis["fragmented_packets_count"] += 1
        
        # Если есть фрагменты, но соединение заблокировано - DPI собирает фрагменты
        if analysis["fragmented_packets_count"] > 0:
            # Проверяем признаки сборки фрагментов DPI
            
            # Индикатор 1: Блокировка происходит после получения всех фрагментов
            if self._block_after_reassembly(tcp_packets, fragmented_packets):
                analysis["reassembly_indicators"].append("block_after_reassembly")
                analysis["confidence"] += 0.4
            
            # Индикатор 2: Нормальная TCP сборка, но блокировка на уровне приложения
            if self._normal_tcp_reassembly_but_blocked(tcp_packets):
                analysis["reassembly_indicators"].append("tcp_reassembly_blocked")
                analysis["confidence"] += 0.3
            
            # Индикатор 3: Фрагменты приходят в правильном порядке, но блокируются
            if self._ordered_fragments_blocked(fragmented_packets):
                analysis["reassembly_indicators"].append("ordered_fragments_blocked")
                analysis["confidence"] += 0.2
        
        analysis["fragments_reassembled"] = analysis["confidence"] > 0.3
        
        return analysis
    
    def _block_after_reassembly(self, tcp_packets: List[RawPacket], fragmented_packets: List[RawPacket]) -> bool:
        """
        Проверка блокировки после сборки фрагментов.
        
        Args:
            tcp_packets: Все TCP пакеты (RawPacket)
            fragmented_packets: Фрагментированные пакеты (RawPacket)
        
        Returns:
            True если обнаружена блокировка после сборки фрагментов
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        if not fragmented_packets:
            return False
        
        # Без временных меток, проверяем наличие RST после фрагментов в последовательности
        frag_indices = []
        for i, p in enumerate(tcp_packets):
            if p in fragmented_packets:
                frag_indices.append(i)
        
        if not frag_indices:
            return False
        
        last_frag_index = max(frag_indices)
        
        # Проверяем, есть ли RST после последнего фрагмента
        for i in range(last_frag_index + 1, len(tcp_packets)):
            p = tcp_packets[i]
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                if tcp_header.flags & TCPHeader.FLAG_RST:
                    return True
        
        return False
    
    def _normal_tcp_reassembly_but_blocked(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка нормальной TCP сборки, но блокировки на уровне приложения.
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            
        Returns:
            True если TCP сборка успешна, но приложение заблокировано
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        # Ищем ACK пакеты (успешная TCP сборка) но отсутствие ответа приложения
        ack_packets = []
        data_packets = []
        
        for p in tcp_packets:
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                if tcp_header.flags & TCPHeader.FLAG_ACK:
                    ack_packets.append(p)
                
                if p.payload and len(p.payload) > 0:
                    data_packets.append(p)
        
        return len(ack_packets) > 0 and len(data_packets) > 0
    
    def _ordered_fragments_blocked(self, fragmented_packets: List[RawPacket]) -> bool:
        """
        Проверка блокировки упорядоченных фрагментов.
        
        Note: RawPacket не содержит временные метки, поэтому проверяем порядок по sequence numbers.
        
        Args:
            fragmented_packets: Список фрагментированных пакетов (RawPacket)
            
        Returns:
            True если фрагменты упорядочены, но заблокированы
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        if len(fragmented_packets) < 2:
            return False
        
        # Проверяем, что фрагменты идут в правильном порядке по sequence numbers
        seq_numbers = []
        for p in fragmented_packets:
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                seq_numbers.append(tcp_header.seq_num)
        
        return seq_numbers == sorted(seq_numbers)
    
    def _filter_relevant_packets(self, packets: List[RawPacket], domain: Optional[str] = None) -> List[RawPacket]:
        """
        Фильтрация пакетов, релевантных для анализа неудачи.
        
        Args:
            packets: Список всех пакетов (RawPacket)
            domain: Целевой домен (опционально)
            
        Returns:
            Список релевантных пакетов (RawPacket)
        """
        if not packets:
            return []
        
        relevant_packets = []
        
        # Если указан домен, пытаемся найти его IP
        target_ips = set()
        if domain:
            try:
                import socket
                target_ip = socket.gethostbyname(domain)
                target_ips.add(target_ip)
                LOG.debug(f"Целевой IP для {domain}: {target_ip}")
            except:
                LOG.debug(f"Не удалось разрешить IP для {domain}")
        
        for packet in packets:
            is_relevant = False
            
            # TCP пакеты всегда релевантны
            if packet.protocol == ProtocolType.TCP:
                is_relevant = True
            
            # UDP пакеты к портам 53 (DNS), 443, 80
            elif packet.protocol == ProtocolType.UDP and packet.dst_port in [53, 80, 443]:
                is_relevant = True
            
            # Пакеты к целевому IP
            elif target_ips and packet.dst_ip in target_ips:
                is_relevant = True
            
            # ICMP пакеты (могут указывать на блокировку)
            elif packet.protocol == ProtocolType.ICMP:
                is_relevant = True
            
            # Пакеты с TLS/SSL данными
            elif packet.payload:
                payload = packet.payload
                # Проверяем на TLS handshake
                if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                    is_relevant = True
                # Проверяем на HTTP
                elif b'HTTP' in payload[:100] or b'GET ' in payload[:100] or b'POST ' in payload[:100]:
                    is_relevant = True
            
            if is_relevant:
                relevant_packets.append(packet)
        
        LOG.debug(f"Отфильтровано {len(relevant_packets)} релевантных пакетов из {len(packets)}")
        return relevant_packets
    
    def _analyze_sni_filtering(self, tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Анализ блокировки по SNI (Server Name Indication).
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
        
        Returns:
            Dict с результатами анализа SNI фильтрации
        """
        analysis = {
            "sni_blocked": False,
            "sni_found": False,
            "sni_domains": [],
            "blocking_indicators": [],
            "confidence": 0.0
        }
        
        client_hello_packets = []
        
        # Ищем ClientHello пакеты и извлекаем SNI
        for packet in tcp_packets:
            if packet.payload:
                payload = packet.payload
                if self._is_client_hello_payload(payload):
                    client_hello_packets.append(packet)
                    
                    # Пытаемся извлечь SNI используя RawPacketEngine
                    sni_domain = self.packet_engine.extract_tls_sni(payload)
                    if sni_domain:
                        analysis["sni_found"] = True
                        analysis["sni_domains"].append(sni_domain)
        
        if analysis["sni_found"]:
            # Индикатор 1: ClientHello с SNI есть, но ServerHello нет
            server_hello_packets = [
                p for p in tcp_packets 
                if p.payload and self._is_server_hello_payload(p.payload)
            ]
            
            if client_hello_packets and not server_hello_packets:
                analysis["blocking_indicators"].append("no_server_hello_after_sni")
                analysis["confidence"] += 0.4
            
            # Индикатор 2: Быстрый RST после ClientHello с SNI
            rst_after_client_hello = self._rst_after_client_hello(client_hello_packets, tcp_packets)
            if rst_after_client_hello:
                analysis["blocking_indicators"].append("rst_after_client_hello")
                analysis["confidence"] += 0.5
            
            # Индикатор 3: Блокировка специфичных доменов
            if self._is_blocked_domain_pattern(analysis["sni_domains"]):
                analysis["blocking_indicators"].append("blocked_domain_pattern")
                analysis["confidence"] += 0.3
        
        analysis["sni_blocked"] = analysis["confidence"] > 0.4
        
        return analysis
    
    def _extract_sni_from_client_hello(self, payload: bytes) -> Optional[str]:
        """Извлечение SNI из ClientHello пакета."""
        try:
            # Упрощенный парсинг SNI из TLS ClientHello
            # Ищем SNI extension (type 0x0000)
            
            if len(payload) < 50:  # Минимальный размер для ClientHello с SNI
                return None
            
            # Пропускаем TLS Record Header (5 bytes) и Handshake Header (4 bytes)
            offset = 9
            
            # Пропускаем Version (2) + Random (32) + Session ID Length + Session ID
            if offset + 2 + 32 + 1 >= len(payload):
                return None
            
            offset += 2 + 32  # Version + Random
            session_id_length = payload[offset]
            offset += 1 + session_id_length
            
            # Пропускаем Cipher Suites
            if offset + 2 >= len(payload):
                return None
            cipher_suites_length = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_length
            
            # Пропускаем Compression Methods
            if offset + 1 >= len(payload):
                return None
            compression_methods_length = payload[offset]
            offset += 1 + compression_methods_length
            
            # Extensions
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
                    return self._parse_sni_extension(payload[offset:offset + ext_length])
                
                offset += ext_length
            
            return None
        except:
            return None
    
    def _parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """Парсинг SNI extension."""
        try:
            if len(sni_data) < 5:
                return None
            
            # SNI List Length (2 bytes)
            offset = 2
            
            # SNI Type (1 byte) - должен быть 0x00 для hostname
            if sni_data[offset] != 0x00:
                return None
            offset += 1
            
            # SNI Length (2 bytes)
            sni_length = (sni_data[offset] << 8) | sni_data[offset + 1]
            offset += 2
            
            if offset + sni_length > len(sni_data):
                return None
            
            # SNI Hostname
            hostname = sni_data[offset:offset + sni_length].decode('utf-8', errors='ignore')
            return hostname
        except:
            return None
    
    def _rst_after_client_hello(self, client_hello_packets: List[RawPacket], tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка RST после ClientHello.
        
        Args:
            client_hello_packets: Список пакетов с ClientHello (RawPacket)
            tcp_packets: Все TCP пакеты (RawPacket)
        
        Returns:
            True если найдены RST пакеты после ClientHello
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        if not client_hello_packets:
            return False
        
        # Без временных меток, просто проверяем наличие RST пакетов
        # после ClientHello в последовательности пакетов
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
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                if tcp_header.flags & TCPHeader.FLAG_RST:
                    return True
        
        return False
    
    def _is_blocked_domain_pattern(self, domains: List[str]) -> bool:
        """Проверка паттернов заблокированных доменов."""
        blocked_patterns = [
            "twitter.com", "x.com", "facebook.com", "instagram.com",
            "youtube.com", "telegram.org", "discord.com"
        ]
        
        for domain in domains:
            for pattern in blocked_patterns:
                if pattern in domain.lower():
                    return True
        
        return False
    
    def _detect_stateful_tracking(self, tcp_packets: List[RawPacket], strategy: Strategy) -> bool:
        """
        Детекция stateful отслеживания DPI.
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            strategy: Стратегия обхода
        
        Returns:
            True если обнаружено stateful отслеживание
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
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
                if len(p.data) >= 40:
                    ip_header = IPHeader.unpack(p.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                    
                    if tcp_header.flags & TCPHeader.FLAG_RST:
                        rst_count += 1
            
            return rst_count > 0
        
        return False
    
    def _is_connection_refused(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка отклонения соединения.
        
        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
        
        Returns:
            True если соединение было отклонено
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        syn = []
        syn_ack = []
        rst = []
        
        for p in tcp_packets:
            if len(p.data) >= 40:
                ip_header = IPHeader.unpack(p.data[:20])
                ip_header_size = ip_header.ihl * 4
                tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                
                # SYN без ACK
                if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (tcp_header.flags & TCPHeader.FLAG_ACK):
                    syn.append(p)
                # SYN-ACK
                elif (tcp_header.flags & TCPHeader.FLAG_SYN) and (tcp_header.flags & TCPHeader.FLAG_ACK):
                    syn_ack.append(p)
                # RST
                elif tcp_header.flags & TCPHeader.FLAG_RST:
                    rst.append(p)

        # если был ClientHello, не уводим в refused
        saw_client_hello = any(p.payload and self._is_client_hello_payload(p.payload) for p in tcp_packets)
        if saw_client_hello:
            return False

        return len(syn) > 0 and (len(syn_ack) == 0 or len(rst) > 0)
    
    def _analyze_tls_from_json(self, json_data: Dict) -> bool:
        """Анализ TLS проблем из JSON данных."""
        flows = json_data.get("flows", {})
        
        for flow_name, packets in flows.items():
            # Поиск TLS handshake проблем
            has_client_hello = any(p.get("payload_len", 0) > 100 for p in packets)
            has_server_response = any(p.get("src_port") == 443 for p in packets)
            
            if has_client_hello and not has_server_response:
                return True
        
        return False
    
    def _extract_failure_details(self, packets: List[RawPacket], failure_cause: FailureCause, strategy: Strategy) -> Dict[str, Any]:
        """
        Извлечение детальной информации о неудаче с расширенным анализом.
        
        Args:
            packets: Список всех пакетов (RawPacket)
            failure_cause: Причина неудачи
            strategy: Стратегия обхода
            
        Returns:
            Dict с детальной информацией о неудаче
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
        
        details = {
            "packet_count": len(packets),
            "tcp_packet_count": len(tcp_packets),
            "strategy_name": strategy.name,
            "attack_name": strategy.attack_name,
            "analysis_method": "raw_packet_engine",
            "details": "",
            "technical_details": {}
        }
        
        if failure_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            # Находим RST пакеты
            rst_packets = []
            for p in tcp_packets:
                if len(p.data) >= 40:
                    ip_header = IPHeader.unpack(p.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                    
                    if tcp_header.flags & TCPHeader.FLAG_RST:
                        rst_packets.append(p)
            
            rst_analysis = self._analyze_rst_injection(rst_packets, tcp_packets)
            
            details.update({
                "rst_count": len(rst_packets),
                "injection_confidence": rst_analysis["confidence"],
                "injection_indicators": rst_analysis["injection_indicators"],
                "details": f"DPI RST инъекция обнаружена с уверенностью {rst_analysis['confidence']:.2f}. "
                          f"Индикаторы: {', '.join(rst_analysis['injection_indicators'])}",
                "technical_details": rst_analysis
            })
        
        elif failure_cause == FailureCause.DPI_CONTENT_INSPECTION:
            tls_analysis = self._analyze_tls_handshake(tcp_packets)
            
            details.update({
                "client_hello_count": tls_analysis["client_hello_count"],
                "server_hello_count": tls_analysis["server_hello_count"],
                "tls_alerts": tls_analysis["tls_alerts"],
                "details": f"DPI блокирует содержимое TLS. ClientHello: {tls_analysis['client_hello_count']}, "
                          f"ServerHello: {tls_analysis['server_hello_count']}",
                "technical_details": tls_analysis
            })
        
        elif failure_cause == FailureCause.DPI_REASSEMBLES_FRAGMENTS:
            frag_analysis = self._analyze_fragmentation_effectiveness(tcp_packets, strategy)
            
            details.update({
                "fragmented_packets": frag_analysis["fragmented_packets_count"],
                "reassembly_confidence": frag_analysis["confidence"],
                "reassembly_indicators": frag_analysis["reassembly_indicators"],
                "details": f"DPI собирает фрагменты. Фрагментированных пакетов: {frag_analysis['fragmented_packets_count']}, "
                          f"индикаторы сборки: {', '.join(frag_analysis['reassembly_indicators'])}",
                "technical_details": frag_analysis
            })
        
        elif failure_cause == FailureCause.DPI_SNI_FILTERING:
            sni_analysis = self._analyze_sni_filtering(tcp_packets)
            
            details.update({
                "sni_domains": sni_analysis["sni_domains"],
                "sni_blocking_confidence": sni_analysis["confidence"],
                "blocking_indicators": sni_analysis["blocking_indicators"],
                "details": f"DPI блокирует по SNI. Домены: {', '.join(sni_analysis['sni_domains'])}, "
                          f"индикаторы: {', '.join(sni_analysis['blocking_indicators'])}",
                "technical_details": sni_analysis
            })
        
        elif failure_cause == FailureCause.DPI_STATEFUL_TRACKING:
            details.update({
                "details": "DPI отслеживает состояние соединения - stateful evasion неэффективен",
                "strategy_type": "stateful_evasion"
            })
        
        elif failure_cause == FailureCause.TLS_HANDSHAKE_FAILURE:
            tls_analysis = self._analyze_tls_handshake(tcp_packets)
            
            details.update({
                "tls_alerts": tls_analysis["tls_alerts"],
                "details": f"TLS handshake неудачен. Алерты: {len(tls_analysis['tls_alerts'])}",
                "technical_details": tls_analysis
            })
        
        elif failure_cause == FailureCause.CONNECTION_REFUSED:
            # Находим SYN и RST пакеты
            syn_packets = []
            rst_packets = []
            
            for p in tcp_packets:
                if len(p.data) >= 40:
                    ip_header = IPHeader.unpack(p.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                    
                    # SYN без ACK
                    if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (tcp_header.flags & TCPHeader.FLAG_ACK):
                        syn_packets.append(p)
                    # RST
                    elif tcp_header.flags & TCPHeader.FLAG_RST:
                        rst_packets.append(p)
            
            details.update({
                "syn_count": len(syn_packets),
                "rst_count": len(rst_packets),
                "details": f"Соединение отклонено. SYN: {len(syn_packets)}, RST: {len(rst_packets)}"
            })
        
        elif failure_cause == FailureCause.NETWORK_TIMEOUT:
            details.update({
                "details": "Таймаут сети - пакеты не достигают цели или ответ не приходит"
            })
        
        else:  # UNKNOWN
            details.update({
                "details": "Причина неудачи не определена - требуется дополнительный анализ"
            })
        
        return details
    
    def _extract_details_from_json(self, json_data: Dict, failure_cause: FailureCause, strategy: Strategy) -> Dict[str, Any]:
        """Извлечение деталей из JSON данных."""
        details = {
            "total_flows": json_data.get("total_flows", 0),
            "strategy_name": strategy.name,
            "analysis_method": "json_converter",
            "confidence": 0.7
        }
        
        flows = json_data.get("flows", {})
        if flows:
            # Анализ первого потока для получения целевого домена
            first_flow = list(flows.values())[0]
            if first_flow:
                first_packet = first_flow[0]
                details["target_domain"] = first_packet.get("dst_ip", "unknown")
        
        return details
    
    def generate_recommendations(self, failure_report: FailureReport) -> List[Recommendation]:
        """
        Публичный метод для генерации рекомендаций на основе отчета о неудаче.
        Интегрируется с системой Intent'ов для предложения альтернативных стратегий.
        
        Args:
            failure_report: Отчет об анализе неудачи стратегии
            
        Returns:
            Список рекомендаций с приоритетами и параметрами
        """
        LOG.info(f"Генерация рекомендаций для {failure_report.strategy_id}")
        
        # Базовые рекомендации на основе причины неудачи
        base_recommendations = self._generate_recommendations(
            failure_report.root_cause, 
            failure_report.failure_details, 
            Strategy(
                name=failure_report.strategy_id,
                attack_name=failure_report.strategy_id
            )
        )
        
        # Интеграция с системой Intent'ов
        intent_recommendations = self._generate_intent_based_recommendations(failure_report)
        
        # Объединяем и ранжируем рекомендации
        all_recommendations = base_recommendations + intent_recommendations
        
        # Удаляем дубликаты и сортируем по приоритету
        unique_recommendations = self._deduplicate_recommendations(all_recommendations)
        sorted_recommendations = sorted(unique_recommendations, key=lambda x: x.priority, reverse=True)
        
        LOG.info(f"Сгенерировано {len(sorted_recommendations)} уникальных рекомендаций")
        
        return sorted_recommendations
    
    def _generate_intent_based_recommendations(self, failure_report: FailureReport) -> List[Recommendation]:
        """
        Генерация рекомендаций на основе системы Intent'ов.
        Создает маппинг причин неудач на рекомендуемые Intent'ы.
        """
        intent_recommendations = []
        
        # Маппинг причин неудач на Intent'ы
        failure_to_intents = {
            FailureCause.DPI_ACTIVE_RST_INJECTION: [
                ("short_ttl_decoy", "Используйте пакеты с коротким TTL для обхода RST инъекций"),
                ("out_of_order_decoy", "Попробуйте атаки с нарушением порядка пакетов"),
                ("sequence_overlap", "Создайте перекрытие TCP последовательностей")
            ],
            FailureCause.DPI_REASSEMBLES_FRAGMENTS: [
                ("packet_reordering", "Переключитесь на изменение порядка пакетов"),
                ("timing_manipulation", "Используйте манипуляции с таймингом"),
                ("sequence_overlap", "Попробуйте перекрытие последовательностей")
            ],
            FailureCause.DPI_SNI_FILTERING: [
                ("conceal_sni", "Скройте SNI от DPI анализа"),
                ("fake_sni", "Отправьте поддельный SNI перед настоящим"),
                ("record_fragmentation", "Фрагментируйте TLS записи")
            ],
            FailureCause.DPI_CONTENT_INSPECTION: [
                ("payload_obfuscation", "Обфусцируйте содержимое пакетов"),
                ("tls_extension_manipulation", "Манипулируйте TLS расширениями"),
                ("record_fragmentation", "Используйте фрагментацию записей")
            ],
            FailureCause.DPI_STATEFUL_TRACKING: [
                ("sequence_overlap", "Создайте перекрытие TCP последовательностей"),
                ("packet_reordering", "Нарушьте порядок пакетов"),
                ("timing_manipulation", "Измените тайминг отправки")
            ]
        }
        
        # Получаем Intent'ы для данной причины неудачи
        intent_mappings = failure_to_intents.get(failure_report.root_cause, [])
        
        for intent_key, rationale in intent_mappings:
            # Определяем приоритет на основе уверенности в анализе
            priority = 0.7 + (failure_report.confidence * 0.2)
            
            # Создаем параметры на основе Intent'а
            parameters = self._get_intent_parameters(intent_key, failure_report)
            
            recommendation = Recommendation(
                action=f"apply_intent_{intent_key}",
                rationale=f"{rationale} (Intent: {intent_key})",
                priority=priority,
                parameters=parameters
            )
            
            intent_recommendations.append(recommendation)
        
        # Добавляем альтернативные Intent'ы на основе технических деталей
        alternative_intents = self._suggest_alternative_intents(failure_report)
        intent_recommendations.extend(alternative_intents)
        
        return intent_recommendations
    
    def _get_intent_parameters(self, intent_key: str, failure_report: FailureReport) -> Dict[str, Any]:
        """Получение параметров для Intent'а на основе анализа неудачи."""
        
        base_parameters = {
            "intent_key": intent_key,
            "confidence": failure_report.confidence,
            "source": "failure_analysis"
        }
        
        # Специфичные параметры для каждого Intent'а
        intent_specific_params = {
            "short_ttl_decoy": {
                "ttl": 1,
                "fooling_method": "badseq",
                "reason": "rst_injection_detected"
            },
            "conceal_sni": {
                "split_position": "sni",
                "fooling_method": "badsum",
                "reason": "sni_filtering_detected"
            },
            "record_fragmentation": {
                "split_count": 8,
                "split_position": "random",
                "reason": "content_inspection_detected"
            },
            "packet_reordering": {
                "reorder_method": "simple",
                "split_positions": [2, 3],
                "reason": "fragmentation_reassembly_detected"
            },
            "sequence_overlap": {
                "overlap_size": 2,
                "reason": "stateful_tracking_detected"
            },
            "timing_manipulation": {
                "delay_ms": 50,
                "jitter_enabled": True,
                "reason": "timing_sensitive_dpi"
            },
            "payload_obfuscation": {
                "obfuscation_method": "xor",
                "reason": "deep_content_inspection"
            }
        }
        
        specific_params = intent_specific_params.get(intent_key, {})
        base_parameters.update(specific_params)
        
        # Адаптируем параметры на основе технических деталей неудачи
        technical_details = failure_report.failure_details.get("technical_details", {})
        
        if intent_key == "short_ttl_decoy" and "injection_indicators" in technical_details:
            indicators = technical_details["injection_indicators"]
            if "suspicious_ttl" in indicators:
                base_parameters["ttl"] = 2  # Используем TTL=2 если DPI использует TTL=1
        
        if intent_key == "record_fragmentation" and "fragmented_packets" in technical_details:
            frag_count = technical_details.get("fragmented_packets", 0)
            if frag_count > 0:
                # Увеличиваем количество фрагментов если простая фрагментация не сработала
                base_parameters["split_count"] = min(16, frag_count * 2)
        
        return base_parameters
    
    def _suggest_alternative_intents(self, failure_report: FailureReport) -> List[Recommendation]:
        """Предложение альтернативных Intent'ов на основе технических деталей."""
        
        alternative_recommendations = []
        technical_details = failure_report.failure_details.get("technical_details", {})
        
        # Анализ RST инъекций для предложения альтернатив
        if failure_report.root_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            injection_indicators = technical_details.get("injection_indicators", [])
            
            if "multiple_rst_sources" in injection_indicators:
                # Множественные источники RST - попробуйте обход через timing
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_timing_manipulation",
                        rationale="Обнаружены множественные источники RST - попробуйте манипуляции с таймингом",
                        priority=0.75,
                        parameters={"intent_key": "timing_manipulation", "delay_ms": 100}
                    )
                )
            
            if "unrealistic_timing" in injection_indicators:
                # Нереалистичный тайминг - DPI очень быстрый, нужны продвинутые методы
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_sequence_overlap",
                        rationale="DPI реагирует слишком быстро - используйте перекрытие последовательностей",
                        priority=0.8,
                        parameters={"intent_key": "sequence_overlap", "overlap_size": 4}
                    )
                )
        
        # Анализ фрагментации для предложения альтернатив
        elif failure_report.root_cause == FailureCause.DPI_REASSEMBLES_FRAGMENTS:
            reassembly_indicators = technical_details.get("reassembly_indicators", [])
            
            if "tcp_reassembly_blocked" in reassembly_indicators:
                # TCP сборка работает, но блокируется на уровне приложения
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_payload_obfuscation",
                        rationale="TCP сборка работает - попробуйте обфускацию на уровне приложения",
                        priority=0.85,
                        parameters={"intent_key": "payload_obfuscation", "obfuscation_method": "xor"}
                    )
                )
        
        # Анализ SNI фильтрации для предложения альтернатив
        elif failure_report.root_cause == FailureCause.DPI_SNI_FILTERING:
            sni_domains = failure_report.failure_details.get("sni_domains", [])
            
            if sni_domains:
                # Известные заблокированные домены - используйте продвинутое сокрытие
                alternative_recommendations.append(
                    Recommendation(
                        action="apply_intent_tls_extension_manipulation",
                        rationale=f"Обнаружена фильтрация доменов {sni_domains} - попробуйте манипуляции с TLS расширениями",
                        priority=0.8,
                        parameters={"intent_key": "tls_extension_manipulation", "extension_order": "random"}
                    )
                )
        
        return alternative_recommendations
    
    def _generate_recommendations(self, failure_cause: FailureCause, failure_details: Dict, strategy: Strategy) -> List[Recommendation]:
        """
        Базовая генерация рекомендаций на основе причины неудачи.
        Используется как основа для расширенной генерации рекомендаций.
        """
        recommendations = []
        
        if failure_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            recommendations.extend([
                Recommendation(
                    action="use_ttl_manipulation",
                    rationale="DPI инжектирует RST - попробуйте манипуляции с TTL",
                    priority=0.9,
                    parameters={"ttl": 1, "fooling": "badseq"}
                ),
                Recommendation(
                    action="try_disorder_attacks",
                    rationale="Атаки с нарушением порядка могут обойти RST инъекции",
                    priority=0.8,
                    parameters={"attack_type": "disorder"}
                )
            ])
        
        elif failure_cause == FailureCause.DPI_CONTENT_INSPECTION:
            recommendations.append(
                Recommendation(
                    action="use_content_obfuscation",
                    rationale="DPI анализирует содержимое - нужна обфускация",
                    priority=0.85,
                    parameters={"method": "fragmentation"}
                )
            )
        
        elif failure_cause == FailureCause.DPI_REASSEMBLES_FRAGMENTS:
            recommendations.extend([
                Recommendation(
                    action="try_advanced_fragmentation",
                    rationale="Простая фрагментация не работает - нужны продвинутые методы",
                    priority=0.8,
                    parameters={"method": "multisplit", "split_count": 10}
                ),
                Recommendation(
                    action="switch_to_timing_attacks",
                    rationale="Переключиться на атаки, основанные на времени",
                    priority=0.7
                )
            ])
        
        elif failure_cause == FailureCause.DPI_SNI_FILTERING:
            recommendations.append(
                Recommendation(
                    action="conceal_sni",
                    rationale="DPI фильтрует по SNI - нужно скрыть или обфусцировать SNI",
                    priority=0.9,
                    parameters={"method": "sni_split"}
                )
            )
        
        # Общие рекомендации для неизвестных причин
        if failure_cause == FailureCause.UNKNOWN:
            recommendations.append(
                Recommendation(
                    action="try_alternative_approaches",
                    rationale="Причина неудачи неясна - попробуйте альтернативные подходы",
                    priority=0.5,
                    parameters={"diversify": True}
                )
            )
        
        return recommendations
    
    def _calculate_confidence(self, packets: List[RawPacket], failure_cause: FailureCause) -> float:
        """
        Расчет уверенности в анализе.
        
        Args:
            packets: Список пакетов (RawPacket)
            failure_cause: Причина неудачи
            
        Returns:
            Уверенность в анализе (0.0 - 1.0)
        """
        from core.packet.raw_packet_engine import IPHeader, TCPHeader
        
        if not packets:
            return 0.1
        
        base_confidence = 0.5
        
        # Увеличиваем уверенность для четких индикаторов
        if failure_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            # Подсчитываем RST пакеты
            rst_count = 0
            for p in packets:
                if p.protocol == ProtocolType.TCP and len(p.data) >= 40:
                    ip_header = IPHeader.unpack(p.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
                    
                    if tcp_header.flags & TCPHeader.FLAG_RST:
                        rst_count += 1
            
            base_confidence += min(0.4, rst_count * 0.1)
        
        elif failure_cause == FailureCause.DPI_CONTENT_INSPECTION:
            base_confidence += 0.3
        
        # Учитываем количество пакетов
        packet_factor = min(0.2, len(packets) / 100)
        
        return min(0.95, base_confidence + packet_factor)
    
    def _generate_suggested_intents(self,
                                   failure_cause: FailureCause,
                                   failure_details: Dict[str, Any],
                                   recommendations: List[Recommendation]) -> List[str]:
        """
        Генерация списка рекомендуемых intent'ов на основе анализа неудачи.
        
        Args:
            failure_cause: Корневая причина неудачи
            failure_details: Детали анализа неудачи
            recommendations: Список рекомендаций
            
        Returns:
            Список уникальных intent ключей, отсортированных по приоритету
        """
        intent_keys = []
        
        # 1. Intent'ы из маппинга root_cause
        base_intents = self.cause_to_intents.get(failure_cause, [])
        intent_keys.extend(base_intents)
        
        # 2. Intent'ы из рекомендаций
        for rec in recommendations:
            intent_key = rec.parameters.get("intent_key")
            if intent_key and isinstance(intent_key, str):
                intent_keys.append(intent_key)
        
        # 3. Дополнительные intent'ы на основе деталей неудачи
        additional_intents = self._extract_intents_from_details(failure_details)
        intent_keys.extend(additional_intents)
        
        # Фильтруем None значения и удаляем дубликаты, сохраняя порядок
        filtered_intents = [intent for intent in intent_keys if intent is not None and isinstance(intent, str)]
        unique_intents = list(dict.fromkeys(filtered_intents))
        
        # Ограничиваем до 5 intent'ов
        result = unique_intents[:5]
        
        LOG.info(f"Сгенерировано {len(result)} suggested_intents для {failure_cause.value}: {result}")
        
        return result
    
    def _extract_intents_from_details(self, failure_details: Dict[str, Any]) -> List[str]:
        """
        Извлечение дополнительных intent'ов из деталей неудачи.
        
        Args:
            failure_details: Детали анализа неудачи
            
        Returns:
            Список дополнительных intent ключей
        """
        intents = []
        
        # Анализ RST характеристик
        if failure_details.get("rst_injection_detected") or failure_details.get("rst_count", 0) > 0:
            intents.append("short_ttl_decoy")
            
            rst_timing = failure_details.get("rst_timing_ms", 0)
            if rst_timing and rst_timing < 10:  # Очень быстрый RST
                intents.append("timing_manipulation")
        
        # Анализ фрагментации
        if (failure_details.get("fragments_reassembled") or 
            failure_details.get("fragmented_packets", 0) > 0):
            intents.append("packet_reordering")
            intents.append("sequence_overlap")
        
        # Анализ SNI
        if (failure_details.get("sni_detected") or 
            failure_details.get("sni_domains")):
            intents.append("conceal_sni")
            intents.append("fake_sni")
        
        # Анализ TLS
        if (failure_details.get("tls_handshake_blocked") or
            failure_details.get("client_hello_count", 0) > 0):
            intents.append("tls_extension_manipulation")
            intents.append("record_fragmentation")
        
        # Анализ технических деталей
        technical_details = failure_details.get("technical_details", {})
        
        # RST injection indicators
        injection_indicators = technical_details.get("injection_indicators", [])
        if "multiple_rst_sources" in injection_indicators:
            intents.append("timing_manipulation")
        if "suspicious_ttl" in injection_indicators:
            intents.append("short_ttl_decoy")
        if "invalid_sequence_numbers" in injection_indicators:
            intents.append("sequence_overlap")
        
        # Fragmentation reassembly indicators
        reassembly_indicators = technical_details.get("reassembly_indicators", [])
        if "tcp_reassembly_blocked" in reassembly_indicators:
            intents.append("payload_obfuscation")
        if "ordered_fragments_blocked" in reassembly_indicators:
            intents.append("packet_reordering")
        
        # SNI blocking indicators
        blocking_indicators = technical_details.get("blocking_indicators", [])
        if "rst_after_client_hello" in blocking_indicators:
            intents.append("conceal_sni")
        if "no_server_hello_after_sni" in blocking_indicators:
            intents.append("fake_sni")
        
        # Фильтруем None значения перед возвратом
        return [intent for intent in intents if intent is not None and isinstance(intent, str)]
    
    def _create_error_report(self, strategy: Strategy, cause: FailureCause, error_msg: str) -> FailureReport:
        """Создание отчета об ошибке."""
        # Генерируем базовые intent'ы даже для ошибок
        suggested_intents = self.cause_to_intents.get(cause, [])[:3]  # Максимум 3 для ошибок
        
        return FailureReport(
            strategy_id=strategy.id or strategy.name,
            domain="unknown",
            analyzed_at=datetime.now(),
            root_cause=cause,
            root_cause_details=error_msg,
            failure_details={"error": error_msg},
            recommendations=[],
            suggested_intents=suggested_intents,
            confidence=0.0
        )
    
    
            
        
    def _deduplicate_recommendations(self, recommendations: List[Recommendation]) -> List[Recommendation]:
        """Удаление дубликатов рекомендаций."""
        
        seen_actions = set()
        unique_recommendations = []
        
        for rec in recommendations:
            if rec.action not in seen_actions:
                seen_actions.add(rec.action)
                unique_recommendations.append(rec)
            else:
                # Если действие уже есть, обновляем приоритет если новый выше
                for existing_rec in unique_recommendations:
                    if existing_rec.action == rec.action and rec.priority > existing_rec.priority:
                        existing_rec.priority = rec.priority
                        existing_rec.rationale += f" | {rec.rationale}"
                        break
        
        return unique_recommendations

    async def _cleanup_pcap_file(self, pcap_file: str):
        """Автоочистка временного PCAP файла."""
        try:
            if os.path.exists(pcap_file) and str(self.temp_dir) in pcap_file:
                os.remove(pcap_file)
                LOG.debug(f"Удален временный PCAP файл: {pcap_file}")
        except Exception as e:
            LOG.warning(f"Не удалось удалить временный файл {pcap_file}: {e}")


# Вспомогательные функции для интеграции
def create_strategy_failure_analyzer(temp_dir: str = "temp_pcap") -> StrategyFailureAnalyzer:
    """Фабричная функция для создания анализатора."""
    return StrategyFailureAnalyzer(temp_dir=temp_dir)


async def analyze_strategy_failure(pcap_file: str, strategy_name: str, attack_name: str = None) -> FailureReport:
    """
    Удобная функция для быстрого анализа неудачи стратегии.
    
    Args:
        pcap_file: Путь к PCAP файлу
        strategy_name: Имя стратегии
        attack_name: Имя атаки (опционально)
    
    Returns:
        FailureReport с результатами анализа
    """
    analyzer = StrategyFailureAnalyzer()
    strategy = Strategy(
        name=strategy_name,
        attack_name=attack_name or strategy_name,
        id=strategy_name
    )
    
    return await analyzer.analyze_pcap(pcap_file, strategy)