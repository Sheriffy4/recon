"""
BlockingPatternDetector - система анализа паттернов блокировки DPI.

Этот модуль реализует:
- Выявление типов DPI блокировок с анализом timing и источника пакетов
- Детекцию RST-инъекций с анализом характеристик пакетов
- Анализатор TLS handshake с выявлением точки обрыва соединения
- Детектор DNS манипуляций и подмены ответов
- Анализ HTTP/HTTPS редиректов и блокировок по содержимому
- Систему классификации блокировок по уровням агрессивности DPI

Requirements: FR-15.3, FR-15.4
"""

import asyncio
import logging
import time
import statistics
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import re

# Попытка импорта Scapy с fallback
try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw, TLS, UDP, DNS, ICMP, get_if_list, get_if_addr

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - BlockingPatternDetector will run in limited mode")

# Интеграция с существующими модулями
try:
    from .intelligent_pcap_analyzer import BlockingType, DPIBehavior, PacketAnalysis, FlowAnalysis
    from ..strategy_failure_analyzer import FailureCause

    ANALYZER_COMPONENTS_AVAILABLE = True
except ImportError:
    ANALYZER_COMPONENTS_AVAILABLE = False
    logging.warning("Analyzer components not available")

LOG = logging.getLogger("BlockingPatternDetector")


class DPIAggressivenessLevel(Enum):
    """Уровни агрессивности DPI системы."""

    PASSIVE = "passive"  # Только мониторинг
    LOW = "low"  # Редкие блокировки
    MODERATE = "moderate"  # Селективные блокировки
    HIGH = "high"  # Активные блокировки
    AGGRESSIVE = "aggressive"  # Массивные блокировки
    EXTREME = "extreme"  # Тотальные блокировки


class RST_InjectionType(Enum):
    """Типы RST инъекций."""

    BIDIRECTIONAL = "bidirectional"  # RST в обе стороны
    CLIENT_SIDE = "client_side"  # RST только клиенту
    SERVER_SIDE = "server_side"  # RST только серверу
    DELAYED = "delayed"  # RST с задержкой
    IMMEDIATE = "immediate"  # Мгновенный RST
    SPOOFED = "spoofed"  # RST с подменой адреса


class TLSHandshakeStage(Enum):
    """Стадии TLS handshake."""

    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    CERTIFICATE = "certificate"
    SERVER_HELLO_DONE = "server_hello_done"
    CLIENT_KEY_EXCHANGE = "client_key_exchange"
    CHANGE_CIPHER_SPEC = "change_cipher_spec"
    FINISHED = "finished"
    APPLICATION_DATA = "application_data"


class DNSManipulationType(Enum):
    """Типы DNS манипуляций."""

    RESPONSE_POISONING = "response_poisoning"  # Подмена ответа
    REQUEST_BLOCKING = "request_blocking"  # Блокировка запроса
    REDIRECT_INJECTION = "redirect_injection"  # Инъекция редиректа
    TIMEOUT_ATTACK = "timeout_attack"  # Таймаут запроса
    NXDOMAIN_INJECTION = "nxdomain_injection"  # Инъекция NXDOMAIN


@dataclass
class RSTInjectionAnalysis:
    """Результат анализа RST инъекции."""

    detected: bool
    injection_type: RST_InjectionType
    timing_ms: float
    source_analysis: Dict[str, Any] = field(default_factory=dict)

    # Характеристики RST пакета
    rst_ttl: Optional[int] = None
    rst_window: Optional[int] = None
    rst_sequence: Optional[int] = None
    rst_acknowledgment: Optional[int] = None

    # Анализ источника
    likely_spoofed: bool = False
    hop_distance_estimate: Optional[int] = None
    timing_anomalies: List[str] = field(default_factory=list)

    # Контекст
    packets_before_rst: int = 0
    payload_trigger: Optional[str] = None
    confidence: float = 0.0


@dataclass
class TLSHandshakeAnalysis:
    """Результат анализа TLS handshake."""

    completed: bool
    failure_stage: Optional[TLSHandshakeStage] = None
    failure_reason: str = ""

    # Детали handshake
    client_hello_sni: Optional[str] = None
    server_certificate_cn: Optional[str] = None
    cipher_suites: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)

    # Анализ обрыва
    last_successful_stage: Optional[TLSHandshakeStage] = None
    interruption_timing_ms: Optional[float] = None
    interruption_method: str = ""  # "rst", "timeout", "alert", "drop"

    # Подозрительные характеристики
    sni_related_failure: bool = False
    certificate_related_failure: bool = False
    cipher_related_failure: bool = False

    confidence: float = 0.0


@dataclass
class DNSManipulationAnalysis:
    """Результат анализа DNS манипуляций."""

    detected: bool
    manipulation_type: DNSManipulationType

    # Детали запроса/ответа
    query_domain: str = ""
    expected_response: Optional[str] = None
    actual_response: Optional[str] = None
    response_timing_ms: float = 0.0

    # Анализ подмены
    response_source_ip: Optional[str] = None
    legitimate_server_ip: Optional[str] = None
    response_ttl_analysis: Dict[str, Any] = field(default_factory=dict)

    # Признаки манипуляции
    suspicious_response_timing: bool = False
    suspicious_response_content: bool = False
    suspicious_response_source: bool = False

    confidence: float = 0.0


@dataclass
class HTTPRedirectAnalysis:
    """Результат анализа HTTP редиректов."""

    detected: bool
    redirect_type: str = ""  # "301", "302", "307", "meta_refresh", "javascript"

    # Детали редиректа
    original_url: str = ""
    redirect_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)

    # Анализ подозрительности
    suspicious_redirect: bool = False
    block_page_detected: bool = False
    government_block_page: bool = False
    isp_block_page: bool = False

    # Характеристики блокировки
    block_page_content: str = ""
    block_page_language: str = ""
    block_reason: str = ""

    confidence: float = 0.0


@dataclass
class BlockingPatternAnalysis:
    """Комплексный результат анализа паттернов блокировки."""

    domain: str
    analysis_id: str
    analyzed_at: datetime

    # Основные результаты
    primary_blocking_type: BlockingType
    dpi_aggressiveness: DPIAggressivenessLevel
    blocking_confidence: float

    # Детальные анализы
    rst_analysis: Optional[RSTInjectionAnalysis] = None
    tls_analysis: Optional[TLSHandshakeAnalysis] = None
    dns_analysis: Optional[DNSManipulationAnalysis] = None
    http_analysis: Optional[HTTPRedirectAnalysis] = None

    # Временные характеристики
    blocking_timing_ms: Optional[float] = None
    consistency_across_attempts: float = 0.0

    # DPI характеристики
    dpi_behavioral_signature: Dict[str, Any] = field(default_factory=dict)
    evasion_recommendations: List[str] = field(default_factory=list)

    # Метаданные
    packets_analyzed: int = 0
    flows_analyzed: int = 0
    analysis_duration_ms: float = 0.0


class BlockingPatternDetector:
    """
    Система анализа паттернов блокировки DPI.

    Выявляет различные типы блокировок и анализирует их характеристики
    для определения оптимальных стратегий обхода.
    """

    def __init__(
        self,
        enable_deep_analysis: bool = True,
        timing_threshold_ms: float = 100.0,
        confidence_threshold: float = 0.7,
    ):
        self.enable_deep_analysis = enable_deep_analysis
        self.timing_threshold_ms = timing_threshold_ms
        self.confidence_threshold = confidence_threshold

        # Кэш анализов
        self.analysis_cache: Dict[str, BlockingPatternAnalysis] = {}

        # Паттерны блокировок
        self._load_blocking_patterns()

        # Статистика
        self.stats = {
            "analyses_performed": 0,
            "rst_injections_detected": 0,
            "tls_failures_analyzed": 0,
            "dns_manipulations_detected": 0,
            "http_redirects_analyzed": 0,
        }

        LOG.info("BlockingPatternDetector initialized")

    async def analyze_blocking_patterns(
        self, domain: str, pcap_file: str, flow_analyses: Optional[List[FlowAnalysis]] = None
    ) -> BlockingPatternAnalysis:
        """
        Комплексный анализ паттернов блокировки для домена.

        Args:
            domain: Целевой домен
            pcap_file: Путь к PCAP файлу
            flow_analyses: Предварительные анализы потоков

        Returns:
            Результат анализа паттернов блокировки
        """
        analysis_id = f"{domain}_{int(time.time())}"

        # Проверяем кэш
        cache_key = None
        try:
            p = Path(pcap_file)
            if p.exists():
                cache_key = f"{domain}_{p.stat().st_mtime}"
        except Exception as e:
            LOG.debug("Cache key calculation failed for %s: %s", pcap_file, e)

        if cache_key and cache_key in self.analysis_cache:
            LOG.debug("Using cached analysis for %s", domain)
            return self.analysis_cache[cache_key]

        LOG.info(f"Starting blocking pattern analysis for {domain}")
        start_time = time.time()

        analysis = BlockingPatternAnalysis(
            domain=domain,
            analysis_id=analysis_id,
            analyzed_at=datetime.now(),
            primary_blocking_type=BlockingType.UNKNOWN,
            dpi_aggressiveness=DPIAggressivenessLevel.PASSIVE,
            blocking_confidence=0.0,
        )

        try:
            if not SCAPY_AVAILABLE:
                LOG.warning("Scapy not available - limited analysis")
                return analysis

            # Загрузка и предварительный анализ PCAP
            packets = rdpcap(pcap_file)
            analysis.packets_analyzed = len(packets)

            # Группировка пакетов по потокам
            flows = self._group_packets_by_flow(packets)
            analysis.flows_analyzed = len(flows)

            # Анализ RST инъекций
            analysis.rst_analysis = await self._analyze_rst_injections(domain, flows, packets)

            # Анализ TLS handshake
            analysis.tls_analysis = await self._analyze_tls_handshake(domain, flows, packets)

            # Анализ DNS манипуляций
            analysis.dns_analysis = await self._analyze_dns_manipulations(domain, flows, packets)

            # Анализ HTTP редиректов
            analysis.http_analysis = await self._analyze_http_redirects(domain, flows, packets)

            # Определение основного типа блокировки
            analysis.primary_blocking_type = self._determine_primary_blocking_type(analysis)

            # Оценка агрессивности DPI
            analysis.dpi_aggressiveness = self._assess_dpi_aggressiveness(analysis)

            # Расчет общей уверенности
            analysis.blocking_confidence = self._calculate_blocking_confidence(analysis)

            # Генерация рекомендаций по обходу
            analysis.evasion_recommendations = await self._generate_evasion_recommendations(
                analysis
            )

            # Создание поведенческой сигнатуры DPI
            analysis.dpi_behavioral_signature = self._create_dpi_signature(analysis)

            # Завершение анализа
            analysis.analysis_duration_ms = (time.time() - start_time) * 1000

            # Кэширование результата
            if cache_key:
                self.analysis_cache[cache_key] = analysis

            # Обновление статистики
            self.stats["analyses_performed"] += 1
            if analysis.rst_analysis and analysis.rst_analysis.detected:
                self.stats["rst_injections_detected"] += 1
            if analysis.tls_analysis and not analysis.tls_analysis.completed:
                self.stats["tls_failures_analyzed"] += 1
            if analysis.dns_analysis and analysis.dns_analysis.detected:
                self.stats["dns_manipulations_detected"] += 1
            if analysis.http_analysis and analysis.http_analysis.detected:
                self.stats["http_redirects_analyzed"] += 1

            LOG.info(
                f"Blocking pattern analysis completed for {domain} in {analysis.analysis_duration_ms:.1f}ms"
            )

        except Exception as e:
            LOG.error(f"Blocking pattern analysis failed for {domain}: {e}")
            raise

        return analysis

    async def detect_rst_injection_patterns(
        self, domain: str, packets: List[Any]
    ) -> RSTInjectionAnalysis:
        """
        Детекция RST-инъекций с анализом timing и источника пакетов.

        Args:
            domain: Целевой домен
            packets: Список пакетов для анализа

        Returns:
            Результат анализа RST инъекций
        """
        analysis = RSTInjectionAnalysis(
            detected=False, injection_type=RST_InjectionType.IMMEDIATE, timing_ms=0.0
        )

        if not SCAPY_AVAILABLE:
            return analysis

        try:
            rst_packets = [p for p in packets if TCP in p and p[TCP].flags.R]

            if not rst_packets:
                return analysis

            analysis.detected = True

            # Анализ каждого RST пакета
            for rst_packet in rst_packets:
                # Анализ TTL
                if IP in rst_packet:
                    analysis.rst_ttl = rst_packet[IP].ttl

                    # Анализ подозрительного TTL
                    if analysis.rst_ttl < 64:  # Подозрительно низкий TTL
                        analysis.likely_spoofed = True
                        analysis.timing_anomalies.append("suspicious_low_ttl")

                # Анализ TCP характеристик
                tcp_layer = rst_packet[TCP]
                analysis.rst_window = tcp_layer.window
                analysis.rst_sequence = tcp_layer.seq
                analysis.rst_acknowledgment = tcp_layer.ack

                # Анализ timing
                rst_time = float(rst_packet.time)

                # Поиск предшествующих пакетов
                preceding_packets = [
                    p
                    for p in packets
                    if float(p.time) < rst_time and TCP in p and not p[TCP].flags.R
                ]

                if preceding_packets:
                    last_packet_time = max(float(p.time) for p in preceding_packets)
                    analysis.timing_ms = (rst_time - last_packet_time) * 1000
                    analysis.packets_before_rst = len(preceding_packets)

                    # Анализ подозрительно быстрого RST
                    if analysis.timing_ms < 1.0:  # Менее 1мс - подозрительно
                        analysis.timing_anomalies.append("suspiciously_fast_rst")
                        analysis.likely_spoofed = True

                # Анализ payload триггера
                if preceding_packets:
                    last_packet = max(preceding_packets, key=lambda p: float(p.time))
                    if Raw in last_packet:
                        payload = bytes(last_packet[Raw])
                        if b"Host:" in payload or b"SNI" in payload:
                            analysis.payload_trigger = "sni_or_host_header"

            # Определение типа инъекции
            analysis.injection_type = self._classify_rst_injection_type(rst_packets, packets)

            # Расчет уверенности
            confidence_factors = []
            if analysis.likely_spoofed:
                confidence_factors.append(0.8)
            if analysis.timing_anomalies:
                confidence_factors.append(0.7)
            if analysis.payload_trigger:
                confidence_factors.append(0.9)

            analysis.confidence = statistics.mean(confidence_factors) if confidence_factors else 0.5

        except Exception as e:
            LOG.error(f"RST injection analysis failed for {domain}: {e}")

        return analysis

    async def analyze_tls_handshake_interruption(
        self, domain: str, packets: List[Any]
    ) -> TLSHandshakeAnalysis:
        """
        Анализ TLS handshake с выявлением точки обрыва соединения.

        Args:
            domain: Целевой домен
            packets: Список пакетов для анализа

        Returns:
            Результат анализа TLS handshake
        """
        analysis = TLSHandshakeAnalysis(completed=False)

        if not SCAPY_AVAILABLE:
            return analysis

        try:
            # Фильтрация TLS пакетов
            tls_packets = [p for p in packets if TLS in p]

            if not tls_packets:
                return analysis

            # Анализ стадий handshake
            handshake_stages = {}

            for packet in tls_packets:
                tls_layer = packet[TLS]
                packet_time = float(packet.time)

                # Анализ Client Hello
                if hasattr(tls_layer, "msg") and len(tls_layer.msg) > 0:
                    msg = tls_layer.msg[0]

                    if hasattr(msg, "msgtype"):
                        if msg.msgtype == 1:  # Client Hello
                            handshake_stages[TLSHandshakeStage.CLIENT_HELLO] = packet_time

                            # Извлечение SNI
                            if hasattr(msg, "ext") and msg.ext:
                                for ext in msg.ext:
                                    if hasattr(ext, "servernames") and ext.servernames:
                                        analysis.client_hello_sni = ext.servernames[
                                            0
                                        ].servername.decode()

                        elif msg.msgtype == 2:  # Server Hello
                            handshake_stages[TLSHandshakeStage.SERVER_HELLO] = packet_time

                        elif msg.msgtype == 11:  # Certificate
                            handshake_stages[TLSHandshakeStage.CERTIFICATE] = packet_time

                        elif msg.msgtype == 14:  # Server Hello Done
                            handshake_stages[TLSHandshakeStage.SERVER_HELLO_DONE] = packet_time

                        elif msg.msgtype == 16:  # Client Key Exchange
                            handshake_stages[TLSHandshakeStage.CLIENT_KEY_EXCHANGE] = packet_time

            # Определение последней успешной стадии
            completed_stages = list(handshake_stages.keys())
            if completed_stages:
                analysis.last_successful_stage = max(
                    completed_stages, key=lambda s: handshake_stages[s]
                )

            # Проверка завершенности handshake
            required_stages = [
                TLSHandshakeStage.CLIENT_HELLO,
                TLSHandshakeStage.SERVER_HELLO,
                TLSHandshakeStage.CERTIFICATE,
                TLSHandshakeStage.SERVER_HELLO_DONE,
            ]

            analysis.completed = all(stage in handshake_stages for stage in required_stages)

            if not analysis.completed:
                # Определение стадии сбоя
                for stage in required_stages:
                    if stage not in handshake_stages:
                        analysis.failure_stage = stage
                        break

                # Анализ причины сбоя
                if analysis.failure_stage == TLSHandshakeStage.SERVER_HELLO:
                    if (
                        analysis.client_hello_sni
                        and domain.lower() in analysis.client_hello_sni.lower()
                    ):
                        analysis.sni_related_failure = True
                        analysis.failure_reason = "SNI-based blocking detected"

                # Анализ метода прерывания
                rst_after_client_hello = any(
                    TCP in p
                    and p[TCP].flags.R
                    and float(p.time) > handshake_stages.get(TLSHandshakeStage.CLIENT_HELLO, 0)
                    for p in packets
                )

                if rst_after_client_hello:
                    analysis.interruption_method = "rst"
                    if TLSHandshakeStage.CLIENT_HELLO in handshake_stages:
                        analysis.interruption_timing_ms = (
                            min(float(p.time) for p in packets if TCP in p and p[TCP].flags.R)
                            - handshake_stages[TLSHandshakeStage.CLIENT_HELLO]
                        ) * 1000
                else:
                    analysis.interruption_method = "timeout"

            # Расчет уверенности
            confidence_factors = []
            if analysis.sni_related_failure:
                confidence_factors.append(0.9)
            if analysis.interruption_method == "rst":
                confidence_factors.append(0.8)
            if analysis.last_successful_stage:
                confidence_factors.append(0.7)

            analysis.confidence = statistics.mean(confidence_factors) if confidence_factors else 0.3

        except Exception as e:
            LOG.error(f"TLS handshake analysis failed for {domain}: {e}")

        return analysis

    async def detect_dns_manipulations(
        self, domain: str, packets: List[Any]
    ) -> DNSManipulationAnalysis:
        """
        Детектор DNS манипуляций и подмены ответов.

        Args:
            domain: Целевой домен
            packets: Список пакетов для анализа

        Returns:
            Результат анализа DNS манипуляций
        """
        analysis = DNSManipulationAnalysis(
            detected=False,
            manipulation_type=DNSManipulationType.RESPONSE_POISONING,
            query_domain=domain,
        )

        if not SCAPY_AVAILABLE:
            return analysis

        try:
            # Фильтрация DNS пакетов
            dns_packets = [p for p in packets if DNS in p]

            if not dns_packets:
                return analysis

            # Группировка запросов и ответов
            dns_queries = [p for p in dns_packets if p[DNS].qr == 0]  # Запросы
            dns_responses = [p for p in dns_packets if p[DNS].qr == 1]  # Ответы

            # Анализ каждого запроса
            for query in dns_queries:
                query_time = float(query.time)
                query_id = query[DNS].id

                # Поиск соответствующих ответов
                matching_responses = [
                    r for r in dns_responses if r[DNS].id == query_id and float(r.time) > query_time
                ]

                if not matching_responses:
                    # Нет ответа - возможная блокировка
                    analysis.detected = True
                    analysis.manipulation_type = DNSManipulationType.REQUEST_BLOCKING
                    continue

                # Анализ времени ответа
                response = min(matching_responses, key=lambda r: float(r.time))
                response_time_ms = (float(response.time) - query_time) * 1000
                analysis.response_timing_ms = response_time_ms

                # Анализ подозрительно быстрого ответа
                if response_time_ms < 1.0:  # Менее 1мс - подозрительно
                    analysis.suspicious_response_timing = True
                    analysis.detected = True

                # Анализ источника ответа
                if IP in response:
                    analysis.response_source_ip = response[IP].src

                    # Проверка TTL ответа
                    response_ttl = response[IP].ttl
                    if response_ttl < 64:  # Подозрительно низкий TTL
                        analysis.suspicious_response_source = True
                        analysis.detected = True

                # Анализ содержимого ответа
                if response[DNS].ancount > 0:
                    for i in range(response[DNS].ancount):
                        answer = response[DNS].an[i]
                        if hasattr(answer, "rdata"):
                            analysis.actual_response = str(answer.rdata)

                            # Проверка на блокировочные IP
                            if self._is_blocking_ip(analysis.actual_response):
                                analysis.suspicious_response_content = True
                                analysis.detected = True
                                analysis.manipulation_type = DNSManipulationType.REDIRECT_INJECTION

                # Анализ NXDOMAIN ответов
                if response[DNS].rcode == 3:  # NXDOMAIN
                    # Проверка на подозрительный NXDOMAIN
                    if domain in ["google.com", "facebook.com", "twitter.com"]:  # Известные домены
                        analysis.detected = True
                        analysis.manipulation_type = DNSManipulationType.NXDOMAIN_INJECTION

            # Расчет уверенности
            confidence_factors = []
            if analysis.suspicious_response_timing:
                confidence_factors.append(0.8)
            if analysis.suspicious_response_source:
                confidence_factors.append(0.9)
            if analysis.suspicious_response_content:
                confidence_factors.append(0.95)

            analysis.confidence = statistics.mean(confidence_factors) if confidence_factors else 0.0

        except Exception as e:
            LOG.error(f"DNS manipulation analysis failed for {domain}: {e}")

        return analysis

    async def analyze_http_redirects(self, domain: str, packets: List[Any]) -> HTTPRedirectAnalysis:
        """
        Анализ HTTP/HTTPS редиректов и блокировок по содержимому.

        Args:
            domain: Целевой домен
            packets: Список пакетов для анализа

        Returns:
            Результат анализа HTTP редиректов
        """
        analysis = HTTPRedirectAnalysis(detected=False, original_url=f"https://{domain}")

        if not SCAPY_AVAILABLE:
            return analysis

        try:
            # Поиск HTTP пакетов с содержимым
            http_packets = []
            for packet in packets:
                if TCP in packet and Raw in packet:
                    payload = bytes(packet[Raw])
                    if b"HTTP/" in payload:
                        http_packets.append(packet)

            # Анализ HTTP ответов
            for packet in http_packets:
                payload = bytes(packet[Raw]).decode("utf-8", errors="ignore")

                # Поиск редиректов
                if "HTTP/1." in payload and (
                    "301" in payload or "302" in payload or "307" in payload
                ):
                    analysis.detected = True

                    # Извлечение кода ответа
                    if "301" in payload:
                        analysis.redirect_type = "301"
                    elif "302" in payload:
                        analysis.redirect_type = "302"
                    elif "307" in payload:
                        analysis.redirect_type = "307"

                    # Поиск Location заголовка
                    location_match = re.search(r"Location:\s*([^\r\n]+)", payload, re.IGNORECASE)
                    if location_match:
                        analysis.redirect_url = location_match.group(1).strip()
                        analysis.redirect_chain.append(analysis.redirect_url)

                # Поиск блокировочных страниц
                block_indicators = [
                    "access denied",
                    "blocked",
                    "restricted",
                    "forbidden",
                    "заблокирован",
                    "доступ запрещен",
                    "ограничен доступ",
                    "roskomnadzor",
                    "rkn.gov.ru",
                    "blocked by",
                    "access restricted",
                ]

                payload_lower = payload.lower()
                for indicator in block_indicators:
                    if indicator in payload_lower:
                        analysis.detected = True
                        analysis.block_page_detected = True
                        analysis.suspicious_redirect = True

                        # Определение типа блокировки
                        if "roskomnadzor" in payload_lower or "rkn.gov.ru" in payload_lower:
                            analysis.government_block_page = True
                        elif any(
                            isp in payload_lower
                            for isp in ["beeline", "mts", "megafon", "rostelecom"]
                        ):
                            analysis.isp_block_page = True

                        # Сохранение содержимого блокировочной страницы
                        analysis.block_page_content = payload[:1000]  # Первые 1000 символов
                        break

                # Поиск JavaScript редиректов
                if "<script" in payload_lower and (
                    "location.href" in payload_lower or "window.location" in payload_lower
                ):
                    analysis.detected = True
                    analysis.redirect_type = "javascript"

                # Поиск meta refresh редиректов
                meta_refresh_match = re.search(
                    r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']+)["\']',
                    payload,
                    re.IGNORECASE,
                )
                if meta_refresh_match:
                    analysis.detected = True
                    analysis.redirect_type = "meta_refresh"

                    # Извлечение URL из meta refresh
                    content = meta_refresh_match.group(1)
                    url_match = re.search(r"url=([^;]+)", content, re.IGNORECASE)
                    if url_match:
                        analysis.redirect_url = url_match.group(1).strip()

            # Расчет уверенности
            confidence_factors = []
            if analysis.block_page_detected:
                confidence_factors.append(0.95)
            if analysis.government_block_page:
                confidence_factors.append(0.99)
            if analysis.redirect_type in ["301", "302"]:
                confidence_factors.append(0.8)

            analysis.confidence = statistics.mean(confidence_factors) if confidence_factors else 0.0

        except Exception as e:
            LOG.error(f"HTTP redirect analysis failed for {domain}: {e}")

        return analysis

    def classify_dpi_aggressiveness(
        self, analysis: BlockingPatternAnalysis
    ) -> DPIAggressivenessLevel:
        """
        Классификация блокировок по уровням агрессивности DPI.

        Args:
            analysis: Результат анализа паттернов блокировки

        Returns:
            Уровень агрессивности DPI системы
        """
        aggressiveness_score = 0.0

        # Анализ RST инъекций
        if analysis.rst_analysis and analysis.rst_analysis.detected:
            aggressiveness_score += 0.3
            if analysis.rst_analysis.likely_spoofed:
                aggressiveness_score += 0.2
            if analysis.rst_analysis.timing_ms < 10.0:  # Очень быстрый RST
                aggressiveness_score += 0.2

        # Анализ TLS блокировок
        if analysis.tls_analysis and not analysis.tls_analysis.completed:
            aggressiveness_score += 0.2
            if analysis.tls_analysis.sni_related_failure:
                aggressiveness_score += 0.3

        # Анализ DNS манипуляций
        if analysis.dns_analysis and analysis.dns_analysis.detected:
            aggressiveness_score += 0.4
            if analysis.dns_analysis.manipulation_type == DNSManipulationType.RESPONSE_POISONING:
                aggressiveness_score += 0.3

        # Анализ HTTP блокировок
        if analysis.http_analysis and analysis.http_analysis.detected:
            aggressiveness_score += 0.2
            if analysis.http_analysis.government_block_page:
                aggressiveness_score += 0.4

        # Классификация по уровням
        if aggressiveness_score >= 1.0:
            return DPIAggressivenessLevel.EXTREME
        elif aggressiveness_score >= 0.8:
            return DPIAggressivenessLevel.AGGRESSIVE
        elif aggressiveness_score >= 0.6:
            return DPIAggressivenessLevel.HIGH
        elif aggressiveness_score >= 0.4:
            return DPIAggressivenessLevel.MODERATE
        elif aggressiveness_score >= 0.2:
            return DPIAggressivenessLevel.LOW
        else:
            return DPIAggressivenessLevel.PASSIVE

    # Приватные методы для внутренней логики

    def _load_blocking_patterns(self):
        """Загрузка известных паттернов блокировок."""
        self.blocking_patterns = {
            "government_block_ips": ["127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1"],
            "common_block_pages": ["access denied", "blocked", "restricted", "forbidden"],
            "suspicious_ttl_ranges": [(1, 32), (250, 255)],  # Очень низкий TTL  # Очень высокий TTL
        }

    def _group_packets_by_flow(self, packets: List[Any]) -> Dict[str, List[Any]]:
        """Группировка пакетов по TCP потокам."""
        flows = {}

        for packet in packets:
            if TCP in packet and IP in packet:
                # Создание идентификатора потока
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                # Нормализация потока (меньший IP:порт первым)
                if (src_ip, src_port) < (dst_ip, dst_port):
                    flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                else:
                    flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

                if flow_id not in flows:
                    flows[flow_id] = []
                flows[flow_id].append(packet)

        return flows

    async def _analyze_rst_injections(
        self, domain: str, flows: Dict[str, List[Any]], packets: List[Any]
    ) -> RSTInjectionAnalysis:
        """Анализ RST инъекций."""
        return await self.detect_rst_injection_patterns(domain, packets)

    async def _analyze_tls_handshake(
        self, domain: str, flows: Dict[str, List[Any]], packets: List[Any]
    ) -> TLSHandshakeAnalysis:
        """Анализ TLS handshake."""
        return await self.analyze_tls_handshake_interruption(domain, packets)

    async def _analyze_dns_manipulations(
        self, domain: str, flows: Dict[str, List[Any]], packets: List[Any]
    ) -> DNSManipulationAnalysis:
        """Анализ DNS манипуляций."""
        return await self.detect_dns_manipulations(domain, packets)

    async def _analyze_http_redirects(
        self, domain: str, flows: Dict[str, List[Any]], packets: List[Any]
    ) -> HTTPRedirectAnalysis:
        """Анализ HTTP редиректов."""
        return await self.analyze_http_redirects(domain, packets)

    def _determine_primary_blocking_type(self, analysis: BlockingPatternAnalysis) -> BlockingType:
        """Определение основного типа блокировки."""
        # Приоритизация типов блокировки
        if analysis.dns_analysis and analysis.dns_analysis.detected:
            return BlockingType.DNS_POISONING

        if analysis.rst_analysis and analysis.rst_analysis.detected:
            return BlockingType.RST_INJECTION

        if analysis.tls_analysis and not analysis.tls_analysis.completed:
            if analysis.tls_analysis.sni_related_failure:
                return BlockingType.SNI_FILTERING
            else:
                return BlockingType.TLS_HANDSHAKE_BLOCKING

        if analysis.http_analysis and analysis.http_analysis.detected:
            return BlockingType.CONTENT_FILTERING

        return BlockingType.UNKNOWN

    def _assess_dpi_aggressiveness(
        self, analysis: BlockingPatternAnalysis
    ) -> DPIAggressivenessLevel:
        """Оценка агрессивности DPI."""
        return self.classify_dpi_aggressiveness(analysis)

    def _calculate_blocking_confidence(self, analysis: BlockingPatternAnalysis) -> float:
        """Расчет общей уверенности в блокировке."""
        confidences = []

        if analysis.rst_analysis:
            confidences.append(analysis.rst_analysis.confidence)

        if analysis.tls_analysis:
            confidences.append(analysis.tls_analysis.confidence)

        if analysis.dns_analysis:
            confidences.append(analysis.dns_analysis.confidence)

        if analysis.http_analysis:
            confidences.append(analysis.http_analysis.confidence)

        return statistics.mean(confidences) if confidences else 0.0

    async def _generate_evasion_recommendations(
        self, analysis: BlockingPatternAnalysis
    ) -> List[str]:
        """Генерация рекомендаций по обходу."""
        recommendations = []

        if analysis.primary_blocking_type == BlockingType.RST_INJECTION:
            recommendations.extend(
                [
                    "Use TTL-based evasion techniques",
                    "Try packet fragmentation",
                    "Consider out-of-order packet delivery",
                ]
            )

        if analysis.primary_blocking_type == BlockingType.SNI_FILTERING:
            recommendations.extend(
                [
                    "Use SNI obfuscation techniques",
                    "Try domain fronting",
                    "Consider TLS record fragmentation",
                ]
            )

        if analysis.primary_blocking_type == BlockingType.DNS_POISONING:
            recommendations.extend(
                [
                    "Use alternative DNS servers",
                    "Try DNS over HTTPS (DoH)",
                    "Consider DNS over TLS (DoT)",
                ]
            )

        if analysis.dpi_aggressiveness in [
            DPIAggressivenessLevel.AGGRESSIVE,
            DPIAggressivenessLevel.EXTREME,
        ]:
            recommendations.extend(
                [
                    "Use multiple evasion techniques simultaneously",
                    "Consider tunneling protocols",
                    "Try randomized timing patterns",
                ]
            )

        return recommendations

    def _create_dpi_signature(self, analysis: BlockingPatternAnalysis) -> Dict[str, Any]:
        """Создание поведенческой сигнатуры DPI."""
        signature = {
            "primary_blocking_method": analysis.primary_blocking_type.value,
            "aggressiveness_level": analysis.dpi_aggressiveness.value,
            "confidence": analysis.blocking_confidence,
            "characteristics": {},
        }

        if analysis.rst_analysis and analysis.rst_analysis.detected:
            signature["characteristics"]["rst_injection"] = {
                "type": analysis.rst_analysis.injection_type.value,
                "timing_ms": analysis.rst_analysis.timing_ms,
                "likely_spoofed": analysis.rst_analysis.likely_spoofed,
            }

        if analysis.tls_analysis:
            signature["characteristics"]["tls_behavior"] = {
                "blocks_sni": analysis.tls_analysis.sni_related_failure,
                "interruption_method": analysis.tls_analysis.interruption_method,
                "failure_stage": (
                    analysis.tls_analysis.failure_stage.value
                    if analysis.tls_analysis.failure_stage
                    else None
                ),
            }

        if analysis.dns_analysis and analysis.dns_analysis.detected:
            signature["characteristics"]["dns_manipulation"] = {
                "type": analysis.dns_analysis.manipulation_type.value,
                "response_timing_ms": analysis.dns_analysis.response_timing_ms,
            }

        return signature

    def _classify_rst_injection_type(
        self, rst_packets: List[Any], all_packets: List[Any]
    ) -> RST_InjectionType:
        """Классификация типа RST инъекции."""
        if not rst_packets:
            return RST_InjectionType.IMMEDIATE

        # Анализ направления RST пакетов
        rst_directions = set()
        for rst in rst_packets:
            if IP in rst:
                direction = f"{rst[IP].src}->{rst[IP].dst}"
                rst_directions.add(direction)

        if len(rst_directions) > 1:
            return RST_InjectionType.BIDIRECTIONAL

        # Анализ timing
        rst_times = [float(p.time) for p in rst_packets]
        if len(rst_times) > 1:
            time_diff = max(rst_times) - min(rst_times)
            if time_diff > 0.1:  # Более 100мс между RST пакетами
                return RST_InjectionType.DELAYED

        return RST_InjectionType.IMMEDIATE

    def _is_blocking_ip(self, ip_str: str) -> bool:
        """Проверка IP на принадлежность к блокировочным."""
        try:
            ip = ipaddress.ip_address(ip_str)

            # Проверка на известные блокировочные IP
            blocking_ips = self.blocking_patterns.get("government_block_ips", [])
            if ip_str in blocking_ips:
                return True

            # Проверка на приватные адреса (часто используются для блокировки)
            if ip.is_private or ip.is_loopback:
                return True

            return False

        except ValueError:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы детектора."""
        return {
            **self.stats,
            "cached_analyses": len(self.analysis_cache),
            "scapy_available": SCAPY_AVAILABLE,
            "deep_analysis_enabled": self.enable_deep_analysis,
        }
