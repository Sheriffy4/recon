"""
Strategy Failure Analyzer - анализ причин неудач стратегий обхода DPI.

Этот модуль реализует анализ временных PCAP файлов для понимания причин неудач
стратегий обхода и генерации рекомендаций для улучшения.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Импорт RawPCAPReader вместо Scapy
from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket, RawPacketEngine, ProtocolType
from core.packet.packet_parser_utils import (
    parse_tcp_packet_headers,
    extract_rst_packets,
    has_tcp_flag,
    get_tcp_flags,
    get_tcp_sequence_numbers,
    get_ip_ttl,
)
from core.pcap_analysis.rst_analyzer import RSTAnalyzer
from core.pcap_analysis.tls_analyzer import TLSAnalyzer
from core.pcap_analysis.fragmentation_analyzer import FragmentationAnalyzer
from core.pcap_analysis.sni_analyzer import SNIAnalyzer
from core.pcap_analysis.failure_detector import FailureDetector
from core.strategy.recommendation_engine import (
    RecommendationEngine,
    Recommendation as EngineRecommendation,
)

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

        # Инициализация специализированных анализаторов
        self.rst_analyzer = RSTAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.fragmentation_analyzer = FragmentationAnalyzer()
        self.sni_analyzer = SNIAnalyzer()
        self.failure_detector = FailureDetector()
        self.recommendation_engine = RecommendationEngine()

        LOG.info("ℹ️ Используется RawPCAPReader для анализа PCAP")

        LOG.info(f"StrategyFailureAnalyzer инициализирован. Temp dir: {self.temp_dir}")

    @staticmethod
    def _packet_is_protocol(packet: RawPacket, proto: ProtocolType) -> bool:
        """
        Compat helper: RawPacket.protocol в разных реализациях может быть Enum/объект/строка.
        Интерфейсы внешних классов не трогаем.
        """
        p = getattr(packet, "protocol", None)
        if p == proto:
            return True
        name = getattr(p, "name", None)
        if name == proto.name:
            return True
        # Fallback: иногда протокол сериализован строкой
        try:
            return str(p) == proto.name
        except Exception:
            return False

    def _engine_base_intents_for_cause(self, failure_cause: FailureCause) -> List[str]:
        """
        Единственный источник правды по root_cause -> intents: RecommendationEngine.cause_to_intents.
        """
        try:
            mapping = getattr(self.recommendation_engine, "cause_to_intents", {}) or {}
            intents = mapping.get(failure_cause.name, []) or []
            return [i for i in intents if isinstance(i, str)]
        except Exception:
            LOG.debug("Не удалось получить base intents из RecommendationEngine", exc_info=True)
            return []

    def _convert_engine_recommendations(
        self, engine_recs: Iterable[EngineRecommendation]
    ) -> List["Recommendation"]:
        """
        Приведение strategy.recommendation_engine.Recommendation -> локальный Recommendation,
        чтобы не менять интерфейс FailureReport.recommendations.
        """
        converted: List[Recommendation] = []
        for rec in engine_recs or []:
            try:
                converted.append(
                    Recommendation(
                        action=getattr(rec, "action", ""),
                        rationale=getattr(rec, "rationale", ""),
                        priority=float(getattr(rec, "priority", 0.5)),
                        parameters=dict(getattr(rec, "parameters", {}) or {}),
                    )
                )
            except Exception:
                LOG.debug("Не удалось сконвертировать EngineRecommendation", exc_info=True)
        return converted

    def _augment_report_with_engine_recommendations(self, report: FailureReport) -> FailureReport:
        """
        Дополняем отчет рекомендациями из RecommendationEngine (централизованный генератор),
        не меняя интерфейсы StrategyFailureAnalyzer/FailureReport.
        """
        try:
            engine_recs = self.recommendation_engine.generate_recommendations(report)
            local_recs = self._convert_engine_recommendations(engine_recs)

            merged = self._deduplicate_recommendations((report.recommendations or []) + local_recs)
            merged.sort(key=lambda r: r.priority, reverse=True)
            report.recommendations = merged[:10]

            # suggested_intents пересчитываем на основе централизованных рекомендаций
            report.suggested_intents = self._generate_suggested_intents(
                report.root_cause, report.failure_details, report.recommendations
            )
        except Exception:
            LOG.debug("Ошибка дополнения отчета рекомендациями RecommendationEngine", exc_info=True)
        return report

    async def analyze_pcap(
        self, pcap_file: str, strategy: Strategy, domain: Optional[str] = None
    ) -> FailureReport:
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
                return self._create_error_report(
                    strategy, FailureCause.UNKNOWN, f"PCAP файл не найден: {pcap_file}"
                )

            # Используем RawPCAPReader для анализа
            return await self._analyze_with_raw_engine(pcap_file, strategy, domain=domain)

        except Exception as e:
            LOG.error(f"Ошибка анализа PCAP: {e}")
            return self._create_error_report(
                strategy, FailureCause.UNKNOWN, f"Ошибка анализа: {str(e)}"
            )
        finally:
            # Автоочистка временного файла
            await self._cleanup_pcap_file(pcap_file)

    def _convert_generated_strategy_to_strategy(self, generated_strategy: Any) -> "Strategy":
        """
        ИСПРАВЛЕНИЕ: Конвертация GeneratedStrategy в Strategy

        Проблема: GeneratedStrategy не имеет attack_name и id атрибутов
        Решение: Создаем Strategy объект с правильными атрибутами
        """
        try:
            # Извлекаем attack_name из attack_combination
            if (
                hasattr(generated_strategy, "attack_combination")
                and generated_strategy.attack_combination
            ):
                attack_name = generated_strategy.attack_combination[0]  # Берем первую атаку
            elif hasattr(generated_strategy, "attack_name"):
                attack_name = generated_strategy.attack_name
            else:
                attack_name = "unknown"

            # Создаем Strategy объект
            strategy = Strategy(
                name=getattr(generated_strategy, "name", "unknown"),
                attack_name=attack_name,
                parameters=getattr(generated_strategy, "parameters", {}),
                id=getattr(generated_strategy, "name", None),  # Используем name как id
            )

            LOG.debug(
                f"[CONVERT] GeneratedStrategy -> Strategy: {strategy.name} ({strategy.attack_name})"
            )
            return strategy

        except Exception as e:
            LOG.error(f"[CONVERT] Ошибка конвертации GeneratedStrategy: {e}")
            # Создаем fallback Strategy
            return Strategy(name="unknown", attack_name="unknown", parameters={}, id="unknown")

    async def _analyze_with_raw_engine(
        self, pcap_file: str, strategy: Any, domain: Optional[str] = None
    ) -> FailureReport:
        import asyncio

        try:
            # ИСПРАВЛЕНИЕ: Конвертируем GeneratedStrategy в Strategy если нужно
            if hasattr(strategy, "attack_combination") and not hasattr(strategy, "attack_name"):
                LOG.debug(f"[FIX] Конвертируем GeneratedStrategy в Strategy для анализа")
                strategy = self._convert_generated_strategy_to_strategy(strategy)

            loop = asyncio.get_event_loop()

            # Загрузка PCAP файла через RawPCAPReader
            LOG.info(f"Загрузка PCAP файла через RawPCAPReader: {pcap_file}")
            packets = await loop.run_in_executor(None, self.pcap_reader.read_pcap_file, pcap_file)

            LOG.info(f"📦 Загружено {len(packets)} пакетов из PCAP")

            # Анализируем все типы пакетов, не только TCP
            tcp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.TCP)]
            udp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.UDP)]
            icmp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.ICMP)]

            LOG.info(
                f"Статистика пакетов: TCP={len(tcp_packets)}, UDP={len(udp_packets)}, ICMP={len(icmp_packets)}, Всего={len(packets)}"
            )

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
            target_domain = domain or (
                sni_analysis["sni_domains"][0] if sni_analysis["sni_domains"] else "unknown"
            )
            failure_details["target_domain"] = target_domain

            report = FailureReport(
                strategy_id=getattr(strategy, "id", None) or getattr(strategy, "name", "unknown"),
                domain=target_domain,
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=failure_details.get("details", ""),
                failure_details=failure_details,
                recommendations=[],
                suggested_intents=[],
                confidence=self._calculate_confidence(packets, failure_cause),
                block_timing=self._compute_block_timing(tcp_packets),
                blocked_after_packet=self._compute_block_index(tcp_packets),
            )
            return self._augment_report_with_engine_recommendations(report)
        except Exception as e:
            LOG.error(f"Ошибка Scapy анализа: {e}")
            return self._create_error_report(strategy, FailureCause.UNKNOWN, str(e))

    async def _analyze_with_json_converter(
        self, pcap_file: str, strategy: Any, domain: Optional[str] = None
    ) -> FailureReport:
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

            report = FailureReport(
                strategy_id=strategy.id or strategy.name,
                domain=target_domain,
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=failure_details.get("details", ""),
                failure_details=failure_details,
                recommendations=[],
                suggested_intents=[],
                confidence=failure_details.get("confidence", 0.5),
            )
            return self._augment_report_with_engine_recommendations(report)
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

            report = FailureReport(
                strategy_id=strategy.id or strategy.name,
                domain="unknown",
                analyzed_at=datetime.now(),
                root_cause=failure_cause,
                root_cause_details=details,
                failure_details={"file_size": file_size, "analysis_method": "fallback"},
                recommendations=[],
                suggested_intents=[],
                confidence=0.3,  # Низкая уверенность для fallback анализа
            )
            return self._augment_report_with_engine_recommendations(report)

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
        if not packets:
            return FailureCause.NETWORK_TIMEOUT

        # Анализ TCP пакетов
        tcp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.TCP)]
        if not tcp_packets:
            return FailureCause.NETWORK_TIMEOUT

        # 1. Детектор RST инъекций (приоритет 1) - используем утилиту
        rst_packets = extract_rst_packets(tcp_packets)

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

    def _analyze_rst_injection(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Детальный анализ RST пакетов для определения инъекции DPI.

        Backward compatibility wrapper - делегирует к RSTAnalyzer.

        Args:
            rst_packets: Список RST пакетов (RawPacket)
            all_tcp_packets: Все TCP пакеты (RawPacket)

        Returns:
            Dict с результатами анализа RST инъекции
        """
        return self.rst_analyzer.analyze_rst_injection(rst_packets, all_tcp_packets)

    def _analyze_rst_ttl(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ TTL значений в RST пакетах для детекции инъекций.

        Backward compatibility wrapper - делегирует к RSTAnalyzer.
        """
        return self.rst_analyzer.analyze_rst_ttl(rst_packets, all_tcp_packets)

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
        return self.rst_analyzer.compute_block_index(tcp_packets)

    def _analyze_rst_sequence_numbers(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ seq/ack номеров в RST пакетах.

        Backward compatibility wrapper - делегирует к RSTAnalyzer.
        """
        return self.rst_analyzer.analyze_rst_sequence_numbers(rst_packets, all_tcp_packets)

    def _analyze_rst_timing(
        self, rst_packets: List[RawPacket], all_tcp_packets: List[RawPacket]
    ) -> Dict[str, Any]:
        """
        Анализ временных характеристик RST пакетов.

        Backward compatibility wrapper - делегирует к RSTAnalyzer.
        """
        return self.rst_analyzer.analyze_rst_timing(rst_packets, all_tcp_packets)

    def _analyze_rst_sources(self, rst_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Анализ источников RST пакетов.

        Backward compatibility wrapper - делегирует к RSTAnalyzer.
        """
        return self.rst_analyzer.analyze_rst_sources(rst_packets)

    def _analyze_tls_handshake(self, tcp_packets: List[RawPacket]) -> Dict[str, Any]:
        """
        Детальный анализ TLS handshake для обнаружения блокировок.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            Dict с результатами анализа TLS handshake
        """
        return self.tls_analyzer.analyze_tls_handshake(tcp_packets)

    def _is_client_hello_payload(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS ClientHello.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.
        """
        return self.tls_analyzer.is_client_hello_payload(payload)

    def _is_server_hello_payload(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS ServerHello.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.
        """
        return self.tls_analyzer.is_server_hello_payload(payload)

    def _is_tls_alert(self, payload: bytes) -> bool:
        """
        Проверка, является ли payload TLS Alert.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.
        """
        return self.tls_analyzer.is_tls_alert(payload)

    def _parse_tls_alert(self, payload: bytes) -> Dict[str, Any]:
        """
        Парсинг TLS Alert сообщения.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.
        """
        return self.tls_analyzer.parse_tls_alert(payload)

    def _get_tls_alert_description(self, code: int) -> str:
        """
        Получение описания TLS Alert по коду.

        Backward compatibility wrapper - делегирует к TLSAnalyzer.
        """
        return self.tls_analyzer.get_tls_alert_description(code)

    def _is_fragmentation_strategy(self, strategy: Strategy) -> bool:
        """Проверка, является ли стратегия основанной на фрагментации."""
        return self.fragmentation_analyzer.is_fragmentation_strategy(strategy)

    def _analyze_fragmentation_effectiveness(
        self, tcp_packets: List[RawPacket], strategy: Strategy
    ) -> Dict[str, Any]:
        """
        Анализ эффективности стратегий фрагментации.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            strategy: Стратегия обхода

        Returns:
            Dict с результатами анализа фрагментации
        """
        return self.fragmentation_analyzer.analyze_fragmentation_effectiveness(
            tcp_packets, strategy
        )

    def _block_after_reassembly(
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
        return self.fragmentation_analyzer.block_after_reassembly(tcp_packets, fragmented_packets)

    def _normal_tcp_reassembly_but_blocked(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка нормальной TCP сборки, но блокировки на уровне приложения.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            True если TCP сборка успешна, но приложение заблокировано
        """
        return self.fragmentation_analyzer.normal_tcp_reassembly_but_blocked(tcp_packets)

    def _ordered_fragments_blocked(self, fragmented_packets: List[RawPacket]) -> bool:
        """
        Проверка блокировки упорядоченных фрагментов.

        Args:
            fragmented_packets: Список фрагментированных пакетов (RawPacket)

        Returns:
            True если фрагменты упорядочены, но заблокированы
        """
        return self.fragmentation_analyzer.ordered_fragments_blocked(fragmented_packets)

    def _filter_relevant_packets(
        self, packets: List[RawPacket], domain: Optional[str] = None
    ) -> List[RawPacket]:
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

        # Если указан домен, пытаемся найти его IP (неблокирующий способ)
        # TODO: использовать async DNS resolver для избежания блокировки
        target_ips = set()
        if domain:
            try:
                import socket

                target_ip = socket.gethostbyname(domain)
                target_ips.add(target_ip)
                LOG.debug(f"Целевой IP для {domain}: {target_ip}")
            except Exception:
                LOG.debug(f"Не удалось разрешить IP для {domain}", exc_info=True)

        for packet in packets:
            is_relevant = False

            proto = getattr(packet, "protocol", None)
            proto_name = getattr(proto, "name", str(proto))

            # TCP пакеты всегда релевантны
            if proto == ProtocolType.TCP or proto_name == "TCP":
                is_relevant = True

            # UDP пакеты к портам 53 (DNS), 443, 80
            elif (proto == ProtocolType.UDP or proto_name == "UDP") and getattr(
                packet, "dst_port", None
            ) in [53, 80, 443]:
                is_relevant = True

            # Пакеты к целевому IP
            elif target_ips and getattr(packet, "dst_ip", None) in target_ips:
                is_relevant = True

            # ICMP пакеты (могут указывать на блокировку)
            elif proto == ProtocolType.ICMP or proto_name == "ICMP":
                is_relevant = True

            # Пакеты с TLS/SSL данными
            elif packet.payload:
                payload = packet.payload
                # Проверяем на TLS handshake
                if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                    is_relevant = True
                # Проверяем на HTTP
                elif (
                    b"HTTP" in payload[:100]
                    or b"GET " in payload[:100]
                    or b"POST " in payload[:100]
                ):
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
            "confidence": 0.0,
        }

        base = self.sni_analyzer.analyze_sni_filtering(tcp_packets)
        analysis["sni_domains"] = base.get("sni_domains", [])
        analysis["sni_found"] = bool(analysis["sni_domains"])

        if analysis["sni_found"]:
            client_hello_packets = [
                p for p in tcp_packets if p.payload and self._is_client_hello_payload(p.payload)
            ]
            server_hello_packets = [
                p for p in tcp_packets if p.payload and self._is_server_hello_payload(p.payload)
            ]

            # Индикатор 1: ClientHello с SNI есть, но ServerHello нет
            if client_hello_packets and not server_hello_packets:
                analysis["blocking_indicators"].append("no_server_hello_after_sni")
                analysis["confidence"] += 0.4

            # Индикатор 2: RST после ClientHello
            if base.get("rst_after_client_hello"):
                analysis["blocking_indicators"].append("rst_after_client_hello")
                analysis["confidence"] += 0.5

            # Индикатор 3: Паттерн заблокированного домена
            if self._is_blocked_domain_pattern(analysis["sni_domains"]):
                analysis["blocking_indicators"].append("blocked_domain_pattern")
                analysis["confidence"] += 0.3

        analysis["confidence"] = min(1.0, float(analysis["confidence"]))
        analysis["sni_blocked"] = analysis["confidence"] > 0.4

        return analysis

    def _extract_sni_from_client_hello(self, payload: bytes) -> Optional[str]:
        """Извлечение SNI из ClientHello пакета."""
        return self.sni_analyzer.extract_sni_from_client_hello(payload)

    def _parse_sni_extension(self, sni_data: bytes) -> Optional[str]:
        """Парсинг SNI extension."""
        return self.sni_analyzer.parse_sni_extension(sni_data)

    def _rst_after_client_hello(
        self, client_hello_packets: List[RawPacket], tcp_packets: List[RawPacket]
    ) -> bool:
        """
        Проверка RST после ClientHello.

        Args:
            client_hello_packets: Список пакетов с ClientHello (RawPacket)
            tcp_packets: Все TCP пакеты (RawPacket)

        Returns:
            True если найдены RST пакеты после ClientHello
        """
        return self.sni_analyzer.rst_after_client_hello(client_hello_packets, tcp_packets)

    def _is_blocked_domain_pattern(self, domains: List[str]) -> bool:
        """Проверка паттернов заблокированных доменов."""
        return self.sni_analyzer.is_blocked_domain_pattern(domains)

    def _detect_stateful_tracking(self, tcp_packets: List[RawPacket], strategy: Strategy) -> bool:
        """
        Детекция stateful отслеживания DPI.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)
            strategy: Стратегия обхода

        Returns:
            True если обнаружено stateful отслеживание
        """
        return self.failure_detector.detect_stateful_tracking(tcp_packets, strategy)

    def _is_connection_refused(self, tcp_packets: List[RawPacket]) -> bool:
        """
        Проверка отклонения соединения.

        Args:
            tcp_packets: Список TCP пакетов (RawPacket)

        Returns:
            True если соединение было отклонено
        """
        return self.failure_detector.is_connection_refused(tcp_packets)

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

    def _extract_failure_details(
        self, packets: List[RawPacket], failure_cause: FailureCause, strategy: Strategy
    ) -> Dict[str, Any]:
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

        tcp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.TCP)]

        details = {
            "packet_count": len(packets),
            "tcp_packet_count": len(tcp_packets),
            "strategy_name": strategy.name,
            "attack_name": strategy.attack_name,
            "analysis_method": "raw_packet_engine",
            "details": "",
            "technical_details": {},
        }

        if failure_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            # Находим RST пакеты
            rst_packets = extract_rst_packets(tcp_packets)

            rst_analysis = self._analyze_rst_injection(rst_packets, tcp_packets)

            details.update(
                {
                    "rst_count": len(rst_packets),
                    "injection_confidence": rst_analysis["confidence"],
                    "injection_indicators": rst_analysis["injection_indicators"],
                    "details": f"DPI RST инъекция обнаружена с уверенностью {rst_analysis['confidence']:.2f}. "
                    f"Индикаторы: {', '.join(rst_analysis['injection_indicators'])}",
                    "technical_details": rst_analysis,
                }
            )

        elif failure_cause == FailureCause.DPI_CONTENT_INSPECTION:
            tls_analysis = self._analyze_tls_handshake(tcp_packets)

            details.update(
                {
                    "client_hello_count": tls_analysis["client_hello_count"],
                    "server_hello_count": tls_analysis["server_hello_count"],
                    "tls_alerts": tls_analysis["tls_alerts"],
                    "details": f"DPI блокирует содержимое TLS. ClientHello: {tls_analysis['client_hello_count']}, "
                    f"ServerHello: {tls_analysis['server_hello_count']}",
                    "technical_details": tls_analysis,
                }
            )

        elif failure_cause == FailureCause.DPI_REASSEMBLES_FRAGMENTS:
            frag_analysis = self._analyze_fragmentation_effectiveness(tcp_packets, strategy)

            details.update(
                {
                    "fragmented_packets": frag_analysis["fragmented_packets_count"],
                    "reassembly_confidence": frag_analysis["confidence"],
                    "reassembly_indicators": frag_analysis["reassembly_indicators"],
                    "details": f"DPI собирает фрагменты. Фрагментированных пакетов: {frag_analysis['fragmented_packets_count']}, "
                    f"индикаторы сборки: {', '.join(frag_analysis['reassembly_indicators'])}",
                    "technical_details": frag_analysis,
                }
            )

        elif failure_cause == FailureCause.DPI_SNI_FILTERING:
            sni_analysis = self._analyze_sni_filtering(tcp_packets)

            details.update(
                {
                    "sni_domains": sni_analysis["sni_domains"],
                    "sni_blocking_confidence": sni_analysis["confidence"],
                    "blocking_indicators": sni_analysis["blocking_indicators"],
                    "details": f"DPI блокирует по SNI. Домены: {', '.join(sni_analysis['sni_domains'])}, "
                    f"индикаторы: {', '.join(sni_analysis['blocking_indicators'])}",
                    "technical_details": sni_analysis,
                }
            )

        elif failure_cause == FailureCause.DPI_STATEFUL_TRACKING:
            details.update(
                {
                    "details": "DPI отслеживает состояние соединения - stateful evasion неэффективен",
                    "strategy_type": "stateful_evasion",
                }
            )

        elif failure_cause == FailureCause.TLS_HANDSHAKE_FAILURE:
            tls_analysis = self._analyze_tls_handshake(tcp_packets)

            details.update(
                {
                    "tls_alerts": tls_analysis["tls_alerts"],
                    "details": f"TLS handshake неудачен. Алерты: {len(tls_analysis['tls_alerts'])}",
                    "technical_details": tls_analysis,
                }
            )

        elif failure_cause == FailureCause.CONNECTION_REFUSED:
            # Находим SYN и RST пакеты
            syn_packets = []
            rst_packets = []

            for p in tcp_packets:
                headers = parse_tcp_packet_headers(p)
                if headers is None:
                    continue
                _, tcp_header, _ = headers
                if (tcp_header.flags & TCPHeader.FLAG_SYN) and not (
                    tcp_header.flags & TCPHeader.FLAG_ACK
                ):
                    syn_packets.append(p)
                elif tcp_header.flags & TCPHeader.FLAG_RST:
                    rst_packets.append(p)

            details.update(
                {
                    "syn_count": len(syn_packets),
                    "rst_count": len(rst_packets),
                    "details": f"Соединение отклонено. SYN: {len(syn_packets)}, RST: {len(rst_packets)}",
                }
            )

        elif failure_cause == FailureCause.NETWORK_TIMEOUT:
            details.update(
                {"details": "Таймаут сети - пакеты не достигают цели или ответ не приходит"}
            )

        else:  # UNKNOWN
            details.update(
                {"details": "Причина неудачи не определена - требуется дополнительный анализ"}
            )

        return details

    def _extract_details_from_json(
        self, json_data: Dict, failure_cause: FailureCause, strategy: Strategy
    ) -> Dict[str, Any]:
        """Извлечение деталей из JSON данных."""
        details = {
            "total_flows": json_data.get("total_flows", 0),
            "strategy_name": strategy.name,
            "analysis_method": "json_converter",
            "confidence": 0.7,
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

        try:
            engine_recs = self.recommendation_engine.generate_recommendations(failure_report)
            local_recs = self._convert_engine_recommendations(engine_recs)
            local_recs = self._deduplicate_recommendations(local_recs)
            local_recs.sort(key=lambda x: x.priority, reverse=True)
            LOG.info(f"Сгенерировано {len(local_recs)} рекомендаций через RecommendationEngine")
            return local_recs
        except Exception:
            LOG.debug("Ошибка генерации рекомендаций через RecommendationEngine", exc_info=True)
            return []

    def _generate_intent_based_recommendations(
        self, failure_report: FailureReport
    ) -> List[Recommendation]:
        """
        Генерация рекомендаций на основе системы Intent'ов.
        Создает маппинг причин неудач на рекомендуемые Intent'ы.
        """
        # Совместимость: делегируем к RecommendationEngine, чтобы не было дублирования логики.
        try:
            engine_recs = self.recommendation_engine.generate_recommendations(failure_report)
            return self._convert_engine_recommendations(engine_recs)
        except Exception:
            LOG.debug(
                "Ошибка генерации intent-based рекомендаций через RecommendationEngine",
                exc_info=True,
            )
            return []

    def _get_intent_parameters(
        self, intent_key: str, failure_report: FailureReport
    ) -> Dict[str, Any]:
        """Получение параметров для Intent'а на основе анализа неудачи."""
        try:
            # приватный, но это единый источник правды для параметров
            return dict(
                self.recommendation_engine._get_intent_parameters(intent_key, failure_report) or {}
            )
        except Exception:
            return {"intent_key": intent_key}

    def _suggest_alternative_intents(self, failure_report: FailureReport) -> List[Recommendation]:
        """Предложение альтернативных Intent'ов на основе технических деталей."""
        try:
            engine_recs = self.recommendation_engine._suggest_alternative_intents(failure_report)
            return self._convert_engine_recommendations(engine_recs)
        except Exception:
            return []

    def _generate_recommendations(
        self, failure_cause: FailureCause, failure_details: Dict, strategy: Strategy
    ) -> List[Recommendation]:
        """
        Базовая генерация рекомендаций на основе причины неудачи.
        Используется как основа для расширенной генерации рекомендаций.
        """
        # Совместимость: оставляем метод, но делегируем к централизованному RecommendationEngine.
        # Для генерации нужен FailureReport-объект; создаем минимальный stub.
        stub = FailureReport(
            strategy_id=getattr(strategy, "id", None) or getattr(strategy, "name", "unknown"),
            domain=failure_details.get("target_domain", "unknown"),
            analyzed_at=datetime.now(),
            root_cause=failure_cause,
            root_cause_details=failure_details.get("details", ""),
            failure_details=failure_details or {},
            recommendations=[],
            suggested_intents=[],
            confidence=float(failure_details.get("confidence", 0.5) or 0.5),
        )
        try:
            engine_recs = self.recommendation_engine.generate_recommendations(stub)
            return self._convert_engine_recommendations(engine_recs)
        except Exception:
            LOG.debug(
                "Ошибка делегирования генерации рекомендаций в RecommendationEngine", exc_info=True
            )
            return []

    def _calculate_confidence(self, packets: List[RawPacket], failure_cause: FailureCause) -> float:
        """
        Расчет уверенности в анализе.

        Args:
            packets: Список пакетов (RawPacket)
            failure_cause: Причина неудачи

        Returns:
            Уверенность в анализе (0.0 - 1.0)
        """
        if not packets:
            return 0.1

        base_confidence = 0.5

        # Увеличиваем уверенность для четких индикаторов
        if failure_cause == FailureCause.DPI_ACTIVE_RST_INJECTION:
            # Подсчитываем RST пакеты
            tcp_packets = [p for p in packets if self._packet_is_protocol(p, ProtocolType.TCP)]
            rst_count = len(extract_rst_packets(tcp_packets))

            base_confidence += min(0.4, rst_count * 0.1)

        elif failure_cause == FailureCause.DPI_CONTENT_INSPECTION:
            base_confidence += 0.3

        # Учитываем количество пакетов
        packet_factor = min(0.2, len(packets) / 100)

        return min(0.95, base_confidence + packet_factor)

    def _generate_suggested_intents(
        self,
        failure_cause: FailureCause,
        failure_details: Dict[str, Any],
        recommendations: List[Recommendation],
    ) -> List[str]:
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
        intent_keys.extend(self._engine_base_intents_for_cause(failure_cause))

        # 2. Intent'ы из рекомендаций
        for rec in recommendations:
            intent_key = rec.parameters.get("intent_key")
            if intent_key and isinstance(intent_key, str):
                intent_keys.append(intent_key)

        # 3. Дополнительные intent'ы на основе деталей неудачи
        additional_intents = self._extract_intents_from_details(failure_details)
        intent_keys.extend(additional_intents)

        # Фильтруем None значения и удаляем дубликаты, сохраняя порядок
        filtered_intents = [
            intent for intent in intent_keys if intent is not None and isinstance(intent, str)
        ]
        unique_intents = list(dict.fromkeys(filtered_intents))

        # Ограничиваем до 5 intent'ов
        result = unique_intents[:5]

        LOG.info(
            f"Сгенерировано {len(result)} suggested_intents для {failure_cause.value}: {result}"
        )

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
        if (
            failure_details.get("fragments_reassembled")
            or failure_details.get("fragmented_packets", 0) > 0
        ):
            intents.append("packet_reordering")
            intents.append("sequence_overlap")

        # Анализ SNI
        if failure_details.get("sni_detected") or failure_details.get("sni_domains"):
            intents.append("conceal_sni")
            intents.append("fake_sni")

        # Анализ TLS
        if (
            failure_details.get("tls_handshake_blocked")
            or failure_details.get("client_hello_count", 0) > 0
        ):
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

    def _create_error_report(
        self, strategy: Strategy, cause: FailureCause, error_msg: str
    ) -> FailureReport:
        """Создание отчета об ошибке."""
        # Генерируем базовые intent'ы даже для ошибок
        suggested_intents = self._engine_base_intents_for_cause(cause)[:3]  # Максимум 3 для ошибок

        return FailureReport(
            strategy_id=strategy.id or strategy.name,
            domain="unknown",
            analyzed_at=datetime.now(),
            root_cause=cause,
            root_cause_details=error_msg,
            failure_details={"error": error_msg},
            recommendations=[],
            suggested_intents=suggested_intents,
            confidence=0.0,
        )

    def _deduplicate_recommendations(
        self, recommendations: List[Recommendation]
    ) -> List[Recommendation]:
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


async def analyze_strategy_failure(
    pcap_file: str, strategy_name: str, attack_name: str = None
) -> FailureReport:
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
        name=strategy_name, attack_name=attack_name or strategy_name, id=strategy_name
    )

    return await analyzer.analyze_pcap(pcap_file, strategy)
