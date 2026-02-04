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
import logging
import asyncio
import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, replace
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

# Импорт детекторов из нового модуля (Step 1 refactoring)
from .detectors import (
    RSTInjectionDetector,
    TLSHandshakeAnalyzer,
    SNIFilteringDetector,
    FragmentationAnalyzer,
    TimeoutDetector,
)

# Импорт экстрактора сигнатур (Step 2 refactoring)
from .signature_extractor import DPISignatureExtractor, DPISignature

# Импорт анализатора потоков (Step 3 refactoring)
from .flow_analyzer import FlowAnalyzer, FlowAnalysis, PacketAnalysis

# Импорт анализатора блокировок (Steps 4-6 refactoring)
from .blocking_analyzer import BlockingAnalyzer

# Импорт стратегий анализа (Step 7 refactoring)
from .analysis_strategies import (
    AnalysisContext,
    AnalysisStrategyFactory,
)

# Импорт сериализатора результатов (Step 9 refactoring)
from .result_serializer import ResultSerializer

# Импорт оптимизаций производительности (Step 11 refactoring)
from .performance_optimizer import (
    ResultCache,
    ParallelFlowProcessor,
    PerformanceMonitor,
    get_global_cache,
    get_global_monitor,
)

LOG = logging.getLogger("IntelligentPCAPAnalyzer")


# Backward compatibility: re-export all public classes
# Detectors and extractors are now in separate modules but re-exported here
__all__ = [
    "BlockingType",
    "DPIBehavior",
    "PacketAnalysis",
    "FlowAnalysis",
    "DPISignature",
    "PCAPAnalysisResult",
    "IntelligentPCAPAnalyzer",
    "RSTInjectionDetector",
    "TLSHandshakeAnalyzer",
    "SNIFilteringDetector",
    "FragmentationAnalyzer",
    "TimeoutDetector",
    "DPISignatureExtractor",
    "ResultSerializer",
    "ResultCache",
    "PerformanceMonitor",
    "analyze_pcap_file",
    "batch_analyze_pcap_files",
]

# Version information
__version__ = "2.0.0"
__api_version__ = "2.0"


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

        # Настройки производительности (Step 11)
        self.enable_caching = self.config.get("enable_caching", True)
        self.enable_parallel_processing = self.config.get("enable_parallel_processing", True)
        self.max_concurrent_flows = self.config.get("max_concurrent_flows", 10)

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

        # Инициализация анализатора потоков (Step 3 refactoring)
        # Передаем tls_analyzer для интеграции
        self.flow_analyzer = FlowAnalyzer(
            tls_analyzer=self.tls_analyzer,
            blocking_detector=None,  # Будет установлен позже, если нужен
        )

        # Инициализация анализатора блокировок (Steps 4-6 refactoring)
        self.blocking_analyzer = BlockingAnalyzer()

        # Инициализация сериализатора результатов (Step 9 refactoring)
        self.result_serializer = ResultSerializer()

        # Инициализация оптимизаций производительности (Step 11 refactoring)
        if self.enable_caching:
            self.cache = get_global_cache()
        else:
            self.cache = None

        if self.enable_parallel_processing:
            self.parallel_processor = ParallelFlowProcessor(
                max_concurrent=self.max_concurrent_flows
            )
        else:
            self.parallel_processor = None

        self.performance_monitor = get_global_monitor()

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
        perf = self.performance_monitor.start_operation("pcap_analysis")

        try:
            # Проверка существования файла
            if not os.path.exists(pcap_file):
                raise FileNotFoundError(f"PCAP файл не найден: {pcap_file}")

            file_stat = os.stat(pcap_file)

            # ---- Cache (whole-result) -------------------------------------------------
            cache_key = None
            if self.cache:
                cache_key = self._build_cache_key(pcap_file, file_stat)
                cached = self.cache.get(cache_key)
                if cached is not None:
                    analysis_duration = (datetime.now() - start_time).total_seconds()

                    # Accept either already-built PCAPAnalysisResult or dict-like payload
                    if isinstance(cached, PCAPAnalysisResult):
                        cached_result = cached
                    elif isinstance(cached, dict):
                        cached_result = self._dict_to_result(cached)
                    else:
                        cached_result = cached  # best-effort (keeps old behavior if any)

                    # Avoid mutating cached object (analysis_duration differs per call)
                    try:
                        result = replace(
                            cached_result,
                            analysis_duration=analysis_duration,
                            technical_details={
                                **(cached_result.technical_details or {}),
                                "cache_hit": True,
                                "cache_key": cache_key,
                            },
                        )
                    except Exception:
                        # If replace() fails for any reason, fall back to returning cached as-is
                        result = cached_result
                        try:
                            result.analysis_duration = analysis_duration
                            if isinstance(result.technical_details, dict):
                                result.technical_details.setdefault("cache_hit", True)
                                result.technical_details.setdefault("cache_key", cache_key)
                        except Exception:
                            pass

                    perf.finish(items_processed=getattr(result, "total_packets", 0) or 0)
                    LOG.info("Cache hit: результат анализа возвращён из кэша")
                    return result

            # Создание контекста анализа
            context = AnalysisContext(
                pcap_file=pcap_file,
                max_packets_to_analyze=self.max_packets_to_analyze,
                enable_signature_extraction=self.enable_signature_extraction,
                flow_analyzer=self.flow_analyzer,
                blocking_analyzer=self.blocking_analyzer,
                signature_extractor=self.signature_extractor,
            )

            # Inject optional helpers without changing context interface
            if self.parallel_processor:
                context.parallel_processor = self.parallel_processor
            context.performance_monitor = self.performance_monitor

            # Выбор и выполнение стратегии анализа
            strategy = AnalysisStrategyFactory.create_strategy(context)
            result_dict = await strategy.analyze()

            # Преобразование в PCAPAnalysisResult
            result = self._dict_to_result(result_dict)

            # Вычисление времени анализа
            analysis_duration = (datetime.now() - start_time).total_seconds()
            result.analysis_duration = analysis_duration
            perf.finish(items_processed=result.total_packets)

            # Store in cache after successful full build
            if self.cache and cache_key:
                try:
                    # store an immutable-ish snapshot (avoid later accidental mutations)
                    cache_store = replace(
                        result,
                        technical_details={
                            **(result.technical_details or {}),
                            "cache_stored": True,
                            "cache_key": cache_key,
                            "cache_stored_at": datetime.now().isoformat(),
                        },
                    )
                except Exception:
                    cache_store = result
                self.cache.set(cache_key, cache_store)

            LOG.info(
                f"Анализ завершен за {analysis_duration:.2f}с. "
                f"Блокировка: {result.blocking_detected}, "
                f"Тип: {result.primary_blocking_type.value}"
            )

            return result

        except FileNotFoundError as e:
            LOG.error(f"PCAP файл не найден: {e}")
            perf.finish(items_processed=0)
            return self._create_error_result(pcap_file, str(e))
        except ImportError as e:
            LOG.error(f"Ошибка импорта зависимостей: {e}")
            perf.finish(items_processed=0)
            return self._create_error_result(pcap_file, str(e))
        except Exception as e:
            LOG.error(f"Неожиданная ошибка анализа PCAP: {e}", exc_info=True)
            perf.finish(items_processed=0)
            return self._create_error_result(pcap_file, str(e))

    def _dict_to_result(self, result_dict: Dict[str, Any]) -> PCAPAnalysisResult:
        """
        Преобразование словаря результата в PCAPAnalysisResult.

        Args:
            result_dict: Словарь с результатами анализа

        Returns:
            PCAPAnalysisResult
        """
        # Преобразование типов блокировки из строк в enum
        bt_raw = result_dict.get(
            "primary_blocking_type",
            result_dict.get("primary_blocking_type_value", "unknown"),
        )
        # Accept: local Enum, foreign Enum (has .value), or string
        bt_val = getattr(bt_raw, "value", bt_raw)
        try:
            primary_blocking_type = BlockingType(bt_val)
        except Exception:
            primary_blocking_type = BlockingType.UNKNOWN

        db_raw = result_dict.get("dpi_behavior", DPIBehavior.UNKNOWN.value)
        db_val = getattr(db_raw, "value", db_raw)
        try:
            dpi_behavior = DPIBehavior(db_val)
        except Exception:
            dpi_behavior = DPIBehavior.UNKNOWN

        return PCAPAnalysisResult(
            pcap_file=result_dict["pcap_file"],
            analysis_timestamp=result_dict["analysis_timestamp"],
            total_packets=result_dict["total_packets"],
            total_flows=result_dict["total_flows"],
            analysis_duration=0,  # Будет установлено в основном методе
            blocking_detected=result_dict["blocking_detected"],
            primary_blocking_type=primary_blocking_type,
            dpi_behavior=dpi_behavior,
            confidence=result_dict["confidence"],
            flows=result_dict.get("flows", []),
            dpi_signatures=result_dict.get("dpi_signatures", []),
            blocking_evidence=result_dict.get("blocking_evidence", {}),
            bypass_recommendations=result_dict.get("bypass_recommendations", []),
            technical_details=result_dict.get("technical_details", {}),
        )

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
            technical_details={"error": error_msg, "analysis_method": "error"},
        )

    def _build_cache_key(self, pcap_file: str, file_stat: os.stat_result) -> str:
        """
        Build a stable cache key for a PCAP + analyzer config + dependency mode.

        NOTE: Does not change public API; used internally for ResultCache.
        """
        cfg = {
            "enable_deep_analysis": self.enable_deep_analysis,
            "enable_signature_extraction": self.enable_signature_extraction,
            "confidence_threshold": self.confidence_threshold,
            "max_packets_to_analyze": self.max_packets_to_analyze,
            "scapy_available": bool(self.scapy_available),
            "pcap_json_available": bool(self.pcap_json_available),
            "enable_parallel_processing": bool(self.enable_parallel_processing),
            "max_concurrent_flows": self.max_concurrent_flows,
        }
        cfg_json = json.dumps(cfg, sort_keys=True, default=str).encode("utf-8")
        cfg_hash = hashlib.sha256(cfg_json).hexdigest()[:12]

        # Include basic file identity to invalidate cache on file change
        ident = (
            f"{pcap_file}:{file_stat.st_size}:{int(file_stat.st_mtime)}:{cfg_hash}:{__version__}"
        )
        return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:16]

    async def save_analysis_result(self, result: PCAPAnalysisResult, output_file: str) -> bool:
        """
        Сохранение результата анализа в файл.

        Args:
            result: Результат анализа для сохранения
            output_file: Путь к выходному файлу

        Returns:
            True если успешно, False при ошибке
        """
        return self.result_serializer.save_to_file(result, output_file)

    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Получение статистики производительности.

        Returns:
            Словарь со статистикой
        """
        stats = {
            "monitor": self.performance_monitor.get_summary(),
        }

        if self.cache:
            stats["cache"] = self.cache.get_stats()

        return stats

    def clear_cache(self) -> None:
        """Очистка кэша результатов."""
        if self.cache:
            self.cache.clear()
            LOG.info("Cache cleared")


# Удобные функции для использования
async def analyze_pcap_file(
    pcap_file: str, config: Optional[Dict[str, Any]] = None
) -> PCAPAnalysisResult:
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


async def batch_analyze_pcap_files(
    pcap_files: List[str], config: Optional[Dict[str, Any]] = None
) -> List[PCAPAnalysisResult]:
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
            "max_packets_to_analyze": 5000,
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
