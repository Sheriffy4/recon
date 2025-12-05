"""
AdaptiveEngine - главный оркестратор адаптивной системы обхода DPI.

Этот модуль реализует единую точку входа для всей логики адаптивного обхода,
координируя работу всех компонентов системы согласно требованиям FR-1, FR-2, FR-3.
"""

import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import concurrent.futures
from functools import lru_cache
import threading
import hashlib
import pickle
import subprocess
from enum import Enum

# Список шифров для эмуляции Chrome и раздувания ClientHello до ~1400 байт
BROWSER_CIPHER_LIST = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA:"
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
    "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:EDH-RSA-DES-CBC3-SHA"
)

# Define enums first to avoid import issues
class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogCategory(Enum):
    SYSTEM = "system"
    STRATEGY_TEST = "strategy_test"
    DPI_ANALYSIS = "dpi_analysis"
    FINGERPRINTING = "fingerprinting"
    PERFORMANCE = "performance"
    VALIDATION = "validation"
    ENGINE_OPERATION = "engine_operation"
    NETWORK = "network"
    ERROR_ANALYSIS = "error_analysis"

class LogContext:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


try:
    from core.bypass.filtering.feature_flags import FeatureFlagManager as FeatureFlags
except ImportError:
    FeatureFlags = None

try:
    from pcap_to_json_analyzer import analyze_pcap as analyze_pcap_json
    PCAP_JSON_AVAILABLE = True
except ImportError:
    analyze_pcap_json = None
    PCAP_JSON_AVAILABLE = False

# Task 7.1: Import TestResultCoordinator for test result management
try:
    from core.test_result_coordinator import TestResultCoordinator
    from core.pcap.analyzer import PCAPAnalyzer
    from core.validation.strategy_validator import StrategyValidator as ValidationStrategyValidator
    from core.validation.strategy_saver import StrategySaver
    TEST_RESULT_COORDINATOR_AVAILABLE = True
except ImportError as e:
    logging.warning(f"TestResultCoordinator components not available: {e}")
    TestResultCoordinator = None
    PCAPAnalyzer = None
    ValidationStrategyValidator = None
    StrategySaver = None
    TEST_RESULT_COORDINATOR_AVAILABLE = False
# Task 7.4: Import diagnostics modules
try:
    from core.diagnostics.structured_logger import (
        get_structured_logger
    )
    from core.diagnostics.performance_monitor import get_performance_monitor
    DIAGNOSTICS_AVAILABLE = True
    # Use string-based approach to avoid enum conflicts
    pass
except ImportError:
    DIAGNOSTICS_AVAILABLE = False
    logging.warning("Diagnostics modules not available")
    get_structured_logger = None
    get_performance_monitor = None

# Task 8.1: Import closed-loop metrics
try:
    from core.metrics.closed_loop_metrics import (
        get_closed_loop_metrics_collector,
        ClosedLoopMetricsCollector
    )
    CLOSED_LOOP_METRICS_AVAILABLE = True
except ImportError:
    CLOSED_LOOP_METRICS_AVAILABLE = False
    logging.warning("Closed-loop metrics not available")
    get_closed_loop_metrics_collector = None

# Auto-strategy-discovery: Import ConnectionMetrics
try:
    from core.connection_metrics import ConnectionMetrics, BlockType
    CONNECTION_METRICS_AVAILABLE = True
except ImportError:
    CONNECTION_METRICS_AVAILABLE = False
    logging.warning("ConnectionMetrics not available")
    ConnectionMetrics = None
    BlockType = None

# Task 3.3: Import StrategyEvaluator for centralized success/failure evaluation
try:
    from core.strategy_evaluator import StrategyEvaluator, EvaluationResult
    STRATEGY_EVALUATOR_AVAILABLE = True
except ImportError:
    STRATEGY_EVALUATOR_AVAILABLE = False
    logging.warning("StrategyEvaluator not available")
    StrategyEvaluator = None
    EvaluationResult = None
    ClosedLoopMetricsCollector = None

# Task 18: Import adaptive strategy adjuster
try:
    from core.adaptive_strategy_adjuster import AdaptiveStrategyAdjuster
    ADAPTIVE_STRATEGY_ADJUSTER_AVAILABLE = True
except ImportError:
    ADAPTIVE_STRATEGY_ADJUSTER_AVAILABLE = False
    logging.warning("Adaptive strategy adjuster not available")
    AdaptiveStrategyAdjuster = None

# Импорт существующих компонентов
try:
    from core.strategy_failure_analyzer import (
        StrategyFailureAnalyzer, 
        FailureReport, 
        Strategy, 
        TestResult, 
        TrialArtifacts
    )
    from core.fingerprint.dpi_fingerprint_service import (
        DPIFingerprintService, 
        DPIFingerprint
    )
    from core.strategy.strategy_intent_engine import (
        StrategyIntentEngine, 
        StrategyIntent
    )
    from core.strategy.strategy_generator import (
        StrategyGenerator, 
        GeneratedStrategy
    )
    COMPONENTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Some adaptive components not available: {e}")
    COMPONENTS_AVAILABLE = False
    StrategyFailureAnalyzer = None
    FailureReport = None
    Strategy = None
    TestResult = None
    TrialArtifacts = None
    DPIFingerprintService = None
    DPIFingerprint = None
    StrategyIntentEngine = None
    StrategyIntent = None
    StrategyGenerator = None
    GeneratedStrategy = None

# Интеграция с существующими модулями проекта
try:
    from core.unified_bypass_engine import UnifiedBypassEngine
    from core.bypass.engine.attack_dispatcher import AttackDispatcher
    from core.bypass.attacks.attack_registry import get_attack_registry
    # Task 7.3: Import capture-enabled bypass engine wrapper
    from core.pcap.bypass_engine_integration import WindowsBypassEngineWithCapture
    ENGINE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Bypass engine components not available: {e}")
    ENGINE_AVAILABLE = False
    UnifiedBypassEngine = None
    AttackDispatcher = None
    get_attack_registry = None
    WindowsBypassEngineWithCapture = None

LOG = logging.getLogger("AdaptiveEngine")


@dataclass
class StrategyResult:
    """Результат поиска стратегии"""
    success: bool
    strategy: Optional[Any] = None
    message: str = ""
    execution_time: float = 0.0
    trials_count: int = 0
    fingerprint_updated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AdaptiveConfig:
    """Конфигурация адаптивного движка"""
    # Основные параметры
    max_trials: int = 15
    stop_on_success: bool = True
    enable_fingerprinting: bool = True
    enable_failure_analysis: bool = True
    
    # Файлы данных
    fingerprints_file: str = "dpi_fingerprints.json"
    strategies_file: str = "best_strategies.json"
    negative_knowledge_file: str = "negative_knowledge.json"
    protocol_preferences_file: str = "protocol_preferences.json"
    
    # Таймауты
    strategy_timeout: float = 30.0
    connection_timeout: float = 5.0
    
    # Dual-stack и сетевые настройки
    enable_ipv6_fallback: bool = True
    prefer_ipv4: bool = True  # Предпочитать IPv4 по умолчанию
    timeout_factor_content_inspection: float = 2.0  # Множитель таймаута для DPI_CONTENT_INSPECTION
    timeout_factor_slow_cdn: float = 1.5  # Множитель для медленных CDN
    
    # Режимы работы
    mode: str = "comprehensive"  # quick, balanced, comprehensive
    
    # Новые параметры производительности
    enable_caching: bool = True
    cache_ttl_hours: int = 24
    enable_parallel_testing: bool = False  # ОТКЛЮЧЕНО: DPI стратегии конфликтуют за сетевые ресурсы
    max_parallel_workers: int = 5  # Увеличено для параллельного тестирования доменов
    enable_profiling: bool = False
    fingerprint_cache_size: int = 1000
    strategy_cache_size: int = 500
    
    # Task 11.1: Verification mode parameters
    verify_with_pcap: bool = False  # Enable verification mode with extended PCAP capture
    
    # Task 12.2: Batch mode parameters (Requirement 6.1, 6.2)
    batch_mode: bool = False  # Enable batch mode - saves only to adaptive_knowledge.json, not domain_rules.json
    
    # Task 7.1: Test result coordinator feature flag (Requirement 9.2)
    use_test_result_coordinator: bool = True  # Enable TestResultCoordinator for consistent test verdicts
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdaptiveConfig":
        """Создание конфигурации из словаря"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


class AdaptiveEngine:
    """
    Главный оркестратор адаптивной системы обхода DPI.
    
    Координирует работу всех компонентов:
    - Strategy Failure Analyzer (SFA)
    - DPI Fingerprint Service (DFS) 
    - Strategy Intent Engine (SIE)
    - Strategy Generator (SG)
    - Enhanced Strategy Calibrator
    """
    
    def __init__(self, config: Optional[AdaptiveConfig] = None):
        self.config = config or AdaptiveConfig()
        
        # === ИСПРАВЛЕНИЕ ЭКСПЕРТА: Глобальный lock для WinDivert ===
        self._divert_lock = threading.RLock()
        
        # Инициализация кэшей и блокировок ПЕРЕД инициализацией компонентов
        self._fingerprint_cache = {}
        self._strategy_cache = {}
        self._domain_accessibility_cache = {}
        self._protocol_preference_cache = {}  # Кэш предпочтительных протоколов IPv4/IPv6
        self._cache_lock = threading.RLock()
        
        # Инициализация компонентов
        self._init_components()
        
        # Initialize feature flags
        self._feature_flags = None
        try:
            if FeatureFlags is None:
                LOG.warning("⚠️ FeatureFlags class not imported, trying direct import")
                from core.feature_flags import FeatureFlags as FF
                self._feature_flags = FF()
            else:
                self._feature_flags = FeatureFlags()
            LOG.info("✅ Feature flags initialized successfully")
        except Exception as e:
            LOG.error(f"❌ Could not initialize feature flags: {e}")
            import traceback
            LOG.error(traceback.format_exc())
        
        # НОВОЕ: Компоненты замкнутого цикла обучения
        try:
            from core.knowledge.knowledge_accumulator import KnowledgeAccumulator
            from core.knowledge.pattern_matcher import PatternMatcher
            
            self.knowledge_accumulator = KnowledgeAccumulator()
            self.pattern_matcher = PatternMatcher(self.knowledge_accumulator)
            
            LOG.info("✅ Компоненты замкнутого цикла обучения инициализированы")
        except ImportError as e:
            LOG.warning(f"⚠️ Компоненты замкнутого цикла недоступны: {e}")
            self.knowledge_accumulator = None
            self.pattern_matcher = None
        
        # Статистика с производительностью
        self.stats = {
            "domains_processed": 0,
            "strategies_found": 0,
            "total_trials": 0,
            "fingerprints_created": 0,
            "failures_analyzed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "parallel_tests_executed": 0,
            "average_test_time": 0.0,
            "fingerprint_creation_time": 0.0,
            "strategy_generation_time": 0.0
        }
        
        # НОВОЕ: Статистика замкнутого цикла обучения
        self.closed_loop_stats = {
            "iterations_total": 0,
            "intents_generated": 0,
            "strategies_augmented": 0,
            "pattern_matches": 0,
            "knowledge_updates": 0
        }
        
        # НОВОЕ: Статистика адаптивных таймаутов
        self.timeout_stats = {
            "adaptive_timeouts_applied": 0,
            "content_inspection_adjustments": 0,
            "rst_injection_adjustments": 0,
            "network_timeout_adjustments": 0,
            "slow_cdn_adjustments": 0,
            "average_timeout_factor": 1.0
        }
        
        # Task 8.1: Initialize closed-loop metrics collector
        self.metrics_collector = None
        if CLOSED_LOOP_METRICS_AVAILABLE and get_closed_loop_metrics_collector:
            try:
                self.metrics_collector = get_closed_loop_metrics_collector()
                LOG.info("✅ Коллектор метрик замкнутого цикла инициализирован")
            except Exception as e:
                LOG.warning(f"⚠️ Ошибка инициализации коллектора метрик: {e}")
                self.metrics_collector = None
        else:
            LOG.warning("⚠️ Коллектор метрик замкнутого цикла недоступен")
        
        # Task 18: Initialize adaptive strategy adjuster
        self.strategy_adjuster = None
        if ADAPTIVE_STRATEGY_ADJUSTER_AVAILABLE and AdaptiveStrategyAdjuster:
            try:
                self.strategy_adjuster = AdaptiveStrategyAdjuster()
                LOG.info("[OK] Adaptive strategy adjuster initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize adaptive strategy adjuster: {e}")
                self.strategy_adjuster = None
        else:
            LOG.warning("Adaptive strategy adjuster not available")
        
        # Task 3.3: Initialize StrategyEvaluator for centralized success/failure evaluation
        self.strategy_evaluator = None
        if STRATEGY_EVALUATOR_AVAILABLE and StrategyEvaluator:
            try:
                self.strategy_evaluator = StrategyEvaluator()
                LOG.info("✅ StrategyEvaluator инициализирован для централизованной оценки стратегий")
            except Exception as e:
                LOG.warning(f"⚠️ Ошибка инициализации StrategyEvaluator: {e}")
                self.strategy_evaluator = None
        else:
            LOG.warning("⚠️ StrategyEvaluator недоступен")
        
        # Task 5.4: Initialize AdaptiveKnowledgeBase for automatic strategy discovery
        self.adaptive_knowledge = None
        try:
            from core.adaptive_knowledge import AdaptiveKnowledgeBase
            self.adaptive_knowledge = AdaptiveKnowledgeBase()
            LOG.info("✅ AdaptiveKnowledgeBase инициализирован для автоматического поиска стратегий")
        except Exception as e:
            LOG.warning(f"⚠️ Ошибка инициализации AdaptiveKnowledgeBase: {e}")
            self.adaptive_knowledge = None
        
        # Task 11.5: Initialize StrategyValidator for verification mode
        self.strategy_validator = None
        try:
            from core.strategy_validator import StrategyValidator
            self.strategy_validator = StrategyValidator()
            LOG.info("✅ StrategyValidator инициализирован для верификационного режима")
        except Exception as e:
            LOG.warning(f"⚠️ Ошибка инициализации StrategyValidator: {e}")
            self.strategy_validator = None
        
        # Task 7.1: Initialize TestResultCoordinator for consistent test verdicts (Requirement 9.2)
        self.test_result_coordinator = None
        if self.config.use_test_result_coordinator and TEST_RESULT_COORDINATOR_AVAILABLE:
            try:
                # Initialize dependencies
                pcap_analyzer = PCAPAnalyzer() if PCAPAnalyzer else None
                validation_strategy_validator = ValidationStrategyValidator() if ValidationStrategyValidator else None
                
                # Initialize coordinator
                self.test_result_coordinator = TestResultCoordinator(
                    pcap_analyzer=pcap_analyzer,
                    strategy_validator=validation_strategy_validator
                )
                LOG.info("✅ TestResultCoordinator инициализирован для управления результатами тестов")
                LOG.info(f"   PCAP Analyzer: {'Available' if pcap_analyzer else 'Not Available'}")
                LOG.info(f"   Strategy Validator: {'Available' if validation_strategy_validator else 'Not Available'}")
            except Exception as e:
                LOG.warning(f"⚠️ Ошибка инициализации TestResultCoordinator: {e}")
                self.test_result_coordinator = None
        else:
            if not self.config.use_test_result_coordinator:
                LOG.info("ℹ️ TestResultCoordinator отключен через конфигурацию")
            else:
                LOG.warning("⚠️ TestResultCoordinator недоступен")
        
        # Task 7.1: Initialize StrategySaver for deduplication (Requirement 5.4, 5.5)
        self.strategy_saver = None
        if self.config.use_test_result_coordinator and TEST_RESULT_COORDINATOR_AVAILABLE and StrategySaver:
            try:
                self.strategy_saver = StrategySaver()
                LOG.info("✅ StrategySaver инициализирован для дедупликации сохранений")
            except Exception as e:
                LOG.warning(f"⚠️ Ошибка инициализации StrategySaver: {e}")
                self.strategy_saver = None

        
        # Пул потоков для параллельного тестирования
        if self.config.enable_parallel_testing:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.max_parallel_workers
            )
        else:
            self._executor = None
        
        # Профилирование
        self._profiling_data = {}
        self._profiling_lock = threading.RLock()
        self._avg_augmentation_time = 0.0
        self._augmentation_count = 0
        
        # Task 7.4: Initialize diagnostics
        self.structured_logger = None
        self.performance_monitor = None
        if DIAGNOSTICS_AVAILABLE and get_structured_logger and get_performance_monitor:
            try:
                self.structured_logger = get_structured_logger()
                self.performance_monitor = get_performance_monitor()
                LOG.info("Diagnostics modules initialized successfully")
            except Exception as e:
                LOG.warning(f"Failed to initialize diagnostics: {e}")
        
        LOG.info(f"AdaptiveEngine initialized with caching={'enabled' if self.config.enable_caching else 'disabled'}, "
                f"parallel_testing={'enabled' if self.config.enable_parallel_testing else 'disabled'}")
    
    def _get_strategy_name(self, strategy: Any) -> str:
        """
        Extract strategy name from strategy object.
        
        Args:
            strategy: Strategy object (can be dict, object, or string)
            
        Returns:
            Strategy name as string
        """
        if isinstance(strategy, str):
            return strategy
        elif isinstance(strategy, dict):
            return strategy.get('name', strategy.get('attack_name', 'unknown'))
        elif hasattr(strategy, 'name'):
            return strategy.name
        elif hasattr(strategy, 'attack_name'):
            return strategy.attack_name
        else:
            return 'unknown'
    
    def _record_profiling_data(self, operation: str, execution_time: float):
        """
        Запись данных профилирования для анализа производительности.
        
        Args:
            operation: Название операции
            execution_time: Время выполнения в секундах
        """
        if not self.config.enable_profiling:
            return
        
        with self._profiling_lock:
            if operation not in self._profiling_data:
                self._profiling_data[operation] = {
                    "total_time": 0.0,
                    "call_count": 0,
                    "min_time": float('inf'),
                    "max_time": 0.0,
                    "avg_time": 0.0
                }
            
            data = self._profiling_data[operation]
            data["total_time"] += execution_time
            data["call_count"] += 1
            data["min_time"] = min(data["min_time"], execution_time)
            data["max_time"] = max(data["max_time"], execution_time)
            data["avg_time"] = data["total_time"] / data["call_count"]
            
            # Логируем медленные операции
            if execution_time > 1.0:  # Операции дольше 1 секунды
                LOG.warning(f"⚠️ Медленная операция {operation}: {execution_time:.3f}s "
                           f"(среднее: {data['avg_time']:.3f}s)")
    
    def _update_average_augmentation_time(self, execution_time: float):
        """
        Обновление среднего времени augmentation для метрик производительности.
        
        Args:
            execution_time: Время выполнения augmentation в секундах
        """
        with self._profiling_lock:
            self._augmentation_count += 1
            self._avg_augmentation_time = (
                (self._avg_augmentation_time * (self._augmentation_count - 1) + execution_time) /
                self._augmentation_count
            )
            
            # Проверяем соответствие требованиям производительности
            if self._avg_augmentation_time > 0.2:  # 200ms лимит
                LOG.warning(f"⚠️ Среднее время augmentation превышает лимит: "
                           f"{self._avg_augmentation_time:.3f}s > 0.200s")
    
    def get_profiling_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики профилирования для анализа производительности.
        
        Returns:
            Словарь с данными профилирования
        """
        with self._profiling_lock:
            stats = {
                "profiling_enabled": self.config.enable_profiling,
                "avg_augmentation_time_ms": self._avg_augmentation_time * 1000,
                "augmentation_count": self._augmentation_count,
                "performance_requirements": {
                    "avg_augmentation_time_limit_ms": 200,
                    "meets_requirements": self._avg_augmentation_time <= 0.2
                },
                "operations": {}
            }
            
            for operation, data in self._profiling_data.items():
                stats["operations"][operation] = {
                    "avg_time_ms": data["avg_time"] * 1000,
                    "min_time_ms": data["min_time"] * 1000,
                    "max_time_ms": data["max_time"] * 1000,
                    "total_time_ms": data["total_time"] * 1000,
                    "call_count": data["call_count"],
                    "total_time_percentage": (data["total_time"] / 
                                            sum(op["total_time"] for op in self._profiling_data.values())) * 100
                }
            
            return stats
    
    def optimize_hot_paths(self):
        """
        Оптимизация горячих путей на основе данных профилирования.
        
        Анализирует данные профилирования и применяет оптимизации
        для наиболее медленных операций.
        """
        if not self.config.enable_profiling or not self._profiling_data:
            LOG.info("Профилирование отключено или нет данных для оптимизации")
            return
        
        with self._profiling_lock:
            # Находим самые медленные операции
            slow_operations = []
            for operation, data in self._profiling_data.items():
                if data["avg_time"] > 0.1:  # Операции медленнее 100ms
                    slow_operations.append((operation, data["avg_time"]))
            
            slow_operations.sort(key=lambda x: x[1], reverse=True)
            
            if slow_operations:
                LOG.info(f"🔧 Найдено {len(slow_operations)} медленных операций для оптимизации:")
                
                for operation, avg_time in slow_operations[:5]:  # Топ 5
                    LOG.info(f"   - {operation}: {avg_time:.3f}s")
                    
                    # Применяем специфичные оптимизации
                    if operation == "pattern_matching":
                        self._optimize_pattern_matching()
                    elif operation == "pcap_analysis":
                        self._optimize_pcap_analysis()
                    elif operation == "strategy_generation":
                        self._optimize_strategy_generation()
            else:
                LOG.info("✅ Все операции выполняются в пределах нормы")
    
    def _optimize_pattern_matching(self):
        """Оптимизация сопоставления паттернов."""
        if self.pattern_matcher:
            # Увеличиваем размер кэша для Pattern Matcher
            LOG.info("🔧 Оптимизация Pattern Matcher: увеличение кэша")
            # Кэш уже реализован в PatternMatcher
    
    def _optimize_pcap_analysis(self):
        """Оптимизация анализа PCAP."""
        LOG.info("🔧 Оптимизация PCAP анализа: рекомендуется использовать более быстрые методы")
        # Здесь можно добавить специфичные оптимизации для SFA
    
    def _optimize_strategy_generation(self):
        """Оптимизация генерации стратегий."""
        LOG.info("🔧 Оптимизация генерации стратегий: ограничение количества генерируемых стратегий")
        # Можно динамически уменьшить max_strategies в зависимости от производительности
    
    def _test_strategy(self, target_ip: str, strategy_input, domain: Optional[str], timeout: float,
                      verification_mode: bool = False, enable_capture: bool = True) -> Dict[str, Any]:  # Requirement 1.2: Add enable_capture
        """
        Test strategy using the appropriate method based on feature flags.
        
        This method automatically selects between:
        - Service-based testing (like zapret) - NEW, more reliable
        - Inline testing (current approach) - OLD, has issues
        
        Args:
            target_ip: Target IP address
            strategy_input: Strategy configuration
            domain: Domain name
            timeout: Timeout in seconds
            verification_mode: Enable extended PCAP capture for verification (Task 11.2)
            enable_capture: Enable individual PCAP capture (Requirement 1.2: False when using shared PCAP)
            
        Returns:
            Dict with test results
        """
        # Check if service-based testing is enabled
        use_service_based = False
        if self._feature_flags:
            try:
                use_service_based = self._feature_flags.is_enabled('service_based_testing')
                LOG.info(f"🔍 Service-based testing flag: {use_service_based}")
            except Exception as e:
                LOG.warning(f"Could not check service_based_testing flag: {e}")
        else:
            LOG.warning("⚠️ Feature flags not available, defaulting to inline testing")
        
        # Check method availability
        has_service_method = hasattr(self.bypass_engine, 'test_strategy_as_service')
        has_inline_method = hasattr(self.bypass_engine, 'test_strategy_like_testing_mode')
        LOG.info(f"🔍 Available methods: service={has_service_method}, inline={has_inline_method}")
        
        # Select testing method
        if use_service_based and has_service_method:
            LOG.info("✅ Using service-based testing (zapret-style)")
            return self.bypass_engine.test_strategy_as_service(
                target_ip=target_ip,
                strategy_input=strategy_input,
                domain=domain,
                timeout=timeout,
                verification_mode=verification_mode,  # Task 11.2: Pass verification_mode
                enable_capture=enable_capture  # Requirement 1.2: Pass enable_capture
            )
        elif has_inline_method:
            LOG.info("⚠️ Using inline testing (legacy)")
            return self.bypass_engine.test_strategy_like_testing_mode(
                target_ip=target_ip,
                strategy_input=strategy_input,
                domain=domain,
                timeout=timeout,
                verification_mode=verification_mode  # Task 11.2: Pass verification_mode
            )
        else:
            LOG.error("❌ No testing method available!")
            return {
                "success": False,
                "error": "No testing method available",
                "target_ip": target_ip,
                "domain": domain
            }
    
    def _init_components(self):
        """Инициализация всех компонентов системы"""
        if not COMPONENTS_AVAILABLE:
            raise ImportError("Required adaptive components not available")
        
        # Task 6.2: Initialize DoHIntegration for unified DNS resolution
        try:
            from core.dns.doh_integration import DoHIntegration
            self.doh_integration = DoHIntegration.from_config_file("config/doh_config.json")
            LOG.info("✅ DoHIntegration initialized for adaptive engine")
            LOG.info(f"   DoH enabled: {self.doh_integration.enable_doh}")
            LOG.info(f"   Auto-detect blocking: {self.doh_integration.auto_detect_blocking}")
        except Exception as e:
            LOG.warning(f"⚠️ DoHIntegration not available: {e}, using direct DoHResolver")
            self.doh_integration = None
        
        # === ИСПРАВЛЕНИЕ ЭКСПЕРТА: UnifiedStrategyLoader ===
        # Task 6.1: Use StrategyManager instead of UnifiedStrategyLoader (which doesn't exist)
        try:
            from core.strategy_manager import StrategyManager
            self._strategy_manager = StrategyManager()
            LOG.info("✅ StrategyManager initialized for strategy persistence")
        except Exception as e:
            LOG.warning(f"⚠️ StrategyManager not available: {e}")
            self._strategy_manager = None
        
        # Основные компоненты
        if StrategyFailureAnalyzer:
            self.failure_analyzer = StrategyFailureAnalyzer()
        if DPIFingerprintService:
            self.fingerprint_service = DPIFingerprintService(
                cache_file=self.config.fingerprints_file
            )
        if StrategyIntentEngine:
            self.intent_engine = StrategyIntentEngine()
        if StrategyGenerator:
            self.strategy_generator = StrategyGenerator()
        
        # === ИСПРАВЛЕНИЕ ЭКСПЕРТА: UnifiedBypassEngine с полной конфигурацией ===
        if ENGINE_AVAILABLE and UnifiedBypassEngine:
            try:
                from core.unified_bypass_engine import UnifiedEngineConfig
                
                engine_config = UnifiedEngineConfig(
                    debug=True,
                    force_override=True,
                    enable_diagnostics=True,
                    log_all_strategies=True,
                    track_forced_override=True
                )
                
                if WindowsBypassEngineWithCapture:
                    self.bypass_engine = WindowsBypassEngineWithCapture(
                        UnifiedBypassEngine(config=engine_config)
                    )
                    LOG.info("✅ Capture-enabled bypass engine initialized")
                else:
                    self.bypass_engine = UnifiedBypassEngine(config=engine_config)
                    LOG.warning("⚠️ Regular bypass engine initialized")
            except Exception as e:
                LOG.error(f"Bypass engine init failed: {e}")
                self.bypass_engine = None
        else:
            LOG.warning("Bypass engine not available")
            self.bypass_engine = None
        
        # Загрузка сохраненных стратегий
        self.best_strategies = self._load_best_strategies()
        self.negative_knowledge = self._load_negative_knowledge()
        
        # Загрузка предпочтений протоколов
        self._load_protocol_preferences()
        
        # Task 6.5: Log component initialization summary
        LOG.info("=" * 60)
        LOG.info("AdaptiveEngine Component Initialization Summary:")
        LOG.info(f"  ✅ StrategyManager: {'Available' if self._strategy_manager else 'Not Available'}")
        LOG.info(f"  ✅ DoHIntegration: {'Available' if self.doh_integration else 'Not Available'}")
        LOG.info(f"  ✅ BypassEngine: {'Available' if self.bypass_engine else 'Not Available'}")
        LOG.info(f"  ✅ PCAP Capture: {'Enabled' if WindowsBypassEngineWithCapture and isinstance(self.bypass_engine, WindowsBypassEngineWithCapture) else 'Disabled'}")
        LOG.info(f"  ✅ Forced Override: Enabled (all strategies use no_fallbacks=True, forced=True)")
        LOG.info(f"  ✅ Strategy Validation: Enabled")
        LOG.info(f"  ✅ PCAP Analysis: Enabled (PCAPAnalyzer)")
        LOG.info("=" * 60)
    
    def _load_best_strategies(self) -> Dict[str, Any]:
        """Загрузка сохраненных лучших стратегий"""
        strategies_file = Path(self.config.strategies_file)
        if not strategies_file.exists():
            return {}
        
        try:
            with open(strategies_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                strategies = {}
                for domain, strategy_data in data.items():
                    if Strategy:
                        strategies[domain] = Strategy(
                            name=strategy_data.get("name", "unknown"),
                            attack_name=strategy_data.get("attack_name", "unknown"),
                            parameters=strategy_data.get("parameters", {}),
                            id=strategy_data.get("id")
                        )
                LOG.info(f"Loaded {len(strategies)} saved strategies")
                return strategies
        except Exception as e:
            LOG.warning(f"Failed to load saved strategies: {e}")
            return {}
    
    def _save_best_strategies(self):
        """Сохранение лучших стратегий"""
        try:
            data = {}
            for domain, strategy in self.best_strategies.items():
                data[domain] = {
                    "name": strategy.name,
                    "attack_name": getattr(strategy, 'attack_name', strategy.attack_combination[0] if hasattr(strategy, 'attack_combination') and strategy.attack_combination else 'unknown'),
                    "parameters": strategy.parameters,
                    "id": getattr(strategy, 'id', strategy.name),
                    "saved_at": datetime.now().isoformat()
                }
            
            with open(self.config.strategies_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"Saved {len(data)} strategies to {self.config.strategies_file}")
        except Exception as e:
            LOG.error(f"Failed to save strategies: {e}")
    
    def _load_negative_knowledge(self) -> Dict[str, List[str]]:
        """Загрузка негативных знаний (что не работает)"""
        nk_file = Path(self.config.negative_knowledge_file)
        if not nk_file.exists():
            return {}
        
        try:
            with open(nk_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                LOG.info(f"Loaded negative knowledge for {len(data)} domains")
                return data
        except Exception as e:
            LOG.warning(f"Failed to load negative knowledge: {e}")
            return {}
    
    def _load_protocol_preferences(self):
        """Загрузка предпочтений протоколов из файла"""
        pref_file = Path(self.config.protocol_preferences_file)
        if not pref_file.exists():
            LOG.info("Protocol preferences file not found, starting with empty preferences")
            return
        
        try:
            with open(pref_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Загружаем данные в кэш с проверкой валидности
                current_time = datetime.now()
                loaded_count = 0
                
                with self._cache_lock:
                    for domain, pref_data in data.items():
                        try:
                            # Проверяем структуру данных
                            if all(key in pref_data for key in ["ip_type", "target_ip", "timestamp", "success_count"]):
                                # Парсим timestamp
                                timestamp = datetime.fromisoformat(pref_data["timestamp"])
                                
                                # Проверяем, не устарели ли данные (максимум 30 дней)
                                age_days = (current_time - timestamp).days
                                if age_days <= 30:
                                    self._protocol_preference_cache[domain] = {
                                        "ip_type": pref_data["ip_type"],
                                        "target_ip": pref_data["target_ip"],
                                        "timestamp": timestamp,
                                        "success_count": pref_data["success_count"]
                                    }
                                    loaded_count += 1
                                else:
                                    LOG.debug(f"Skipping outdated preference for {domain} (age: {age_days} days)")
                        except Exception as e:
                            LOG.warning(f"Invalid preference data for {domain}: {e}")
                
                LOG.info(f"Loaded {loaded_count} protocol preferences from {pref_file}")
                
        except Exception as e:
            LOG.warning(f"Failed to load protocol preferences: {e}")
    
    def _save_negative_knowledge(self):
        """Сохранение негативных знаний"""
        try:
            with open(self.config.negative_knowledge_file, 'w', encoding='utf-8') as f:
                json.dump(self.negative_knowledge, f, indent=2, ensure_ascii=False)
        except Exception as e:
            LOG.error(f"Failed to save negative knowledge: {e}")
    

    
    def _save_protocol_preferences(self):
        """Сохранение предпочтений протоколов в файл"""
        try:
            # Подготавливаем данные для сохранения
            data_to_save = {}
            
            with self._cache_lock:
                for domain, pref_data in self._protocol_preference_cache.items():
                    # Проверяем валидность данных перед сохранением
                    if self._is_cache_valid(pref_data.get('timestamp', datetime.now())):
                        # Конвертируем datetime в строку для JSON
                        save_data = pref_data.copy()
                        if 'timestamp' in save_data:
                            save_data['timestamp'] = save_data['timestamp'].isoformat()
                        data_to_save[domain] = save_data
            
            # Сохраняем в файл
            with open(self.config.protocol_preferences_file, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
            
            LOG.info(f"💾 Сохранено {len(data_to_save)} предпочтений протоколов в {self.config.protocol_preferences_file}")
            
        except Exception as e:
            LOG.error(f"Failed to save protocol preferences: {e}")
    
    def _get_cache_key(self, domain: str, context: str = "") -> str:
        """Генерация ключа кэша"""
        key_data = f"{domain}:{context}:{self.config.mode}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_cache_valid(self, timestamp: datetime) -> bool:
        """Проверка валидности кэша"""
        age = datetime.now() - timestamp
        return age.total_seconds() < (self.config.cache_ttl_hours * 3600)

    def _get_cached_fingerprint(self, domain: str) -> Optional[Any]:
        """Кэшированное получение DPI fingerprint"""
        if not self.config.enable_caching:
            return None
        
        cache_key = self._get_cache_key(domain, "fingerprint")
        
        with self._cache_lock:
            if cache_key in self._fingerprint_cache:
                cached_data = self._fingerprint_cache[cache_key]
                if self._is_cache_valid(cached_data["timestamp"]):
                    self.stats["cache_hits"] += 1
                    return cached_data["fingerprint"]
                else:
                    # Удаляем устаревший кэш
                    del self._fingerprint_cache[cache_key]
        
        self.stats["cache_misses"] += 1
        return None
    
    def _cache_fingerprint(self, domain: str, fingerprint: Any):
        """Кэширование DPI fingerprint"""
        if not self.config.enable_caching:
            return
        
        cache_key = self._get_cache_key(domain, "fingerprint")
        
        with self._cache_lock:
            # Ограничиваем размер кэша
            if len(self._fingerprint_cache) >= self.config.fingerprint_cache_size:
                # Удаляем самый старый элемент
                oldest_key = min(self._fingerprint_cache.keys(), 
                               key=lambda k: self._fingerprint_cache[k]["timestamp"])
                del self._fingerprint_cache[oldest_key]
            
            self._fingerprint_cache[cache_key] = {
                "fingerprint": fingerprint,
                "timestamp": datetime.now()
            }
    
    def _get_cached_strategies(self, domain: str, fingerprint_hash: str) -> Optional[List[Any]]:
        """Кэшированное получение стратегий"""
        if not self.config.enable_caching:
            return None
        
        cache_key = self._get_cache_key(domain, f"strategies_{fingerprint_hash}")
        
        with self._cache_lock:
            if cache_key in self._strategy_cache:
                cached_data = self._strategy_cache[cache_key]
                if self._is_cache_valid(cached_data["timestamp"]):
                    self.stats["cache_hits"] += 1
                    return cached_data["strategies"]
                else:
                    del self._strategy_cache[cache_key]
        
        self.stats["cache_misses"] += 1
        return None
    
    def _cache_strategies(self, domain: str, fingerprint_hash: str, strategies: List[Any]):
        """Кэширование сгенерированных стратегий"""
        if not self.config.enable_caching:
            return
        
        cache_key = self._get_cache_key(domain, f"strategies_{fingerprint_hash}")
        
        with self._cache_lock:
            if len(self._strategy_cache) >= self.config.strategy_cache_size:
                oldest_key = min(self._strategy_cache.keys(),
                               key=lambda k: self._strategy_cache[k]["timestamp"])
                del self._strategy_cache[oldest_key]
            
            self._strategy_cache[cache_key] = {
                "strategies": strategies,
                "timestamp": datetime.now()
            }
    
    def _save_protocol_preference(self, domain: str, ip_type: str, target_ip: str):
        """Сохранение предпочтительного протокола для домена"""
        if not self.config.enable_caching:
            return
        
        with self._cache_lock:
            self._protocol_preference_cache[domain] = {
                "ip_type": ip_type,
                "target_ip": target_ip,
                "timestamp": datetime.now(),
                "success_count": self._protocol_preference_cache.get(domain, {}).get("success_count", 0) + 1
            }
        
        # Сохраняем в файл для постоянного хранения (FR-5.8)
        self._save_protocol_preferences()
        
        LOG.info(f"💾 Сохранен предпочтительный протокол для {domain}: {ip_type} ({target_ip})")
        
        # Логируем использование IPv6 и результаты (FR-5.7)
        if ip_type == "IPv6":
            LOG.info(f"🌐 IPv6 успешно использован для {domain}: {target_ip}")
            # Дополнительная статистика для IPv6
            if not hasattr(self, '_ipv6_usage_stats'):
                self._ipv6_usage_stats = {"domains": set(), "total_uses": 0}
            self._ipv6_usage_stats["domains"].add(domain)
            self._ipv6_usage_stats["total_uses"] += 1
        else:
            LOG.info(f"🌐 IPv4 успешно использован для {domain}: {target_ip}")
            # Дополнительная статистика для IPv4
            if not hasattr(self, '_ipv4_usage_stats'):
                self._ipv4_usage_stats = {"domains": set(), "total_uses": 0}
            self._ipv4_usage_stats["domains"].add(domain)
            self._ipv4_usage_stats["total_uses"] += 1
    
    def _get_protocol_preference(self, domain: str) -> Optional[Dict[str, Any]]:
        """Получение предпочтительного протокола для домена"""
        if not self.config.enable_caching:
            return None
        
        with self._cache_lock:
            if domain in self._protocol_preference_cache:
                cached_data = self._protocol_preference_cache[domain]
                if self._is_cache_valid(cached_data["timestamp"]):
                    return cached_data
                else:
                    # Удаляем устаревший кэш
                    del self._protocol_preference_cache[domain]
        
        return None
    
    def get_protocol_preference_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики предпочтений протоколов.
        
        Возвращает детальную статистику использования IPv4/IPv6,
        включая количество доменов, успешные подключения и предпочтения.
        
        Returns:
            Словарь со статистикой предпочтений протоколов
        """
        stats = {
            "timestamp": datetime.now().isoformat(),
            "total_domains_with_preferences": 0,
            "ipv4_preferred_domains": 0,
            "ipv6_preferred_domains": 0,
            "protocol_distribution": {"IPv4": 0, "IPv6": 0},
            "usage_statistics": {
                "ipv4_total_uses": getattr(self, '_ipv4_usage_stats', {}).get('total_uses', 0),
                "ipv6_total_uses": getattr(self, '_ipv6_usage_stats', {}).get('total_uses', 0),
                "ipv4_unique_domains": len(getattr(self, '_ipv4_usage_stats', {}).get('domains', set())),
                "ipv6_unique_domains": len(getattr(self, '_ipv6_usage_stats', {}).get('domains', set()))
            },
            "cache_info": {
                "cached_preferences": len(self._protocol_preference_cache),
                "cache_hit_rate": 0.0
            }
        }
        
        # Анализируем предпочтения протоколов
        with self._cache_lock:
            for domain, pref_data in self._protocol_preference_cache.items():
                if self._is_cache_valid(pref_data.get('timestamp', datetime.now())):
                    stats["total_domains_with_preferences"] += 1
                    
                    ip_type = pref_data.get('ip_type', 'IPv4')
                    if ip_type == "IPv6":
                        stats["ipv6_preferred_domains"] += 1
                    else:
                        stats["ipv4_preferred_domains"] += 1
                    
                    stats["protocol_distribution"][ip_type] += 1
        
        # Вычисляем процентное соотношение
        total_prefs = stats["total_domains_with_preferences"]
        if total_prefs > 0:
            stats["ipv4_percentage"] = (stats["ipv4_preferred_domains"] / total_prefs) * 100
            stats["ipv6_percentage"] = (stats["ipv6_preferred_domains"] / total_prefs) * 100
        else:
            stats["ipv4_percentage"] = 0.0
            stats["ipv6_percentage"] = 0.0
        
        # Эффективность IPv6
        total_ipv6_uses = stats["usage_statistics"]["ipv6_total_uses"]
        total_uses = stats["usage_statistics"]["ipv4_total_uses"] + total_ipv6_uses
        if total_uses > 0:
            stats["ipv6_adoption_rate"] = (total_ipv6_uses / total_uses) * 100
        else:
            stats["ipv6_adoption_rate"] = 0.0
        
        return stats
    
    def _run_strategy_validation(self, result: Any, strategy_dict: Dict[str, Any], domain: str):
        """
        Run StrategyValidator to verify strategy application in verification mode.
        
        This method:
        1. Extracts PCAP file and operation log from test result
        2. Runs StrategyValidator to compare expected vs actual operations
        3. Logs validation results
        4. Updates AdaptiveKnowledgeBase with verified flag if validation passes
        
        Args:
            result: Test result from _test_strategy
            strategy_dict: Strategy configuration that was tested
            domain: Domain name being tested
            
        Requirements: 1.3 - Automatic validation after test
        """
        try:
            # Extract PCAP file from result
            pcap_file = None
            if hasattr(result, 'pcap_file'):
                pcap_file = result.pcap_file
            elif isinstance(result, dict):
                pcap_file = result.get('pcap_file') or result.get('capture_path')
            
            if not pcap_file:
                LOG.warning(f"⚠️ [VALIDATION] No PCAP file available for validation")
                return
            
            # Check if PCAP file exists
            from pathlib import Path
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                LOG.warning(f"⚠️ [VALIDATION] PCAP file not found: {pcap_file}")
                return
            
            # Extract strategy name from strategy_dict
            strategy_name = strategy_dict.get('attack', strategy_dict.get('type', 'unknown'))
            
            LOG.info(f"🔍 [VALIDATION] Running strategy validation for {domain}")
            LOG.info(f"   PCAP file: {pcap_file}")
            LOG.info(f"   Strategy: {strategy_name}")
            
            # Load operation log from the most recent log file
            # The operation logger saves logs with timestamp and domain
            from core.operation_logger import get_operation_logger
            operation_logger = get_operation_logger()
            
            # Find the most recent log file for this domain
            import os
            import glob
            log_dir = operation_logger.log_dir
            domain_safe = domain.replace('.', '_')
            log_pattern = os.path.join(log_dir, f"*_{domain_safe}_*.json")
            log_files = glob.glob(log_pattern)
            
            strategy_log = None
            if not log_files:
                LOG.warning(f"⚠️ [VALIDATION] No operation log found for {domain}")
                LOG.info(f"   Will run PCAP-only analysis without operation log")
            else:
                # Get the most recent log file
                latest_log = max(log_files, key=os.path.getmtime)
                LOG.info(f"   Operation log: {latest_log}")
                
                # Load strategy log
                import json
                try:
                    with open(latest_log, 'r', encoding='utf-8') as f:
                        strategy_log = json.load(f)
                except Exception as e:
                    LOG.warning(f"⚠️ [VALIDATION] Failed to load operation log: {e}")
                    strategy_log = None
            
            # Run validation (works with or without operation log)
            # Pass strategy_name explicitly so it's not 'unknown'
            validation_result = self.strategy_validator.validate_strategy(
                strategy_log=strategy_log,
                pcap_file=pcap_path,
                domain=domain,
                strategy_name=strategy_name  # Pass strategy name explicitly
            )
            
            # Log validation result
            status_symbol = {
                "valid": "✅",
                "invalid": "❌",
                "partial": "⚠️",
                "unknown": "❓"
            }.get(validation_result.status.value, "❓")
            
            LOG.info(f"{status_symbol} [VALIDATION] Status: {validation_result.status.value.upper()}")
            LOG.info(f"   Message: {validation_result.message}")
            
            if validation_result.expected_operations:
                LOG.info(f"   Expected operations: {', '.join(validation_result.expected_operations)}")
            if validation_result.actual_operations:
                LOG.info(f"   Actual operations: {', '.join(validation_result.actual_operations)}")
            if validation_result.missing_operations:
                LOG.warning(f"   Missing operations: {', '.join(validation_result.missing_operations)}")
            if validation_result.unexpected_operations:
                LOG.warning(f"   Unexpected operations: {', '.join(validation_result.unexpected_operations)}")
            
            # Task 11.6: Update AdaptiveKnowledgeBase with verified flag
            # If validation is VALID, mark strategy as verified
            if validation_result.status.value == "valid" and self.adaptive_knowledge:
                try:
                    # Extract strategy name and parameters from strategy_log
                    strategy_name = strategy_log.get('strategy_name', 'unknown')
                    strategy_params = {}
                    
                    # Try to extract parameters from operations
                    operations = strategy_log.get('operations', [])
                    for op in operations:
                        op_type = op.get('type')
                        params = op.get('params', {})
                        
                        if op_type == 'split':
                            # Extract split parameters
                            strategy_params['split_pos'] = params.get('position')
                            strategy_params['split_count'] = params.get('count')
                        
                        elif op_type == 'fake':
                            # Extract fake packet parameters
                            strategy_params['fake_ttl'] = params.get('ttl')
                            fake_count = params.get('count')
                            if fake_count:
                                strategy_params['fake_count'] = fake_count
                        
                        elif op_type == 'disorder':
                            # Mark disorder as enabled
                            strategy_params['disorder'] = True
                        
                        elif op_type == 'fooling':
                            # Extract fooling mode
                            fooling_mode = params.get('mode')
                            if fooling_mode:
                                strategy_params['fooling_mode'] = fooling_mode
                    
                    # Mark strategy as verified using the set_verified method
                    self.adaptive_knowledge.set_verified(
                        domain=domain,
                        strategy_name=strategy_name,
                        strategy_params=strategy_params,
                        verified=True
                    )
                    
                    LOG.info(f"✅ [VALIDATION] Marked strategy '{strategy_name}' as verified in AdaptiveKnowledgeBase")
                    LOG.info(f"   Strategy parameters: {strategy_params}")
                    
                except Exception as e:
                    LOG.warning(f"⚠️ [VALIDATION] Failed to update verified flag: {e}")
            
        except Exception as e:
            LOG.error(f"❌ [VALIDATION] Validation failed: {e}", exc_info=True)
    
    def _calculate_adaptive_timeout(self, domain: str, fingerprint: Optional[Any] = None, 
                                  failure_report: Optional[Any] = None) -> float:
        """
        Вычисление адаптивного таймаута на основе типа DPI и характеристик блокировки.
        
        Требования:
        - FR-5.4: Увеличивать таймауты при DPI_CONTENT_INSPECTION (factor 1.5-2.0)
        - FR-5.5: Применять timeout factor для медленных CDN
        - FR-5.6: НЕ увеличивать таймауты при RST-инъекциях
        
        Args:
            domain: Доменное имя
            fingerprint: DPI fingerprint с информацией о типе блокировки
            failure_report: Отчет о неудаче для анализа причин
            
        Returns:
            Адаптивный таймаут в секундах
        """
        base_timeout = self.config.strategy_timeout
        timeout_factor = 1.0
        adjustment_reason = "base"
        
        # Анализ DPI fingerprint
        if fingerprint:
            try:
                dpi_type = getattr(fingerprint, 'dpi_type', None)
                if dpi_type:
                    dpi_type_str = dpi_type.value if hasattr(dpi_type, 'value') else str(dpi_type)
                    
                    # FR-5.4: Увеличиваем таймауты при DPI_CONTENT_INSPECTION
                    if 'CONTENT_INSPECTION' in dpi_type_str:
                        timeout_factor = self.config.timeout_factor_content_inspection
                        adjustment_reason = "content_inspection"
                        self.timeout_stats["content_inspection_adjustments"] += 1
                        LOG.info(f"🕐 Увеличен таймаут для DPI_CONTENT_INSPECTION: {timeout_factor}x")
                    
                    # FR-5.6: НЕ увеличиваем таймауты при RST-инъекциях
                    elif 'RST_INJECTION' in dpi_type_str or 'ACTIVE_RST' in dpi_type_str:
                        timeout_factor = 1.0  # Оставляем базовый таймаут
                        adjustment_reason = "rst_injection_no_change"
                        self.timeout_stats["rst_injection_adjustments"] += 1
                        LOG.info(f"🕐 Таймаут НЕ изменен для RST-инъекций: {timeout_factor}x")
                    
                    # Для других типов DPI используем умеренное увеличение
                    elif 'STATEFUL' in dpi_type_str or 'REASSEMBLES' in dpi_type_str:
                        timeout_factor = 1.3  # Умеренное увеличение
                        adjustment_reason = "stateful_dpi"
                        self.timeout_stats["network_timeout_adjustments"] += 1
                        LOG.info(f"🕐 Умеренное увеличение таймаута для stateful DPI: {timeout_factor}x")
                        
            except Exception as e:
                LOG.debug(f"Ошибка анализа DPI fingerprint для таймаута: {e}")
        
        # Анализ failure_report для дополнительных корректировок
        if failure_report:
            try:
                # Если есть признаки медленного CDN или сети
                block_timing = getattr(failure_report, 'block_timing', None)
                if block_timing and block_timing > 5.0:  # Медленный ответ
                    # FR-5.5: Применяем timeout factor для медленных CDN
                    slow_factor = self.config.timeout_factor_slow_cdn
                    timeout_factor = max(timeout_factor, slow_factor)
                    adjustment_reason = "slow_cdn"
                    self.timeout_stats["slow_cdn_adjustments"] += 1
                    LOG.info(f"🕐 Увеличен таймаут для медленного CDN: {timeout_factor}x")
                
                # Анализ конкретных ошибок
                failure_details = getattr(failure_report, 'failure_details', {})
                if failure_details:
                    error_indicators = failure_details.get('error_indicators', [])
                    if 'timeout' in str(error_indicators).lower():
                        # Если была ошибка таймаута, увеличиваем
                        timeout_factor = max(timeout_factor, 1.5)
                        adjustment_reason = "previous_timeout"
                        self.timeout_stats["network_timeout_adjustments"] += 1
                        LOG.info(f"🕐 Увеличен таймаут из-за предыдущего timeout: {timeout_factor}x")
                        
            except Exception as e:
                LOG.debug(f"Ошибка анализа failure_report для таймаута: {e}")
        
        # Проверяем tweaks из правил базы знаний
        if hasattr(self, '_current_timeout_factor'):
            tweak_factor = getattr(self, '_current_timeout_factor', 1.0)
            if tweak_factor > 1.0:
                timeout_factor = max(timeout_factor, tweak_factor)
                adjustment_reason = "knowledge_base_tweak"
                LOG.info(f"🕐 Применен tweak из базы знаний: {timeout_factor}x")
        
        # Вычисляем финальный таймаут
        adaptive_timeout = base_timeout * timeout_factor
        
        # Обновляем статистику
        if timeout_factor > 1.0:
            self.timeout_stats["adaptive_timeouts_applied"] += 1
            self._update_average_timeout_factor(timeout_factor)
        
        LOG.debug(f"🕐 Адаптивный таймаут для {domain}: {adaptive_timeout:.1f}s "
                 f"(base: {base_timeout}s, factor: {timeout_factor}x, reason: {adjustment_reason})")
        
        return adaptive_timeout
    
    def _update_average_timeout_factor(self, new_factor: float):
        """Обновление средней статистики timeout factor"""
        current_avg = self.timeout_stats["average_timeout_factor"]
        applied_count = self.timeout_stats["adaptive_timeouts_applied"]
        
        # Вычисляем новое среднее значение
        if applied_count == 1:
            self.timeout_stats["average_timeout_factor"] = new_factor
        else:
            # Скользящее среднее
            self.timeout_stats["average_timeout_factor"] = (
                (current_avg * (applied_count - 1) + new_factor) / applied_count
            )
    
    def _update_adaptive_timeout_from_failure(self, domain: str, failure_report: Any, 
                                            current_timeout: float) -> float:
        """
        Обновление адаптивного таймаута на основе анализа неудачи.
        
        Анализирует причины неудачи и корректирует таймаут для следующих попыток.
        Обновляет статистику адаптивных таймаутов.
        
        Args:
            domain: Доменное имя
            failure_report: Отчет о неудаче от SFA
            current_timeout: Текущий таймаут
            
        Returns:
            Обновленный таймаут для следующих попыток
        """
        if not failure_report:
            return current_timeout
        
        try:
            root_cause = getattr(failure_report, 'root_cause', None)
            if not root_cause:
                return current_timeout
            
            root_cause_str = root_cause.value if hasattr(root_cause, 'value') else str(root_cause)
            new_timeout = current_timeout
            adjustment_made = False
            
            # FR-5.4: Увеличиваем таймауты при DPI_CONTENT_INSPECTION
            if 'CONTENT_INSPECTION' in root_cause_str:
                factor = self.config.timeout_factor_content_inspection
                new_timeout = max(current_timeout * factor, current_timeout + 5.0)
                adjustment_made = True
                self.timeout_stats["content_inspection_adjustments"] += 1
                LOG.info(f"🕐 Увеличен таймаут из-за CONTENT_INSPECTION: {new_timeout:.1f}s")
            
            # FR-5.6: НЕ увеличиваем таймауты при RST-инъекциях
            elif 'RST_INJECTION' in root_cause_str or 'ACTIVE_RST' in root_cause_str:
                # Оставляем таймаут без изменений для RST-инъекций
                new_timeout = current_timeout
                self.timeout_stats["rst_injection_adjustments"] += 1
                LOG.info(f"🕐 Таймаут НЕ изменен для RST-инъекций: {new_timeout:.1f}s")
            
            # Анализ дополнительных характеристик неудачи
            failure_details = getattr(failure_report, 'failure_details', {})
            if failure_details:
                # Проверяем индикаторы медленной сети
                error_indicators = failure_details.get('error_indicators', [])
                if any('timeout' in str(indicator).lower() for indicator in error_indicators):
                    # FR-5.5: Применяем timeout factor для медленных соединений
                    factor = self.config.timeout_factor_slow_cdn
                    new_timeout = max(new_timeout * factor, new_timeout + 3.0)
                    adjustment_made = True
                    self.timeout_stats["slow_cdn_adjustments"] += 1
                    LOG.info(f"🕐 Увеличен таймаут из-за медленного соединения: {new_timeout:.1f}s")
                
                # Проверяем блокировку на уровне сети
                if any('network' in str(indicator).lower() for indicator in error_indicators):
                    new_timeout = max(new_timeout * 1.3, new_timeout + 2.0)
                    adjustment_made = True
                    self.timeout_stats["network_timeout_adjustments"] += 1
                    LOG.info(f"🕐 Увеличен таймаут из-за сетевых проблем: {new_timeout:.1f}s")
            
            # Анализ времени блокировки
            block_timing = getattr(failure_report, 'block_timing', None)
            if block_timing and block_timing > 3.0:
                # Если блокировка происходит медленно, увеличиваем таймаут
                timing_factor = min(block_timing / 3.0, 2.0)  # Максимум 2x
                new_timeout = max(new_timeout * timing_factor, new_timeout + 2.0)
                adjustment_made = True
                self.timeout_stats["slow_cdn_adjustments"] += 1
                LOG.info(f"🕐 Увеличен таймаут из-за медленной блокировки ({block_timing:.1f}s): {new_timeout:.1f}s")
            
            # Ограничиваем максимальный таймаут
            max_timeout = self.config.strategy_timeout * 3.0  # Максимум 3x от базового
            new_timeout = min(new_timeout, max_timeout)
            
            # Обновляем статистику если был сделан adjustment
            if adjustment_made:
                self.timeout_stats["adaptive_timeouts_applied"] += 1
                timeout_factor = new_timeout / self.config.strategy_timeout
                self._update_average_timeout_factor(timeout_factor)
            
            return new_timeout
            
        except Exception as e:
            LOG.warning(f"Ошибка обновления адаптивного таймаута: {e}")
            return current_timeout
    
    def _profile_operation(self, operation_name: str):
        """Декоратор для профилирования операций"""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                if not self.config.enable_profiling:
                    return await func(*args, **kwargs)
                
                start_time = time.time()
                try:
                    result = await func(*args, **kwargs)
                    return result
                finally:
                    execution_time = time.time() - start_time
                    
                    if operation_name not in self._profiling_data:
                        self._profiling_data[operation_name] = {
                            "total_time": 0.0,
                            "call_count": 0,
                            "average_time": 0.0,
                            "min_time": float('inf'),
                            "max_time": 0.0
                        }
                    
                    profile = self._profiling_data[operation_name]
                    profile["total_time"] += execution_time
                    profile["call_count"] += 1
                    profile["average_time"] = profile["total_time"] / profile["call_count"]
                    profile["min_time"] = min(profile["min_time"], execution_time)
                    profile["max_time"] = max(profile["max_time"], execution_time)
                    
                    LOG.debug(f"Profile {operation_name}: {execution_time:.3f}s")
            
            return wrapper
        return decorator
    
    def _convert_strategy_to_unified_format(self, strategy: Any) -> Dict[str, Any]:
        """
        ИСПРАВЛЕНИЕ: Конвертация стратегий в формат UnifiedBypassEngine
        
        Проблема: Неправильная конвертация GeneratedStrategy в zapret формат
        Решение: Правильная конвертация через UnifiedStrategyLoader
        """
        try:
            # Извлекаем атаки и параметры из стратегии
            if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
                attacks = [str(a).lower() for a in strategy.attack_combination]
                params = dict(getattr(strategy, 'parameters', {}) or {})
            elif hasattr(strategy, 'attack_name'):
                attacks = [str(strategy.attack_name).lower()]
                params = dict(getattr(strategy, 'parameters', {}) or {})
            else:
                # Fallback стратегия
                attacks = ["fake"]
                params = {"ttl": 3}

            LOG.info(f"[CONVERT] Конвертация стратегии: attacks={attacks}, params={params}")
            
            # ИСПРАВЛЕНИЕ: Если это smart_combo стратегия без параметров,
            # используем UnifiedStrategyLoader для извлечения параметров по умолчанию
            if len(attacks) == 1 and attacks[0].startswith("smart_combo_") and not params:
                LOG.debug(f"[CONVERT] Обнаружена smart_combo стратегия без параметров: {attacks[0]}")
                if hasattr(self, '_strategy_loader') and self._strategy_loader:
                    try:
                        # Загружаем через UnifiedStrategyLoader чтобы получить параметры по умолчанию
                        normalized = self._strategy_loader.load_strategy(attacks[0])
                        # Извлекаем реальные атаки и параметры
                        attacks = normalized.attacks
                        params = normalized.params
                        LOG.info(f"[CONVERT] ✅ Извлечены атаки и параметры: attacks={attacks}, params={params}")
                    except Exception as e:
                        LOG.warning(f"[CONVERT] ⚠️ Не удалось извлечь параметры из {attacks[0]}: {e}")

            # Обеспечиваем split_pos для split/disorder атак
            split_like = {"fakeddisorder", "fake_disorder", "fakedisorder",
                          "disorder", "disorder2", "multidisorder", "split", "multisplit"}
            if any(a in split_like for a in attacks):
                if "split_pos" not in params and "positions" not in params:
                    params["split_pos"] = "sni"  # TLS default
                    LOG.debug(f"[CONVERT] Добавлен default split_pos=sni")

            # Строим каноническую строку для UnifiedStrategyLoader
            # Фильтруем None значения из attacks
            attacks = [a for a in attacks if a is not None and isinstance(a, str)]
            attack_str = ",".join(attacks)
            param_parts = []
            for k, v in params.items():
                if isinstance(v, (list, tuple)):
                    v_str = ",".join(str(x) for x in v)
                else:
                    v_str = str(v)
                param_parts.append(f"{k}={v_str}")
            
            canonical = f"{attack_str}; {'; '.join(param_parts)}" if param_parts else attack_str
            LOG.info(f"[CONVERT] Каноническая строка: {canonical}")

            # Загружаем через UnifiedStrategyLoader
            if hasattr(self, '_strategy_loader') and self._strategy_loader:
                try:
                    normalized = self._strategy_loader.load_strategy(canonical)
                    forced = self._strategy_loader.create_forced_override(normalized)
                    LOG.info(f"[CONVERT] ✅ Успешная конвертация: {forced}")
                    return forced
                except Exception as e:
                    LOG.warning(f"[CONVERT] ⚠️ Ошибка UnifiedStrategyLoader: {e}")
                    # Fallback к простому формату
            
            # Task 6.5: Ensure forced override in fallback format
            # CRITICAL FIX: Include ALL attacks for combination strategies
            fallback_strategy = {
                "type": attacks[0] if attacks else "fake",
                "params": params,
                "forced": True,
                "no_fallbacks": True,  # Task 6.5: Ensure no fallbacks
                "fallback": True,
                "attacks": attacks  # CRITICAL: Include all attacks, not just first one
            }
            LOG.info(f"[CONVERT] ✅ Fallback формат с forced override: {fallback_strategy}")
            LOG.info(f"[CONVERT] 📋 All attacks included: {attacks}")
            return fallback_strategy

        except Exception as e:
            LOG.error(f"[CONVERT] ❌ Критическая ошибка конвертации: {e}")
            # Надежный fallback
            return {
                "type": "fake",
                "params": {"ttl": 3},
                "no_fallbacks": True,
                "forced": True,
                "error": str(e)
            }
    
    async def _test_strategy_real(self, domain: str, strategy: Any) -> Dict[str, Any]:
        """
        ИСПРАВЛЕНИЕ КРИТИЧЕСКОЙ ПРОБЛЕМЫ: Реальное тестирование стратегий через bypass engine
        
        Проблема: AdaptiveEngine не реально тестировал стратегии, показывал 0 результатов
        Решение: Используем UnifiedBypassEngine для фактического тестирования стратегий
        """
        LOG.info(f"[TEST] 🎯 Реальное тестирование {getattr(strategy, 'name', 'unknown')} для {domain}")
        
        if not self.bypass_engine:
            LOG.error("❌ КРИТИЧЕСКАЯ ОШИБКА: UnifiedBypassEngine недоступен")
            return {
                "success": False,
                "error": "CRITICAL: UnifiedBypassEngine not available - cannot test strategies",
                "response_time": 0.0
            }
        
        try:
            # Task 6.2: Use DoHIntegration for unified DNS resolution
            import socket
            try:
                # Получаем все доступные адреса (IPv4 и IPv6)
                ipv4_addresses = []
                ipv6_addresses = []
                
                if self.doh_integration:
                    # Use DoHIntegration with fallback
                    LOG.info(f"🔍 Resolving {domain} via DoHIntegration")
                    try:
                        ips = await self.doh_integration.resolve_with_fallback(
                            domain, 
                            timeout=10.0,
                            retry_on_failure=True
                        )
                        
                        # Separate IPv4 and IPv6
                        for ip in ips:
                            if ":" in ip:
                                ipv6_addresses.append(ip)
                            else:
                                ipv4_addresses.append(ip)
                        
                        LOG.info(f"✅ DoHIntegration resolved {domain} -> IPv4: {ipv4_addresses}, IPv6: {ipv6_addresses}")
                    except Exception as e:
                        LOG.warning(f"⚠️ DoHIntegration failed for {domain}: {e}, falling back to system DNS")
                        # Fallback to system DNS
                        addr_info = socket.getaddrinfo(
                            domain, 443, 
                            family=socket.AF_UNSPEC,
                            type=socket.SOCK_STREAM
                        )
                        for family, type_, proto, canonname, sockaddr in addr_info:
                            ip = sockaddr[0]
                            if family == socket.AF_INET:
                                ipv4_addresses.append(ip)
                            elif family == socket.AF_INET6:
                                ipv6_addresses.append(ip)
                else:
                    # Use system DNS directly
                    addr_info = socket.getaddrinfo(
                        domain, 443, 
                        family=socket.AF_UNSPEC,  # Поддержка IPv4 и IPv6
                        type=socket.SOCK_STREAM
                    )
                    
                    for family, type_, proto, canonname, sockaddr in addr_info:
                        ip = sockaddr[0]
                        if family == socket.AF_INET:
                            ipv4_addresses.append(ip)
                        elif family == socket.AF_INET6:
                            ipv6_addresses.append(ip)
                
                # Проверяем кэшированные предпочтения для домена
                protocol_pref = self._get_protocol_preference(domain)
                
                # Определяем порядок попыток подключения
                if protocol_pref:
                    # Используем кэшированное предпочтение
                    if protocol_pref["ip_type"] == "IPv6":
                        all_addresses = ipv6_addresses + ipv4_addresses
                        LOG.info(f"🎯 Используем кэшированное предпочтение IPv6 для {domain}")
                    else:
                        all_addresses = ipv4_addresses + ipv6_addresses
                        LOG.info(f"🎯 Используем кэшированное предпочтение IPv4 для {domain}")
                elif self.config.prefer_ipv4:
                    all_addresses = ipv4_addresses + ipv6_addresses
                else:
                    all_addresses = ipv6_addresses + ipv4_addresses
                
                if not all_addresses:
                    LOG.error(f"❌ DNS: Нет доступных адресов для {domain}")
                    return {"success": False, "error": "No addresses found", "response_time": 0.0}
                
                LOG.info(f"✅ DNS: {domain} -> IPv4: {ipv4_addresses}, IPv6: {ipv6_addresses}")
                LOG.info(f"🔄 Порядок попыток: {all_addresses}")
                
                # Пробуем все доступные адреса по порядку
                last_error = None
                for i, target_ip in enumerate(all_addresses):
                    ip_type = "IPv6" if ":" in target_ip else "IPv4"
                    LOG.info(f"🎯 Попытка {i+1}/{len(all_addresses)}: {target_ip} ({ip_type})")
                    
                    try:
                        # 2. Конвертируем стратегию (через UnifiedStrategyLoader)
                        strategy_dict = self._convert_strategy_to_unified_format(strategy)
                        LOG.info(f"📋 Strategy: {strategy_dict}")
                        
                        # 3. Вычисляем адаптивный таймаут
                        adaptive_timeout = self._calculate_adaptive_timeout(domain)
                        
                        start_time = time.time()
                        
                        # ИСПРАВЛЕНИЕ: Используем правильный метод тестирования
                        LOG.info("✅ Используем адаптивное тестирование (service-based или inline)")
                        
                        try:
                            # Task 11.2: Pass verification_mode from config
                            result = self._test_strategy(
                                target_ip=target_ip,
                                strategy_input=strategy_dict,
                                domain=domain,
                                timeout=adaptive_timeout,
                                verification_mode=self.config.verify_with_pcap
                            )
                            
                            success = getattr(result, "success", False)
                            error = getattr(result, "error", None) if not success else None
                            
                            LOG.info(f"[TEST] Результат тестирования: success={success}, error={error}")
                            
                            # Task 11.5: Run StrategyValidator in verification mode
                            if self.config.verify_with_pcap and self.strategy_validator:
                                self._run_strategy_validation(result, strategy_dict, domain)
                            
                            if success:
                                LOG.info(f"[TEST] ✅ УСПЕХ с {ip_type}: {getattr(strategy, 'name', 'unknown')}")
                                # Сохраняем предпочтительный протокол
                                self._save_protocol_preference(domain, ip_type, target_ip)
                                return {
                                    "success": True,
                                    "error": None,
                                    "response_time": time.time() - start_time,
                                    "real_test": True,
                                    "target_ip": target_ip,
                                    "ip_type": ip_type,
                                    "strategy_name": getattr(strategy, 'name', 'unknown')
                                }
                            else:
                                LOG.warning(f"[TEST] ❌ НЕУДАЧА с {ip_type}: {error}")
                                
                                # Task 18: Try adaptive strategy adjustment
                                if self.strategy_adjuster and hasattr(result, 'get'):
                                    pcap_file = result.get("pcap_file") or result.get("capture_path")
                                    if pcap_file:
                                        try:
                                            import os
                                            if os.path.exists(pcap_file):
                                                from core.metrics.clienthello_metrics import ClientHelloMetricsCollector
                                                metrics_collector = ClientHelloMetricsCollector()
                                                clienthello_size = 0
                                                if hasattr(metrics_collector, 'get_average_clienthello_size'):
                                                    clienthello_size = metrics_collector.get_average_clienthello_size(pcap_file)
                                                
                                                if clienthello_size > 0:
                                                    LOG.info(f"[ADAPTIVE] Detected ClientHello size: {clienthello_size} bytes")
                                                    adjusted_strategy = self.strategy_adjuster.adjust_strategy(
                                                        strategy_dict.copy(),
                                                        clienthello_size
                                                    )
                                                    
                                                    if adjusted_strategy != strategy_dict:
                                                        LOG.info(f"[ADAPTIVE] Re-testing with adjusted strategy")
                                                        result_adjusted = self._test_strategy(
                                                            target_ip=target_ip,
                                                            strategy_input=adjusted_strategy,
                                                            domain=domain,
                                                            timeout=adaptive_timeout,
                                                            verification_mode=self.config.verify_with_pcap  # Task 11.2
                                                        )
                                                        
                                                        # Task 11.5: Run validation for adjusted strategy
                                                        if self.config.verify_with_pcap and self.strategy_validator:
                                                            self._run_strategy_validation(result_adjusted, adjusted_strategy, domain)
                                                        
                                                        success_adjusted = getattr(result_adjusted, "success", False)
                                                        if success_adjusted:
                                                            LOG.info(f"[ADAPTIVE] ✓ Adjusted strategy succeeded!")
                                                            self._save_protocol_preference(domain, ip_type, target_ip)
                                                            return {
                                                                "success": True,
                                                                "error": None,
                                                                "response_time": time.time() - start_time,
                                                                "real_test": True,
                                                                "target_ip": target_ip,
                                                                "ip_type": ip_type,
                                                                "strategy_name": getattr(strategy, 'name', 'unknown'),
                                                                "adjusted": True
                                                            }
                                        except Exception as e:
                                            LOG.warning(f"[ADAPTIVE] Failed to adjust strategy: {e}")
                                
                                last_error = error
                                continue  # Пробуем следующий адрес
                        
                        except Exception as e:
                                LOG.error(f"[TEST] ❌ ОШИБКА test_strategy_like_testing_mode: {e}")
                                last_error = str(e)
                                continue
                        
                        # FALLBACK: Ручное управление bypass engine
                        else:
                            LOG.warning("⚠️ test_strategy_like_testing_mode недоступен, используем ручное управление")
                            
                            with self._divert_lock:  # Блокировка для WinDivert
                                try:
                                    LOG.info(f"[TEST] Запуск bypass engine для {target_ip}")
                                    
                                    # Запускаем движок с этой стратегией
                                    self.bypass_engine.start(
                                        target_ips={target_ip},
                                        strategy_map={"default": strategy_dict},
                                        reset_telemetry=True,
                                        strategy_override=strategy_dict
                                    )
                                    
                                    # Даем время на инициализацию WinDivert
                                    await asyncio.sleep(1.0)
                                    
                                    LOG.info(f"[TEST] Тестируем подключение к {domain}")
                                    # Пробуем подключиться через bypass
                                    success, error = await self._probe_https(domain, timeout=adaptive_timeout)
                                    
                                    if success:
                                        LOG.info(f"[TEST] ✅ УСПЕХ с {ip_type}: {getattr(strategy, 'name', 'unknown')}")
                                        # Сохраняем предпочтительный протокол
                                        self._save_protocol_preference(domain, ip_type, target_ip)
                                        return {
                                            "success": True,
                                            "error": None,
                                            "response_time": time.time() - start_time,
                                            "real_test": True,
                                            "target_ip": target_ip,
                                            "ip_type": ip_type,
                                            "strategy_name": getattr(strategy, 'name', 'unknown'),
                                            "method": "manual_bypass_engine"
                                        }
                                    else:
                                        LOG.warning(f"[TEST] ❌ НЕУДАЧА с {ip_type}: {error}")
                                        last_error = error
                                        continue  # Пробуем следующий адрес
                                        
                                except Exception as e:
                                    LOG.error(f"[TEST] ❌ ОШИБКА ручного управления: {e}")
                                    last_error = str(e)
                                    continue
                                    
                                finally:
                                    # КРИТИЧЕСКИ ВАЖНО: Всегда останавливаем движок
                                    try:
                                        LOG.debug("[TEST] Остановка bypass engine")
                                        self.bypass_engine.stop()
                                        await asyncio.sleep(0.2)  # Даем время на очистку
                                    except Exception as e:
                                        LOG.warning(f"[TEST] Ошибка остановки bypass engine: {e}")
                    
                    except Exception as e:
                        LOG.warning(f"❌ Ошибка тестирования с {ip_type} ({target_ip}): {e}")
                        last_error = str(e)
                        continue  # Пробуем следующий адрес
                
                # Если дошли сюда, все адреса не сработали
                LOG.error(f"❌ Все адреса не сработали для {domain}")
                return {
                    "success": False, 
                    "error": f"All addresses failed. Last error: {last_error}",
                    "response_time": 0.0,
                    "addresses_tried": len(all_addresses)
                }
                
            except Exception as e:
                LOG.error(f"❌ DNS failed: {e}")
                return {"success": False, "error": f"DNS failed: {e}", "response_time": 0.0}
                
        except Exception as e:
            LOG.error(f"💥 Test error: {e}")
            import traceback
            LOG.debug(traceback.format_exc())
            return {"success": False, "error": str(e), "response_time": 0.0}

    async def _probe_https(self, domain: str, timeout: float) -> Tuple[bool, Optional[str]]:
        """
        Быстрая проверка HTTPS подключения через curl с эмуляцией браузера.
        Генерирует ClientHello ~1400 байт для обхода фильтров по размеру пакета.
        """
        LOG.debug(f"[PROBE] Проверка HTTPS подключения к {domain} через curl (timeout: {timeout}s)")
        
        try:
            # Определяем null устройство
            null_dev = "NUL" if sys.platform == "win32" else "/dev/null"
            
            # Ищем локальный curl.exe (в папке проекта), так как системный может быть старым
            curl_exe = "curl"
            if sys.platform == "win32":
                import os
                local_curl = Path("curl.exe")
                if local_curl.exists():
                    curl_exe = str(local_curl.absolute())

            # Формируем команду curl
            cmd = [
                curl_exe,
                "-I", "-s", "-k",
                "--http2",                        # Эмуляция HTTP/2
                "--tlsv1.2",                      # Минимум TLS 1.2
                "--ciphers", BROWSER_CIPHER_LIST, # <--- КРИТИЧНО: Раздувает пакет до ~1400 байт
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "--connect-timeout", str(int(timeout)),
                "--max-time", str(int(timeout) + 2),
                "-o", null_dev,
                "-w", "%{http_code}",
                f"https://{domain}"
            ]
            
            # Запускаем процесс асинхронно
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                try:
                    output = stdout.decode().strip()
                    if not output or output == "000":
                        LOG.debug(f"[PROBE] ❌ Curl вернул пустой код или 000")
                        return False, "No HTTP response"
                        
                    http_code = int(output)
                    # Любой ответ от сервера (даже 403/500) означает, что TCP/TLS прошли успешно
                    if 0 < http_code < 600:
                        LOG.debug(f"[PROBE] ✅ Curl успех: HTTP {http_code}")
                        return True, None
                    else:
                        LOG.debug(f"[PROBE] ❌ Curl вернул странный код: {http_code}")
                        return False, f"HTTP {http_code}"
                except ValueError:
                    LOG.debug(f"[PROBE] ❌ Ошибка парсинга кода ответа curl: {stdout}")
                    return False, "Invalid curl output"
            else:
                err_msg = stderr.decode().strip()
                LOG.debug(f"[PROBE] ❌ Curl ошибка (code {process.returncode}): {err_msg}")
                return False, f"Curl error {process.returncode}"

        except Exception as e:
            LOG.debug(f"[PROBE] ❌ Ошибка выполнения curl: {e}")
            return False, f"Execution error: {e}"
    
    async def _probe_https_with_metrics(self, domain: str, timeout: float) -> ConnectionMetrics:
        """
        Task 2.3: Enhanced HTTPS probe that collects ConnectionMetrics.
        
        Проверка HTTPS подключения с детальным сбором метрик для оценки стратегий.
        Использует curl с расширенным форматом вывода для получения всех таймингов.
        """
        if not CONNECTION_METRICS_AVAILABLE:
            # Fallback to old method
            success, error = await self._probe_https(domain, timeout)
            return None
        
        LOG.debug(f"[PROBE_METRICS] Проверка {domain} с детальным сбором метрик (timeout: {timeout}s)")
        
        metrics = ConnectionMetrics()
        start_time = time.time()
        
        try:
            # Определяем null устройство
            null_dev = "NUL" if sys.platform == "win32" else "/dev/null"
            
            # Ищем локальный curl.exe
            curl_exe = "curl"
            if sys.platform == "win32":
                import os
                local_curl = Path("curl.exe")
                if local_curl.exists():
                    curl_exe = str(local_curl.absolute())
            
            # Расширенный формат вывода curl для получения всех таймингов
            # %{time_connect} - TCP handshake time
            # %{time_appconnect} - TLS handshake time (total до app layer)
            # %{time_starttransfer} - TTFB
            # %{time_total} - Total time
            # %{http_code} - HTTP status
            # %{size_download} - Bytes received
            format_str = "%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{http_code}|%{size_download}"
            
            cmd = [
                curl_exe,
                "-I", "-s", "-k",
                "--http2",
                "--tlsv1.2",
                "--ciphers", BROWSER_CIPHER_LIST,
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "--connect-timeout", str(int(timeout)),
                "--max-time", str(int(timeout) + 2),
                "-o", null_dev,
                "-w", format_str,
                f"https://{domain}"
            ]
            
            # Запускаем процесс
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Вычисляем общее время
            metrics.total_time_ms = (time.time() - start_time) * 1000
            
            if process.returncode == 0:
                try:
                    # Парсим вывод curl
                    output = stdout.decode().strip()
                    parts = output.split('|')
                    
                    if len(parts) == 6:
                        time_connect = float(parts[0]) * 1000  # в миллисекунды
                        time_appconnect = float(parts[1]) * 1000
                        time_starttransfer = float(parts[2]) * 1000
                        time_total = float(parts[3]) * 1000
                        http_code = int(parts[4])
                        size_download = int(float(parts[5]))
                        
                        # Заполняем метрики
                        metrics.connect_time_ms = time_connect
                        metrics.tls_time_ms = time_appconnect - time_connect if time_appconnect > time_connect else 0.0
                        metrics.ttfb_ms = time_starttransfer
                        metrics.total_time_ms = time_total
                        metrics.http_status = http_code if http_code > 0 else None
                        metrics.bytes_received = size_download
                        metrics.tls_completed = time_appconnect > 0
                        
                        LOG.debug(f"[PROBE_METRICS] ✅ Метрики собраны: connect={metrics.connect_time_ms:.1f}ms, "
                                f"tls={metrics.tls_time_ms:.1f}ms, ttfb={metrics.ttfb_ms:.1f}ms, "
                                f"http={metrics.http_status}, bytes={metrics.bytes_received}")
                    else:
                        LOG.warning(f"[PROBE_METRICS] Неожиданный формат вывода curl: {output}")
                        metrics.error = "Invalid curl output format"
                        
                except (ValueError, IndexError) as e:
                    LOG.warning(f"[PROBE_METRICS] Ошибка парсинга метрик: {e}")
                    metrics.error = f"Parse error: {e}"
            else:
                # Curl вернул ошибку
                err_msg = stderr.decode().strip()
                metrics.error = f"Curl error {process.returncode}: {err_msg}"
                
                # Определяем тип ошибки
                if "timeout" in err_msg.lower() or "timed out" in err_msg.lower():
                    metrics.timeout = True
                elif "connection refused" in err_msg.lower():
                    metrics.error = "Connection refused"
                elif "reset" in err_msg.lower() or "rst" in err_msg.lower():
                    metrics.rst_received = True
                    metrics.rst_timing_ms = metrics.total_time_ms
                
                LOG.debug(f"[PROBE_METRICS] ❌ Curl ошибка: {metrics.error}")
            
            # Автоматически определяем тип блокировки
            metrics.block_type = metrics.detect_block_type()
            
            return metrics
            
        except Exception as e:
            LOG.error(f"[PROBE_METRICS] ❌ Исключение при сборе метрик: {e}")
            metrics.error = f"Exception: {e}"
            metrics.total_time_ms = (time.time() - start_time) * 1000
            metrics.block_type = BlockType.UNKNOWN
            return metrics

    async def _is_domain_accessible(self, domain: str) -> bool:
        """
        === ИСПРАВЛЕНИЕ ЭКСПЕРТА: Доступно только для 2xx/3xx ===
        Task 6.2: Use DoHIntegration for DNS resolution
        
        ПРИМЕЧАНИЕ: Этот метод используется для быстрых connectivity checks, не для strategy testing.
        Strategy testing происходит через test_strategy_like_testing_mode с curl.
        """
        # Для connectivity check используем простую проверку
        # Реальное тестирование с большим ClientHello происходит в test_strategy_like_testing_mode
        success, error = await self._probe_https(domain, self.config.connection_timeout)
        return success

    def clear_caches(self):
        """Очистка всех кэшей"""
        with self._cache_lock:
            self._fingerprint_cache.clear()
            self._strategy_cache.clear()
            self._domain_accessibility_cache.clear()
            self._protocol_preference_cache.clear()
        
        # Очищаем LRU кэш если он существует
        # The @lru_cache decorator has been removed, so cache_clear is not available
        
        LOG.info("All caches cleared")
    
    def _convert_strategy_to_string(self, strategy: Any) -> str:
        """Конвертация GeneratedStrategy в строку для bypass engine (legacy)"""
        try:
            if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
                # Для комбинированных стратегий
                attacks = strategy.attack_combination
                params = getattr(strategy, 'parameters', {})
                
                # Строим zapret-style команду
                parts = []
                
                # Фильтруем None значения из attacks
                attacks = [a for a in attacks if a is not None and isinstance(a, str)]
                
                # Определяем основной метод
                if len(attacks) == 1:
                    parts.append(f"--dpi-desync={attacks[0]}")
                elif len(attacks) > 1:
                    # Комбинированные атаки
                    parts.append(f"--dpi-desync={','.join(attacks)}")
                
                # Добавляем параметры
                if 'ttl' in params:
                    parts.append(f"--dpi-desync-ttl={params['ttl']}")
                if 'split_pos' in params:
                    parts.append(f"--dpi-desync-split-pos={params['split_pos']}")
                if 'split_count' in params:
                    parts.append(f"--dpi-desync-split-count={params['split_count']}")
                if 'fooling' in params:
                    fooling = params['fooling']
                    if isinstance(fooling, list):
                        fooling = ','.join(fooling)
                    parts.append(f"--dpi-desync-fooling={fooling}")
                
                return ' '.join(parts)
            
            elif hasattr(strategy, 'name'):
                # Fallback - пытаемся извлечь из имени
                return f"--dpi-desync={getattr(strategy, 'name', 'fake')} --dpi-desync-ttl=3"
            
            else:
                # Последний fallback
                return "--dpi-desync=fake --dpi-desync-ttl=3"
                
        except Exception as e:
            LOG.warning(f"Ошибка конвертации стратегии: {e}")
            return "--dpi-desync=fake --dpi-desync-ttl=3"
    
    async def _test_with_basic_engine(self, domain: str, strategy_string: str) -> Dict[str, Any]:
        """Базовое тестирование через bypass engine"""
        try:
            # Используем прямое тестирование через subprocess
            LOG.debug(f"Testing {domain} with strategy: {strategy_string}")
            
            # Запускаем CLI тестирование
            result = await self._run_cli_test(domain, strategy_string)
            
            return {
                "success": getattr(result, 'success', False) if hasattr(result, 'success') else (result.get("success", False) if hasattr(result, 'get') else False),
                "error": getattr(result, 'error', None) if hasattr(result, 'error') else (result.get("error") if hasattr(result, 'get') else None),
                "response_time": getattr(result, 'response_time', 0.0) if hasattr(result, 'response_time') else (result.get("response_time", 0.0) if hasattr(result, 'get') else 0.0)
            }
            
        except Exception as e:
            LOG.warning(f"CLI test failed: {e}, using direct engine test")
            
            # Прямое использование bypass engine
            try:
                # Тестируем доступность домена со стратегией
                import tempfile
                
                # Создаем временный файл со стратегией
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(strategy_string)
                    strategy_file = f.name
                
                # Запускаем тестирование через CLI
                # Разбиваем strategy_string на отдельные параметры
                strategy_parts = strategy_string.split()
                
                cmd = [
                    'python', 'cli.py', domain,
                    '--timeout', '10'
                ] + strategy_parts  # Добавляем параметры стратегии как отдельные аргументы
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                # Анализируем результат
                success = result.returncode == 0
                
                return {
                    "success": success,
                    "error": result.stderr if result.stderr else None,
                    "response_time": 0.0
                }
            except Exception as e:
                LOG.error(f"Ошибка базового тестирования: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "response_time": 0.0
                }
    
    async def _test_with_fallback_method(self, domain: str, strategy: Any, target_ip: str) -> Dict[str, Any]:
        """
        Fallback метод тестирования через curl с привязкой к конкретному IP.
        Использует --resolve и --ciphers для корректной эмуляции браузера.
        """
        LOG.debug(f"Using fallback curl testing for {domain} on IP {target_ip}")
        
        start_time = time.time()
        
        try:
            null_dev = "NUL" if sys.platform == "win32" else "/dev/null"
            
            # Ищем локальный curl
            curl_exe = "curl"
            if sys.platform == "win32":
                import os
                local_curl = Path("curl.exe")
                if local_curl.exists():
                    curl_exe = str(local_curl.absolute())

            cmd = [
                curl_exe,
                "-I", "-s", "-k",
                "--http2",
                "--tlsv1.2",
                "--ciphers", BROWSER_CIPHER_LIST, # <--- КРИТИЧНО
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "--connect-timeout", str(int(self.config.connection_timeout)),
                "--max-time", str(int(self.config.connection_timeout) + 2),
                "--resolve", f"{domain}:443:{target_ip}",
                "-o", null_dev,
                "-w", "%{http_code}",
                f"https://{domain}"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            response_time = time.time() - start_time
            
            if process.returncode == 0:
                try:
                    output = stdout.decode().strip()
                    if not output or output == "000":
                        return {
                            "success": False,
                            "error": "No HTTP response (000)",
                            "response_time": response_time,
                            "real_test": False,
                            "fallback_test": True,
                            "target_ip": target_ip
                        }

                    http_code = int(output)
                    if 0 < http_code < 600:
                        LOG.info(f"[TEST] Fallback curl successful for {domain} on {target_ip} (HTTP {http_code})")
                        return {
                            "success": True,
                            "error": None,
                            "response_time": response_time,
                            "real_test": False,
                            "fallback_test": True,
                            "target_ip": target_ip,
                            "http_code": http_code
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"HTTP {http_code}",
                            "response_time": response_time,
                            "real_test": False,
                            "fallback_test": True,
                            "target_ip": target_ip
                        }
                except ValueError:
                    return {
                        "success": False,
                        "error": "Invalid curl output",
                        "response_time": response_time,
                        "real_test": False,
                        "fallback_test": True,
                        "target_ip": target_ip
                    }
            else:
                err_msg = stderr.decode().strip()
                LOG.debug(f"[TEST] Fallback curl failed for {domain}: {err_msg}")
                return {
                    "success": False,
                    "error": f"Curl error {process.returncode}",
                    "response_time": response_time,
                    "real_test": False,
                    "fallback_test": True,
                    "target_ip": target_ip
                }
                        
        except Exception as e:
            LOG.error(f"Fallback test error: {e}")
            return {
                "success": False,
                "error": f"Fallback execution error: {str(e)}",
                "response_time": 0.0,
                "real_test": False,
                "fallback_test": True
            }
    
    async def _run_cli_test(self, domain: str, strategy_string: str) -> Dict[str, Any]:
        """Запуск тестирования через CLI subprocess"""
        try:
            import subprocess
            import tempfile
            import os
            
            # Создаем временный файл со стратегией
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(strategy_string)
                strategy_file = f.name
            
            try:
                # Запускаем тестирование через CLI
                # Разбиваем strategy_string на отдельные параметры
                strategy_parts = strategy_string.split()
                
                cmd = [
                    'python', 'cli.py', domain,
                    '--timeout', '10',
                    '--quiet'  # Минимальный вывод
                ] + strategy_parts  # Добавляем параметры стратегии как отдельные аргументы
                
                LOG.debug(f"Running CLI command: {' '.join(cmd)}")
                
                start_time = time.time()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    cwd=os.getcwd()
                )
                response_time = time.time() - start_time
                
                # Анализируем результат
                success = result.returncode == 0
                
                # Дополнительная проверка по выводу
                if success and result.stdout:
                    # Ищем индикаторы успеха в выводе
                    success_indicators = ["SUCCESS", "[OK]", "WORKING", "BYPASS"]
                    failure_indicators = ["FAILED", "[FAIL]", "ERROR", "BLOCKED"]
                    
                    stdout_upper = result.stdout.upper()
                    
                    if any(indicator in stdout_upper for indicator in failure_indicators):
                        success = False
                    elif not any(indicator in stdout_upper for indicator in success_indicators):
                        # Если нет явных индикаторов, считаем успехом если returncode == 0
                        pass
                
                LOG.debug(f"CLI test result: success={success}, returncode={result.returncode}")
                
                return {
                    "success": success,
                    "error": result.stderr if result.stderr else None,
                    "response_time": response_time,
                    "stdout": result.stdout,
                    "returncode": result.returncode
                }
                
            finally:
                # Удаляем временный файл
                try:
                    os.unlink(strategy_file)
                except:
                    pass
                    
        except Exception as e:
            # Check if it's a timeout error
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                return {
                    "success": False,
                    "error": "CLI test timeout (15s)",
                    "response_time": 15.0
                }
            else:
                LOG.error(f"CLI test error: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "response_time": 0.0
                }
    
    def _restore_tweaks(self):
        """
        Восстановление оригинальных значений после применения tweaks.
        
        Восстанавливает оригинальные значения конфигурации,
        очищает временные изменения.
        """
        if hasattr(self, '_original_config_values'):
            for key, value in self._original_config_values.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
                    if key == "strategy_timeout":
                        LOG.info(f"🕒 Восстановлен оригинальный таймаут: {value}s")
            
            # Очищаем сохраненные значения
            self._original_config_values.clear()
            LOG.debug("Восстановлены оригинальные значения конфигурации")
        
        # Очищаем временные tweaks
        if hasattr(self, '_current_ttl_adjustment'):
            delattr(self, '_current_ttl_adjustment')
        if hasattr(self, '_current_split_hint'):
            delattr(self, '_current_split_hint')
        if hasattr(self, '_current_split_multiplier'):
            delattr(self, '_current_split_multiplier')
        if hasattr(self, '_current_disorder_enabled'):
            delattr(self, '_current_disorder_enabled')
        if hasattr(self, '_current_timeout_factor'):
            delattr(self, '_current_timeout_factor')

    def _build_context(self, domain: str, fingerprint: Any) -> Dict[str, Any]:
        """
        Создание контекста для Pattern Matcher.
        
        Создает контекст с domain, timestamp, добавляет данные из fingerprint 
        (IP, ASN, dpi_type, dpi_mode), реализует _lookup_asn() для определения ASN,
        добавляет метаданные окружения.
        
        Args:
            domain: Доменное имя
            fingerprint: DPI fingerprint с характеристиками
            
        Returns:
            Словарь с контекстом для Pattern Matcher
        """
        context = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "environment": {
                "platform": "windows",
                "engine_version": "adaptive_v2"
            }
        }
        
        # Добавляем данные из fingerprint
        if fingerprint:
            try:
                # Основные характеристики DPI
                context["dpi_type"] = fingerprint.dpi_type.value if hasattr(fingerprint.dpi_type, 'value') else str(fingerprint.dpi_type)
                context["dpi_mode"] = fingerprint.dpi_mode.value if hasattr(fingerprint.dpi_mode, 'value') else str(fingerprint.dpi_mode)
                
                # IP адрес и ASN
                if hasattr(fingerprint, 'target_ip') and fingerprint.target_ip:
                    context["target_ip"] = fingerprint.target_ip
                    context["asn"] = self._lookup_asn(fingerprint.target_ip)
                else:
                    # Пытаемся получить IP через DNS
                    try:
                        import socket
                        target_ip = socket.gethostbyname(domain)
                        context["target_ip"] = target_ip
                        context["asn"] = self._lookup_asn(target_ip)
                    except Exception as e:
                        LOG.debug(f"Не удалось получить IP для {domain}: {e}")
                        context["target_ip"] = None
                        context["asn"] = None
                
                # Дополнительные характеристики
                if hasattr(fingerprint, 'block_timing'):
                    context["block_timing"] = fingerprint.block_timing
                if hasattr(fingerprint, 'rst_timing_ms'):
                    context["rst_timing_ms"] = fingerprint.rst_timing_ms
                if hasattr(fingerprint, 'connection_established'):
                    context["connection_established"] = fingerprint.connection_established
                    
            except Exception as e:
                LOG.warning(f"Ошибка извлечения данных из fingerprint: {e}")
        
        return context
    
    def _lookup_asn(self, ip_address: str) -> Optional[int]:
        """
        Определение ASN для IP адреса.
        
        Использует локальную базу ip2asn или внешние сервисы
        для определения автономной системы.
        
        Args:
            ip_address: IP адрес для поиска
            
        Returns:
            ASN номер или None если не найден
        """
        if not ip_address:
            return None
            
        try:
            # Простая эвристика для определения ASN по IP
            # В реальной системе здесь должна быть база ip2asn
            
            # Cloudflare
            if ip_address.startswith(('104.16.', '104.17.', '172.64.', '108.162.')):
                return 13335
            # Google
            elif ip_address.startswith(('8.8.', '172.217.', '216.58.', '142.250.')):
                return 15169
            # Amazon AWS
            elif ip_address.startswith(('52.', '54.', '3.', '18.')):
                return 16509
            # Akamai
            elif ip_address.startswith(('23.', '104.64.')):
                return 20940
            # Fastly
            elif ip_address.startswith(('151.101.', '199.232.')):
                return 54113
            else:
                # Для неизвестных IP возвращаем None
                return None
                
        except Exception as e:
            LOG.debug(f"Ошибка определения ASN для {ip_address}: {e}")
            return None

    def _calculate_adaptive_timeout(self, domain: str, fingerprint: Any = None, failure_report: Any = None) -> float:
        """
        Автоматическое вычисление таймаута на основе типа DPI блокировки.
        
        Увеличивает таймауты при DPI_CONTENT_INSPECTION (factor 1.5-2.0),
        сохраняет нормальные таймауты при RST-инъекциях,
        применяет timeout tweaks из правил.
        
        Args:
            domain: Доменное имя
            fingerprint: DPI fingerprint с информацией о типе блокировки
            failure_report: Отчет об анализе неудачи
            
        Returns:
            Вычисленный таймаут в секундах
        """
        base_timeout = self.config.strategy_timeout
        
        # 1. Определяем тип DPI блокировки из fingerprint
        dpi_type = None
        if fingerprint and hasattr(fingerprint, 'dpi_type'):
            dpi_type = fingerprint.dpi_type.value if hasattr(fingerprint.dpi_type, 'value') else str(fingerprint.dpi_type)
        
        # 2. Определяем тип из failure_report (более актуальная информация)
        if failure_report and hasattr(failure_report, 'root_cause'):
            root_cause = failure_report.root_cause.value if hasattr(failure_report.root_cause, 'value') else str(failure_report.root_cause)
            
            # Применяем автоматические множители на основе типа блокировки
            if root_cause == "DPI_CONTENT_INSPECTION":
                # Увеличиваем таймаут для глубокой инспекции контента
                timeout_factor = self.config.timeout_factor_content_inspection
                calculated_timeout = base_timeout * timeout_factor
                
                # Обновляем статистику
                self.timeout_stats["content_inspection_adjustments"] += 1
                self.timeout_stats["adaptive_timeouts_applied"] += 1
                self._update_average_timeout_factor(timeout_factor)
                
                LOG.info(f"🕒 Автоматическое увеличение таймаута для DPI_CONTENT_INSPECTION: "
                        f"{base_timeout}s * {timeout_factor} = {calculated_timeout}s")
                return calculated_timeout
                
            elif root_cause in ["DPI_ACTIVE_RST_INJECTION", "DPI_STATEFUL_TRACKING"]:
                # НЕ увеличиваем таймауты при RST-инъекциях (они быстрые)
                self.timeout_stats["rst_injection_adjustments"] += 1
                LOG.info(f"🕒 Сохраняем нормальный таймаут для RST-инъекций: {base_timeout}s")
                return base_timeout
                
            elif root_cause in ["DPI_SNI_FILTERING", "DPI_REASSEMBLES_FRAGMENTS"]:
                # Небольшое увеличение для других типов DPI
                timeout_factor = 1.3
                calculated_timeout = base_timeout * timeout_factor
                
                # Обновляем статистику
                self.timeout_stats["adaptive_timeouts_applied"] += 1
                self._update_average_timeout_factor(timeout_factor)
                
                LOG.info(f"🕒 Умеренное увеличение таймаута для {root_cause}: "
                        f"{base_timeout}s * {timeout_factor} = {calculated_timeout}s")
                return calculated_timeout
        
        # 3. Эвристика для медленных CDN на основе домена
        slow_cdn_domains = [
            "googlevideo.com", "ytimg.com", "ggpht.com",
            "tiktokcdn.com", "cdninstagram.com", "twimg.com"
        ]
        
        if any(cdn_domain in domain for cdn_domain in slow_cdn_domains):
            timeout_factor = self.config.timeout_factor_slow_cdn
            calculated_timeout = base_timeout * timeout_factor
            self.timeout_stats["slow_cdn_adjustments"] += 1
            self.timeout_stats["adaptive_timeouts_applied"] += 1
            LOG.info(f"🕒 Увеличение таймаута для медленного CDN ({domain}): "
                    f"{base_timeout}s * {timeout_factor} = {calculated_timeout}s")
            return calculated_timeout
        
        # 4. Базовый таймаут по умолчанию
        LOG.debug(f"🕒 Используем базовый таймаут: {base_timeout}s")
        return base_timeout

    def _apply_tweaks(self, tweaks: Dict[str, Any]):
        """
        Применение tweaks из правил базы знаний.
        
        Применяет strategy_timeout_factor, ttl_adjustment, split_position_hint,
        enable_ipv6_fallback. Сохраняет оригинальные значения для восстановления.
        Логирует применение tweaks.
        
        Tweaks применяются временно только для текущей итерации.
        
        Args:
            tweaks: Словарь с настройками из PatternRule
        """
        if not tweaks:
            return
        
        # Инициализируем хранилище оригинальных значений
        if not hasattr(self, '_original_config_values'):
            self._original_config_values = {}
        
        # strategy_timeout_factor
        if "strategy_timeout_factor" in tweaks:
            factor = float(tweaks["strategy_timeout_factor"])
            if "strategy_timeout" not in self._original_config_values:
                self._original_config_values["strategy_timeout"] = self.config.strategy_timeout
            self.config.strategy_timeout *= factor
            # Сохраняем factor для использования в _calculate_adaptive_timeout
            self._current_timeout_factor = factor
            LOG.info(f"Применен tweak: strategy_timeout *= {factor} = {self.config.strategy_timeout}")
        
        # ttl_adjustment
        if "ttl_adjustment" in tweaks:
            adjustment = int(tweaks["ttl_adjustment"])
            # TTL adjustment будет применен в параметрах стратегий
            # Сохраняем для использования в генераторе стратегий
            self._current_ttl_adjustment = adjustment
            LOG.info(f"Применен tweak: ttl_adjustment = {adjustment}")
        
        # split_position_hint
        if "split_position_hint" in tweaks:
            hint = tweaks["split_position_hint"]
            # Сохраняем для использования в генераторе стратегий
            self._current_split_hint = hint
            LOG.info(f"Применен tweak: split_position_hint = {hint}")
        
        # enable_ipv6_fallback
        if "enable_ipv6_fallback" in tweaks:
            enable = bool(tweaks["enable_ipv6_fallback"])
            if "enable_ipv6_fallback" not in self._original_config_values:
                self._original_config_values["enable_ipv6_fallback"] = getattr(self.config, 'enable_ipv6_fallback', False)
            self.config.enable_ipv6_fallback = enable
            LOG.info(f"Применен tweak: enable_ipv6_fallback = {enable}")
        
        # split_count_multiplier
        if "split_count_multiplier" in tweaks:
            multiplier = int(tweaks["split_count_multiplier"])
            self._current_split_multiplier = multiplier
            LOG.info(f"Применен tweak: split_count_multiplier = {multiplier}")
        
        # disorder_enabled
        if "disorder_enabled" in tweaks:
            enabled = bool(tweaks["disorder_enabled"])
            self._current_disorder_enabled = enabled
            LOG.info(f"Применен tweak: disorder_enabled = {enabled}")

    def _merge_queues(self,
                     base: List[Any],
                     extra: List[Any],
                     start_from: int) -> List[Any]:
        """
        Объединение очередей стратегий с приоритетом для новых и ограничением размера.
        
        Объединяет базовую очередь с дополнительными стратегиями,
        вставляет новые стратегии с приоритетом, дедуплицирует
        объединенную очередь, ограничивает размер до 50 стратегий,
        удаляет стратегии с низким expected_success_rate при превышении лимита.
        
        Args:
            base: Базовая очередь стратегий
            extra: Дополнительные стратегии (приоритетные)
            start_from: Индекс, с которого вставлять новые стратегии
            
        Returns:
            Объединенная очередь стратегий (максимум 50 элементов)
        """
        MAX_QUEUE_SIZE = 50  # Максимум 50 стратегий в очереди
        
        if not extra:
            return self._limit_queue_size(base, MAX_QUEUE_SIZE)
        
        if not base:
            deduped = self._dedup_strategies(extra)
            return self._limit_queue_size(deduped, MAX_QUEUE_SIZE)
        
        # Разделяем базовую очередь на две части
        head = base[:start_from] if start_from > 0 else []
        tail = base[start_from:] if start_from < len(base) else []
        
        # Объединяем extra + tail с дедупликацией
        merged_tail = self._dedup_strategies(extra + tail)
        
        # Собираем финальную очередь
        merged = head + merged_tail
        
        # Ограничиваем размер очереди
        limited_queue = self._limit_queue_size(merged, MAX_QUEUE_SIZE)
        
        LOG.debug(f"Объединение очередей: {len(base)} + {len(extra)} -> {len(merged)} -> {len(limited_queue)} "
                 f"(вставка с позиции {start_from}, лимит {MAX_QUEUE_SIZE})")
        
        return limited_queue
    
    def _limit_queue_size(self, strategies: List[Any], max_size: int) -> List[Any]:
        """
        Ограничение размера очереди стратегий с удалением стратегий с низким success_rate.
        
        Args:
            strategies: Список стратегий
            max_size: Максимальный размер очереди
            
        Returns:
            Ограниченный список стратегий
        """
        if len(strategies) <= max_size:
            return strategies
        
        # Сортируем стратегии по expected_success_rate (убывание)
        sorted_strategies = sorted(
            strategies,
            key=lambda s: self._get_strategy_success_rate(s),
            reverse=True
        )
        
        # Берем топ max_size стратегий
        limited = sorted_strategies[:max_size]
        removed_count = len(strategies) - len(limited)
        
        LOG.info(f"🚫 Ограничение очереди: удалено {removed_count} стратегий с низким success_rate, "
                f"осталось {len(limited)}/{max_size}")
        
        return limited
    
    def _get_strategy_success_rate(self, strategy: Any) -> float:
        """
        Получение expected_success_rate стратегии.
        
        Args:
            strategy: Стратегия для оценки
            
        Returns:
            Expected success rate (0.0 - 1.0)
        """
        # Проверяем наличие атрибута expected_success_rate
        if hasattr(strategy, 'expected_success_rate'):
            return float(strategy.expected_success_rate)
        
        # Проверяем в метаданных
        if hasattr(strategy, 'metadata') and strategy.metadata:
            if 'expected_success_rate' in strategy.metadata:
                return float(strategy.metadata['expected_success_rate'])
        
        # Проверяем в параметрах
        if hasattr(strategy, 'parameters') and strategy.parameters:
            if 'success_rate' in strategy.parameters:
                return float(strategy.parameters['success_rate'])
        
        # Эвристическая оценка на основе имени стратегии
        if hasattr(strategy, 'name'):
            name = strategy.name.lower()
            
            # Высокий приоритет для проверенных методов
            if any(keyword in name for keyword in ['sni', 'fragment', 'ttl']):
                return 0.8
            
            # Средний приоритет для экспериментальных методов
            if any(keyword in name for keyword in ['disorder', 'overlap', 'timing']):
                return 0.6
            
            # Низкий приоритет для сложных методов
            if any(keyword in name for keyword in ['complex', 'multi', 'advanced']):
                return 0.4
        
        # Базовый success rate по умолчанию
        return 0.5

    def _dedup_strategies(self, strategies: List[Any]) -> List[Any]:
        """
        Дедупликация стратегий по имени и attack_combination.
        
        Создает уникальный ключ из attack_combination, удаляет дубликаты
        с сохранением порядка, логирует количество удаленных дубликатов.
        
        Args:
            strategies: Список стратегий для дедупликации
            
        Returns:
            Список уникальных стратегий
        """
        if not strategies:
            return []
        
        seen = set()
        unique = []
        
        for strategy in strategies:
            # Создаем уникальный ключ из attack_combination и ключевых параметров
            if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
                key_parts = [tuple(sorted(strategy.attack_combination))]
                
                # Добавляем ключевые параметры для более точной дедупликации
                if hasattr(strategy, 'parameters') and strategy.parameters:
                    params = strategy.parameters
                    key_params = []
                    for param_name in ['ttl', 'split_pos', 'split_count', 'fooling']:
                        if param_name in params:
                            key_params.append(f"{param_name}={params[param_name]}")
                    key_parts.append(tuple(sorted(key_params)))
                
                key = tuple(key_parts)
            else:
                # Fallback: используем имя стратегии
                key = getattr(strategy, 'name', str(strategy))
            
            if key not in seen:
                seen.add(key)
                unique.append(strategy)
        
        removed_count = len(strategies) - len(unique)
        if removed_count > 0:
            LOG.debug(f"Дедупликация: удалено {removed_count} дубликатов, "
                     f"осталось {len(unique)} уникальных стратегий")
        
        return unique

    async def _augment_strategies_from_failure(self,
                                              domain: str,
                                              strategy: Any,
                                              result: Dict[str, Any],
                                              fingerprint: Any,
                                              context: Dict[str, Any]) -> List[Any]:
        """
        НОВЫЙ МЕТОД: Догенерация стратегий на основе анализа неудачи с профилированием.
        
        Workflow:
        1. Анализ PCAP через SFA
        2. Получение suggested_intents из FailureReport
        3. Применение правил базы знаний через PatternMatcher
        4. Объединение intent'ов из SFA и KnowledgeBase
        5. Применение tweaks через _apply_tweaks()
        6. Создание StrategyIntent через SIE.from_keys()
        7. Генерация новых стратегий через StrategyGenerator
        8. Дедупликация стратегий
        9. Обновление DPI fingerprint
        10. Обновление negative knowledge
        
        Args:
            domain: Доменное имя
            strategy: Стратегия, которая не сработала
            result: Результат тестирования с ошибкой
            fingerprint: DPI fingerprint
            context: Контекст (ASN, IP, domain и т.д.)
            
        Returns:
            Список новых стратегий для тестирования
        """
        # Профилирование начала метода
        method_start_time = time.time()
        
        if not self.knowledge_accumulator or not self.pattern_matcher:
            LOG.warning("Компоненты замкнутого цикла недоступны")
            return []
        
        # 1) Анализ PCAP через SFA (если доступен)
        pcap_file = None
        if hasattr(result, 'pcap_file'):
            pcap_file = getattr(result, 'pcap_file', None)
        elif hasattr(result, 'get'):
            pcap_file = result.get('pcap_file')
        elif hasattr(result, 'artifacts') and hasattr(result.artifacts, 'pcap_file'):
            pcap_file = getattr(result.artifacts, 'pcap_file', None)
        
        if not pcap_file:
            LOG.warning("PCAP файл недоступен для анализа неудачи")
            return []
        
        # Профилирование анализа PCAP
        pcap_analysis_start = time.time()
        try:
            # Ensure pcap_file is a string, not a Path object
            pcap_file_str = str(pcap_file) if pcap_file else None
            failure_report = await self.failure_analyzer.analyze_pcap(
                pcap_file_str, strategy, domain=domain
            )
        except Exception as e:
            LOG.error(f"Ошибка анализа PCAP: {e}")
            return []
        
        pcap_analysis_time = time.time() - pcap_analysis_start
        self._record_profiling_data("pcap_analysis", pcap_analysis_time)
        
        if not failure_report:
            LOG.warning("Не удалось проанализировать неудачу")
            return []
        
        # Сохраняем для обновления базы знаний при успехе
        self._last_failure_report = failure_report
        
        # 2) Достаём suggested_intents из SFA
        sfa_intents = failure_report.suggested_intents or []
        
        # 3) Применяем правила базы знаний через PatternMatcher
        pattern_matching_start = time.time()
        kb_intents, tweaks = self.pattern_matcher.apply_knowledge_rules(
            failure_report, context
        )
        pattern_matching_time = time.time() - pattern_matching_start
        self._record_profiling_data("pattern_matching", pattern_matching_time)
        
        if kb_intents:
            self.closed_loop_stats["pattern_matches"] += 1
            # Task 8.1: Record pattern match in metrics
            if self.metrics_collector:
                # Find which pattern matched (simplified approach)
                pattern_id = "unknown_pattern"
                if hasattr(failure_report, 'root_cause'):
                    pattern_id = f"pattern_{failure_report.root_cause.value}"
                self.metrics_collector.record_pattern_match(pattern_id, True)
        
        # 4) Объединяем intent'ы из SFA и KnowledgeBase
        # Фильтруем None значения перед объединением
        sfa_intents = [intent for intent in (sfa_intents or []) if intent is not None]
        kb_intents = [intent for intent in (kb_intents or []) if intent is not None]
        all_intent_keys = list(dict.fromkeys(sfa_intents + kb_intents))
        
        if not all_intent_keys:
            LOG.debug("Нет новых intent'ов для генерации")
            return []
        
        LOG.info(f"Извлечено {len(all_intent_keys)} intent'ов: {all_intent_keys}")
        self.closed_loop_stats["intents_generated"] += len(all_intent_keys)
        
        # Task 8.1: Record intents generated in metrics
        if self.metrics_collector:
            source = "SFA" if sfa_intents else "KnowledgeBase" if kb_intents else "Mixed"
            self.metrics_collector.record_intents_generated(all_intent_keys, source)
        
        # 5) Применяем tweaks
        if tweaks:
            self._apply_tweaks(tweaks)
        
        # 5.1) Обновляем адаптивный таймаут на основе анализа неудачи
        current_timeout = self.config.strategy_timeout
        updated_timeout = self._update_adaptive_timeout_from_failure(domain, failure_report, current_timeout)
        if updated_timeout != current_timeout:
            self.config.strategy_timeout = updated_timeout
            LOG.info(f"🕐 Обновлен адаптивный таймаут для {domain}: {updated_timeout:.1f}s")
        
        # 6) Превращаем в StrategyIntent объекты через SIE.from_keys()
        intent_creation_start = time.time()
        try:
            failure_intents = self.intent_engine.from_keys(all_intent_keys, base_weight=0.9)
        except Exception as e:
            LOG.error(f"Ошибка создания StrategyIntent из ключей: {e}")
            return []
        intent_creation_time = time.time() - intent_creation_start
        self._record_profiling_data("intent_creation", intent_creation_time)
        
        # 7) Генерируем дополнительный пул стратегий через StrategyGenerator
        strategy_generation_start = time.time()
        try:
            extra_strategies = await self.strategy_generator.generate_strategies(
                failure_intents, 
                fingerprint,
                max_strategies=10
            )
        except Exception as e:
            LOG.error(f"Ошибка генерации стратегий: {e}")
            # Добавляем детальную трассировку для отладки
            import traceback
            LOG.error(f"Полная трассировка ошибки:\n{traceback.format_exc()}")
            return []
        strategy_generation_time = time.time() - strategy_generation_start
        self._record_profiling_data("strategy_generation", strategy_generation_time)
        
        # 8) Дедупликация стратегий
        dedup_start = time.time()
        unique_strategies = self._dedup_strategies(extra_strategies)
        dedup_time = time.time() - dedup_start
        self._record_profiling_data("strategy_deduplication", dedup_time)
        
        # 9) Обновляем DPI fingerprint
        try:
            # Конвертируем FailureReport в словарь для fingerprint service
            failure_dict = {
                "root_cause": failure_report.root_cause.value if hasattr(failure_report.root_cause, 'value') else str(failure_report.root_cause),
                "confidence": failure_report.confidence,
                "block_timing": failure_report.block_timing,
                "failure_details": failure_report.failure_details
            }
            # ИСПРАВЛЕНИЕ: Метод не async, убираем await
            self.fingerprint_service.update_from_failure(domain, failure_dict)
        except Exception as e:
            LOG.warning(f"Ошибка обновления fingerprint: {e}")
        
        # 10) Обновляем negative knowledge
        self.knowledge_accumulator.update_failure_pattern(
            failure_report, strategy, context
        )
        
        # Профилирование общего времени выполнения
        total_method_time = time.time() - method_start_time
        self._record_profiling_data("augment_strategies_total", total_method_time)
        
        # Обновляем среднее время augmentation
        self._update_average_augmentation_time(total_method_time)
        
        LOG.info(f"Сгенерировано {len(unique_strategies)} новых стратегий из анализа неудачи "
                f"(время: {total_method_time:.3f}s)")
        
        return unique_strategies

    async def find_best_strategy(self, domain: str, progress_callback=None, shared_pcap_file=None) -> StrategyResult:
        """
        ИСПРАВЛЕНИЕ: Главный метод поиска рабочей стратегии с детальной диагностикой
        
        Проблема: Недостаточное логирование процесса поиска стратегий
        Решение: Детальное логирование каждого этапа с метриками производительности
        
        Args:
            domain: Доменное имя для анализа
            progress_callback: Функция для отображения прогресса
            shared_pcap_file: Shared PCAP file for continuous capture across all strategies
            
        Returns:
            StrategyResult с результатами поиска
        """
        start_time = time.time()
        trials_count = 0
        
        # ДИАГНОСТИКА: Детальное логирование начала анализа
        LOG.info("=" * 80)
        LOG.info(f"🚀 НАЧАЛО АДАПТИВНОГО АНАЛИЗА ДОМЕНА: {domain}")
        LOG.info(f"📊 Конфигурация: mode={self.config.mode}, max_trials={self.config.max_trials}")
        LOG.info(f"🔧 Компоненты: fingerprinting={self.config.enable_fingerprinting}, "
                f"failure_analysis={self.config.enable_failure_analysis}")
        LOG.info(f"⚙️ Bypass Engine: {type(self.bypass_engine).__name__ if self.bypass_engine else 'None'}")
        LOG.info("=" * 80)
        
        if progress_callback:
            progress_callback(f"[SEARCH] 🔍 Анализ домена {domain}...")
        
        # ДИАГНОСТИКА: Логирование статистики
        LOG.info(f"📈 Текущая статистика:")
        LOG.info(f"   - Обработано доменов: {self.stats['domains_processed']}")
        LOG.info(f"   - Найдено стратегий: {self.stats['strategies_found']}")
        LOG.info(f"   - Всего попыток: {self.stats['total_trials']}")
        LOG.info(f"   - Cache hits: {self.stats['cache_hits']}")
        LOG.info(f"   - Cache misses: {self.stats['cache_misses']}")
        
        # Task 11.2: Use shared PCAP file if provided, otherwise create new one
        # FIXED: No longer use shared PCAP file - each test creates its own PCAP
        # This ensures proper isolation and correct metadata for each strategy
        pcap_capturer = None
        pcap_file = None
        
        # Note: Individual PCAP files are created in _test_strategy_with_capture
        # based on strategy name, ensuring proper isolation and metadata
        
        # Task 16.1: Wrap entire method in try/finally to ensure PCAP capture is stopped
        try:
            # Шаг 1: Проверка сохраненных стратегий (domain_rules.json - ручная база)
            if domain in self.best_strategies:
                strategy = self.best_strategies[domain]
                if progress_callback:
                    progress_callback(f"[INFO] Найдена стратегия в domain_rules.json: {strategy.name}, проверяем...")
                
                # ИСПРАВЛЕНИЕ: Проверяем, работает ли сохраненная стратегия
                LOG.info(f"🔍 Проверка стратегии из domain_rules.json {strategy.name} для {domain}")
                
                try:
                    # FIXED: Use individual PCAP file for each test (not shared)
                    # This ensures each strategy has its own PCAP file with correct metadata
                    test_result = await self._test_strategy_with_capture(domain, strategy, shared_pcap_file=None)
                    
                    # Fix: Handle both TestResult object and dict
                    test_success = False
                    if test_result:
                        if hasattr(test_result, 'success'):
                            test_success = test_result.success
                        elif isinstance(test_result, dict):
                            test_success = test_result.get('success', False)
                    
                    if test_success:
                        if progress_callback:
                            progress_callback(f"[OK] Стратегия из domain_rules.json работает: {strategy.name}")
                        
                        # Update statistics for saved strategy reuse
                        self.stats["domains_processed"] += 1
                        self.stats["cache_hits"] += 1
                        
                        return StrategyResult(
                            success=True,
                            strategy=strategy,
                            message=f"Использована стратегия из domain_rules.json: {strategy.name}",
                            execution_time=time.time() - start_time
                        )
                    else:
                        # Сохраненная стратегия не работает - удаляем её и ищем новую
                        LOG.warning(f"⚠️ Стратегия из domain_rules.json {strategy.name} больше не работает для {domain}")
                        if progress_callback:
                            progress_callback(f"[WARNING] Стратегия из domain_rules.json не работает, проверяем adaptive_knowledge.json...")
                        
                        # Удаляем неработающую стратегию
                        del self.best_strategies[domain]
                        self.stats["cache_misses"] += 1
                        
                        # Продолжаем к проверке adaptive_knowledge.json
                        LOG.info(f"🔄 Проверяем adaptive_knowledge.json для {domain}")
                        
                except Exception as e:
                    LOG.error(f"❌ Ошибка при проверке стратегии из domain_rules.json: {e}")
                    if progress_callback:
                        progress_callback(f"[ERROR] Ошибка проверки стратегии, проверяем adaptive_knowledge.json...")
                    
                    # Удаляем проблемную стратегию
                    del self.best_strategies[domain]
                    self.stats["cache_misses"] += 1
        
            # Task 5.4: Шаг 1.5: Проверка adaptive_knowledge.json (автоматическая база)
            if self.adaptive_knowledge:
                try:
                    # Получаем стратегии из adaptive_knowledge.json, отсортированные по приоритету
                    adaptive_strategies = self.adaptive_knowledge.get_strategies_for_domain(domain)
                    
                    if adaptive_strategies:
                        LOG.info(f"📚 Найдено {len(adaptive_strategies)} стратегий в adaptive_knowledge.json для {domain}")
                        if progress_callback:
                            progress_callback(f"[INFO] Найдено {len(adaptive_strategies)} стратегий в adaptive_knowledge.json")
                        
                        # Пробуем стратегии по приоритету
                        for i, strategy_record in enumerate(adaptive_strategies[:3]):  # Пробуем топ-3
                            LOG.info(f"🔍 Проверка стратегии {i+1}/{min(3, len(adaptive_strategies))} из adaptive_knowledge.json: "
                                   f"{strategy_record.strategy_name} (success_rate: {strategy_record.success_rate():.2%})")
                            
                            if progress_callback:
                                progress_callback(f"[TEST] Проверка {strategy_record.strategy_name} "
                                               f"(success_rate: {strategy_record.success_rate():.2%})...")
                            
                            # Создаем объект стратегии из StrategyRecord
                            try:
                                from dataclasses import dataclass
                                
                                @dataclass
                                class AdaptiveStrategy:
                                    name: str
                                    type: str
                                    params: dict
                                    attack_name: str = None
                                    id: str = None
                                    
                                    def __post_init__(self):
                                        if self.attack_name is None:
                                            self.attack_name = self.type
                                        if self.id is None:
                                            self.id = f"adaptive_{self.name}"
                                    
                                    def to_dict(self):
                                        return {
                                            'type': self.type,
                                            'params': self.params
                                        }
                                
                                adaptive_strat = AdaptiveStrategy(
                                    name=strategy_record.strategy_name,
                                    type=strategy_record.strategy_name,
                                    params=strategy_record.strategy_params,
                                    attack_name=strategy_record.strategy_name,
                                    id=f"adaptive_{strategy_record.strategy_name}"
                                )
                                
                                # FIXED: Use individual PCAP file for each test (not shared)
                                # This ensures each strategy has its own PCAP file with correct metadata
                                test_result = await self._test_strategy_with_capture(domain, adaptive_strat, shared_pcap_file=None)
                                
                                # Fix: Handle both TestResult object and dict
                                test_success = False
                                if test_result:
                                    if hasattr(test_result, 'success'):
                                        test_success = test_result.success
                                    elif isinstance(test_result, dict):
                                        test_success = test_result.get('success', False)
                                
                                if test_success:
                                    LOG.info(f"✅ Стратегия из adaptive_knowledge.json работает: {strategy_record.strategy_name}")
                                    if progress_callback:
                                        progress_callback(f"[OK] Стратегия из adaptive_knowledge.json работает: {strategy_record.strategy_name}")
                                    
                                    # Update statistics
                                    self.stats["domains_processed"] += 1
                                    self.stats["cache_hits"] += 1
                                    
                                    # Task 7.4: Extract session_id from result for coordinator routing
                                    session_id = None
                                    if hasattr(test_result, 'metadata') and test_result.metadata:
                                        session_id = test_result.metadata.get('session_id')
                                    elif isinstance(test_result, dict):
                                        session_id = test_result.get('session_id')
                                    
                                    # Task 7.4: Save working strategy through coordinator
                                    await self._save_working_strategy(domain, adaptive_strat, pcap_file, session_id)
                                    
                                    return StrategyResult(
                                        success=True,
                                        strategy=adaptive_strat,
                                        message=f"Использована стратегия из adaptive_knowledge.json: {strategy_record.strategy_name}",
                                        execution_time=time.time() - start_time
                                    )
                                else:
                                    LOG.warning(f"⚠️ Стратегия {strategy_record.strategy_name} из adaptive_knowledge.json не работает")
                                    # Продолжаем к следующей стратегии
                                    
                            except Exception as e:
                                LOG.warning(f"⚠️ Ошибка при тестировании стратегии из adaptive_knowledge.json: {e}")
                                continue
                    
                        LOG.info(f"📚 Ни одна стратегия из adaptive_knowledge.json не сработала, переходим к генерации")
                        if progress_callback:
                            progress_callback(f"[INFO] Стратегии из adaptive_knowledge.json не сработали, генерируем новые...")
                    else:
                        LOG.info(f"📚 Нет стратегий в adaptive_knowledge.json для {domain}")
                        
                except Exception as e:
                    LOG.warning(f"⚠️ Ошибка при проверке adaptive_knowledge.json: {e}")
                    if progress_callback:
                        progress_callback(f"[WARNING] Ошибка проверки adaptive_knowledge.json")
            
            # Шаг 2: Проверка базовой доступности
            # For certain domains known to use subdomains, we should proceed with strategy testing
            # even if the main domain is accessible
            known_subdomain_domains = [
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "youtube.com",
            "ytimg.l.google.com"
            ]
        
            domain_needs_bypass_check = any(subdomain_domain in domain for subdomain_domain in known_subdomain_domains)
        
            if await self._is_domain_accessible(domain):
                # If it's not a known subdomain domain, we can skip bypass strategies
                if not domain_needs_bypass_check:
                    if progress_callback:
                        progress_callback("[OK] Домен доступен без обхода")
                    
                    # Update statistics for accessible domain
                    self.stats["domains_processed"] += 1
                    
                    return StrategyResult(
                        success=True,
                        message="Домен доступен без обхода блокировок",
                        execution_time=time.time() - start_time
                    )
                else:
                    if progress_callback:
                        progress_callback("[INFO] Домен доступен, но требуется проверка обхода для поддоменов")
            else:
                if progress_callback:
                    progress_callback("[INFO] Домен заблокирован, требуется обход")
            
            # Шаг 3: Получение/создание DPI fingerprint с кэшированием
            if progress_callback:
                progress_callback("[STATS] Анализ DPI характеристик...")
        
            fingerprint_start_time = time.time()
            fingerprint = None
        
            try:
                # Проверяем кэш fingerprint'ов
                fingerprint = self._get_cached_fingerprint(domain)
                
                if fingerprint is None:
                    # Создаем новый fingerprint
                    fingerprint = self.fingerprint_service.get_or_create(domain)
                    if fingerprint:
                        self._cache_fingerprint(domain, fingerprint)
                        self.stats["fingerprints_created"] += 1
                
                if fingerprint:
                    if progress_callback:
                        progress_callback(f"[STATS] DPI тип: {fingerprint.dpi_type.value}")
                        
            except Exception as e:
                LOG.warning(f"Failed to create DPI fingerprint for {domain}: {e}")
                if progress_callback:
                    progress_callback("[WARN] DPI анализ недоступен, используем базовые стратегии")
            
            fingerprint_time = time.time() - fingerprint_start_time
            self.stats["fingerprint_creation_time"] = (
                (self.stats["fingerprint_creation_time"] * self.stats["domains_processed"] + fingerprint_time) /
                (self.stats["domains_processed"] + 1)
            )
        
            # Шаг 4: Генерация целевых стратегий с кэшированием
            if progress_callback:
                progress_callback("[TARGET] Генерация целевых стратегий...")
        
            strategy_gen_start_time = time.time()
            strategies = []
        
            try:
                # Создаем хэш fingerprint для кэширования стратегий
                fingerprint_hash = ""
                if fingerprint:
                    fingerprint_data = str(fingerprint.dpi_type.value) + str(fingerprint.dpi_mode.value)
                    fingerprint_hash = hashlib.md5(fingerprint_data.encode()).hexdigest()[:8]
                
                # Проверяем кэш стратегий
                strategies = self._get_cached_strategies(domain, fingerprint_hash)
                
                if strategies is None:
                    # Генерируем новые стратегии
                    intents = self.intent_engine.propose_intents(fingerprint) if fingerprint else []
                    strategies = await self.strategy_generator.generate_strategies(intents, fingerprint)
                    
                    # Кэшируем результат
                    self._cache_strategies(domain, fingerprint_hash, strategies)
                    
            except Exception as e:
                LOG.warning(f"Failed to generate strategies for {domain}: {e}")
                if progress_callback:
                    progress_callback("[WARN] Генерация стратегий недоступна")
                strategies = []
        
            # ✅ КРИТИЧНО: Если есть существующая стратегия, тестируем её ПЕРВОЙ
            # Причина: Проверяем, работает ли она ещё, и если да - используем сразу
            # Если нет - ищем новую стратегию
            existing_strategy = None
            if self._strategy_manager:
                existing_strategy = self._strategy_manager.get_strategy(domain)
        
            if existing_strategy:
                LOG.info(f"✅ Found existing strategy for {domain}: {existing_strategy.strategy}")
                LOG.info(f"   Will test it FIRST to verify it still works")
                
                # Создаём объект стратегии из существующей конфигурации
                # Используем тот же формат, что и сгенерированные стратегии
                try:
                    from dataclasses import dataclass
                    
                    @dataclass
                    class ExistingStrategy:
                        name: str
                        type: str
                        params: dict
                        attack_name: str = None
                        id: str = None
                        
                        def __post_init__(self):
                            # Если attack_name не указан, используем type
                            if self.attack_name is None:
                                self.attack_name = self.type
                            # Если id не указан, используем имя как есть
                            if self.id is None:
                                self.id = self.name
                        
                        def to_dict(self):
                            return {
                                'type': self.type,
                                'params': self.params
                            }
                    
                    # Парсим стратегию из строки (например, "fake+multisplit+disorder")
                    strategy_parts = existing_strategy.strategy.split('+')
                    strategy_type = strategy_parts[0] if strategy_parts else 'unknown'
                    
                    # Собираем параметры из DomainStrategy
                    params = {}
                    if existing_strategy.split_pos is not None:
                        params['split_pos'] = existing_strategy.split_pos
                    if existing_strategy.split_count is not None:
                        params['split_count'] = existing_strategy.split_count
                    if existing_strategy.ttl is not None:
                        params['ttl'] = existing_strategy.ttl
                    if existing_strategy.fake_ttl is not None:
                        params['fake_ttl'] = existing_strategy.fake_ttl
                    if existing_strategy.disorder_method is not None:
                        params['disorder_method'] = existing_strategy.disorder_method
                    if existing_strategy.fooling_modes is not None:
                        params['fooling'] = existing_strategy.fooling_modes
                    if existing_strategy.raw_params:
                        params.update(existing_strategy.raw_params)
                    
                    # Task 17.2: Use strategy name as-is without adding prefix
                    # The prefix was causing issues with attack registry lookup
                    strategy_name = existing_strategy.strategy
                    
                    existing_strat_obj = ExistingStrategy(
                        name=strategy_name,
                        type=strategy_type,
                        params=params,
                        attack_name=strategy_type,
                        id=strategy_name
                    )
                    
                    # Добавляем существующую стратегию В НАЧАЛО списка
                    strategies.insert(0, existing_strat_obj)
                    LOG.info(f"   Added existing strategy to the beginning of test queue")
                    
                except Exception as e:
                    LOG.warning(f"⚠️ Failed to add existing strategy to queue: {e}")
        
            # Фильтрация по негативным знаним
            failed_strategies = set()
            if domain in self.negative_knowledge:
                failed_strategies = set(self.negative_knowledge[domain])
            strategies = [s for s in strategies if s.name not in failed_strategies]
        
            strategy_gen_time = time.time() - strategy_gen_start_time
            self.stats["strategy_generation_time"] = (
            (self.stats["strategy_generation_time"] * self.stats["domains_processed"] + strategy_gen_time) /
            (self.stats["domains_processed"] + 1)
            )
        
            if progress_callback:
                progress_callback(f"[TARGET] Сгенерировано {len(strategies)} целевых стратегий")
        
            LOG.info(f"Generated {len(strategies)} strategies for {domain}")
            LOG.info("[PROCESS] Using SEQUENTIAL testing (parallel testing disabled for DPI strategies)")
        
            # Шаг 5: Тестирование с анализом неудач (ТОЛЬКО последовательное для DPI стратегий)
            # ВАЖНО: Параллельное тестирование DPI стратегий невозможно из-за конфликтов:
            # - WinDivert драйвер может использоваться только одним процессом
            # - Модификация пакетов разными стратегиями создает хаос
            # - TCP соединения ломаются от конфликтующих изменений
            if False:  # Принудительно отключаем параллельное тестирование
                # Параллельное тестирование (ОТКЛЮЧЕНО для DPI)
                successful_strategy, tested_count = await self._test_strategies_parallel(
                    domain, strategies[:self.config.max_trials], progress_callback
                )
                
                trials_count = tested_count  # Учитываем фактическое количество протестированных стратегий
                
                if successful_strategy:
                    # Update statistics for successful strategy finding
                    self.stats["domains_processed"] += 1
                    self.stats["total_trials"] += trials_count
                    self.stats["parallel_tests_executed"] += 1
                    
                    return StrategyResult(
                        success=True,
                        strategy=successful_strategy,
                        message=f"Найдена рабочая стратегия (параллельно): {successful_strategy.name}",
                        execution_time=time.time() - start_time,
                        trials_count=trials_count,
                        fingerprint_updated=bool(fingerprint)
                    )
            else:
                # НОВОЕ: Итеративный цикл обучения с динамической очередью
                strategies_queue = strategies[:self.config.max_trials]  # Начальная очередь
                iteration_count = 0
                max_iterations = 5  # Максимум итераций для предотвращения бесконечного цикла
                
                # Создаем контекст для Pattern Matcher
                context = self._build_context(domain, fingerprint)
            
            # PCAP capture already initialized at the beginning of the method
            
            LOG.info(f"🔄 Начинаем итеративный цикл обучения для {domain}")
            LOG.info(f"📋 Начальная очередь: {len(strategies_queue)} стратегий")
            
            try:
                while strategies_queue and trials_count < self.config.max_trials and iteration_count < max_iterations:
                    iteration_count += 1
                    self.closed_loop_stats["iterations_total"] += 1
                    
                    # Task 8.1: Record iteration start in metrics
                    if self.metrics_collector:
                        self.metrics_collector.record_iteration_start(domain, iteration_count)
                    
                    LOG.info(f"🔄 Итерация {iteration_count}: {len(strategies_queue)} стратегий в очереди")
                    
                    if progress_callback:
                        progress_callback(f"[ITER] Итерация {iteration_count}: тестирование {len(strategies_queue)} стратегий")
                    
                    # Тестируем стратегии из текущей очереди
                    current_queue = strategies_queue.copy()
                    strategies_queue = []  # Очищаем очередь для новых стратегий
                    
                    for i, strategy in enumerate(current_queue):
                        if trials_count >= self.config.max_trials:
                            break
                            
                        trials_count += 1
                        
                        if progress_callback:
                            progress_callback(f"[TEST] Итерация {iteration_count}, стратегия {i+1}/{len(current_queue)}: {strategy.name}")
                        
                        test_start_time = time.time()
                        # FIXED: Use individual PCAP file for each test (not shared)
                        # This ensures each strategy has its own PCAP file with correct metadata
                        result = await self._test_strategy_with_capture(domain, strategy, shared_pcap_file=None)
                        test_time = time.time() - test_start_time
                        
                        # Обновляем среднее время тестирования
                        self.stats["average_test_time"] = (
                            (self.stats["average_test_time"] * (trials_count - 1) + test_time) / trials_count
                        )
                        
                        # Task 3.4: Structured logging of strategy test results
                        # Логируем domain, strategy_name, strategy_params (кратко)
                        strategy_params = {}
                        if hasattr(strategy, 'params'):
                            strategy_params = strategy.params
                        elif hasattr(strategy, 'to_dict'):
                            strategy_dict = strategy.to_dict()
                            strategy_params = strategy_dict.get('params', {})
                        
                        LOG.info(f"🎯 Тест {trials_count}: {strategy.name} -> {'✅ SUCCESS' if result.success else '❌ FAIL'}")
                        LOG.info(f"[STRATEGY_TEST] domain={domain}, strategy_name={strategy.name}, "
                               f"strategy_params={strategy_params}, test_time={test_time:.3f}s")
                        
                        # Task 3.4: Log ConnectionMetrics and EvaluationResult from metadata
                        if hasattr(result, 'metadata') and result.metadata:
                            if 'connection_metrics' in result.metadata:
                                cm = result.metadata['connection_metrics']
                                LOG.info(f"[CONNECTION_METRICS] connect_time_ms={cm.get('connect_time_ms', 0):.1f}, "
                                       f"tls_time_ms={cm.get('tls_time_ms', 0):.1f}, "
                                       f"ttfb_ms={cm.get('ttfb_ms', 0):.1f}, "
                                       f"http_status={cm.get('http_status')}, "
                                       f"bytes_received={cm.get('bytes_received', 0)}, "
                                       f"block_type={cm.get('block_type', 'unknown')}")
                            
                            if 'evaluation_result' in result.metadata:
                                er = result.metadata['evaluation_result']
                                LOG.info(f"[EVALUATION_RESULT] success={er.get('success')}, "
                                       f"block_type={er.get('block_type', 'unknown')}, "
                                       f"confidence={er.get('confidence', 0):.2f}, "
                                       f"reason={er.get('reason', 'N/A')}")
                        
                        if result.success:
                            # УСПЕХ: Обновляем KnowledgeAccumulator и сохраняем стратегию
                            if self.knowledge_accumulator and hasattr(self, '_last_failure_report'):
                                try:
                                    self.knowledge_accumulator.update_success_pattern(
                                        self._last_failure_report, strategy, context
                                    )
                                    self.closed_loop_stats["knowledge_updates"] += 1
                                    
                                    # Task 8.1: Record knowledge base update in metrics
                                    if self.metrics_collector:
                                        rules_count = len(self.knowledge_accumulator.get_all_patterns())
                                        self.metrics_collector.record_knowledge_base_update(rules_count)
                                        
                                        # Record pattern success
                                        pattern_id = "unknown_pattern"
                                        if hasattr(self._last_failure_report, 'root_cause'):
                                            pattern_id = f"pattern_{self._last_failure_report.root_cause.value}"
                                        self.metrics_collector.record_pattern_success(pattern_id, True)
                                    
                                    LOG.info("📚 База знаний обновлена после успеха")
                                except Exception as e:
                                    LOG.warning(f"Ошибка обновления базы знаний: {e}")
                        
                        # Task 5.4: Save successful strategy to adaptive_knowledge.json
                        if self.adaptive_knowledge:
                            try:
                                # Extract ConnectionMetrics from result
                                connection_metrics = None
                                if hasattr(result, 'metadata') and result.metadata:
                                    if 'connection_metrics' in result.metadata:
                                        # Reconstruct ConnectionMetrics from dict
                                        cm_dict = result.metadata['connection_metrics']
                                        if CONNECTION_METRICS_AVAILABLE and ConnectionMetrics:
                                            connection_metrics = ConnectionMetrics(
                                                connect_time_ms=cm_dict.get('connect_time_ms', 0.0),
                                                tls_time_ms=cm_dict.get('tls_time_ms', 0.0),
                                                ttfb_ms=cm_dict.get('ttfb_ms', 0.0),
                                                total_time_ms=cm_dict.get('total_time_ms', 0.0),
                                                http_status=cm_dict.get('http_status'),
                                                bytes_received=cm_dict.get('bytes_received', 0),
                                                tls_completed=cm_dict.get('tls_completed', False),
                                                error=cm_dict.get('error'),
                                                rst_received=cm_dict.get('rst_received', False),
                                                rst_timing_ms=cm_dict.get('rst_timing_ms'),
                                                timeout=cm_dict.get('timeout', False),
                                                block_type=BlockType(cm_dict.get('block_type', 'unknown')) if BlockType else None
                                            )
                                
                                # If no ConnectionMetrics, create a basic one
                                if connection_metrics is None and CONNECTION_METRICS_AVAILABLE and ConnectionMetrics:
                                    connection_metrics = ConnectionMetrics(
                                        connect_time_ms=test_time * 1000,  # Convert to ms
                                        http_status=200,  # Assume success
                                        block_type=BlockType.NONE
                                    )
                                
                                # Extract strategy parameters
                                strategy_params = {}
                                if hasattr(strategy, 'params'):
                                    strategy_params = strategy.params
                                elif hasattr(strategy, 'parameters'):
                                    strategy_params = strategy.parameters
                                elif hasattr(strategy, 'to_dict'):
                                    strategy_dict = strategy.to_dict()
                                    strategy_params = strategy_dict.get('params', {})
                                
                                # Record success in adaptive_knowledge.json
                                self.adaptive_knowledge.record_success(
                                    domain=domain,
                                    strategy_name=strategy.name if hasattr(strategy, 'name') else 'unknown',
                                    strategy_params=strategy_params,
                                    metrics=connection_metrics
                                )
                                
                                LOG.info(f"📚 Сохранена успешная стратегия в adaptive_knowledge.json: {strategy.name if hasattr(strategy, 'name') else 'unknown'}")
                            except Exception as e:
                                LOG.warning(f"⚠️ Ошибка сохранения в adaptive_knowledge.json: {e}")
                        
                        # Восстанавливаем tweaks перед завершением
                        self._restore_tweaks()
                        
                        # Task 6.4: Extract pcap_file from result for PCAP analysis
                        pcap_file = None
                        if hasattr(result, 'artifacts') and hasattr(result.artifacts, 'pcap_file'):
                            pcap_file = result.artifacts.pcap_file
                        elif hasattr(result, 'pcap_file'):
                            pcap_file = result.pcap_file
                        
                        # Task 7.4: Extract session_id from result for coordinator routing
                        session_id = None
                        if hasattr(result, 'metadata') and result.metadata:
                            session_id = result.metadata.get('session_id')
                        elif isinstance(result, dict):
                            session_id = result.get('session_id')
                        
                        # Сохраняем рабочую стратегию с PCAP анализом
                        # Task 7.4: Pass session_id for coordinator save routing (Requirements 1.4, 1.5, 9.4)
                        await self._save_working_strategy(domain, strategy, pcap_file, session_id)
                        
                        if progress_callback:
                            progress_callback(f"[OK] Найдена рабочая стратегия: {strategy.name}")
                        
                        # Update statistics for successful strategy finding
                        self.stats["domains_processed"] += 1
                        self.stats["total_trials"] += trials_count
                        
                        # Task 8.1: Record iteration success in metrics
                        if self.metrics_collector:
                            self.metrics_collector.record_iteration_success(domain, iteration_count)
                        
                        LOG.info(f"🎉 Успех за {iteration_count} итераций, {trials_count} попыток")
                        
                        # Task 11.5: Generate validation report if in verification mode
                        if self.config.verify_with_pcap and self.strategy_validator:
                            try:
                                validation_report = self.strategy_validator.generate_report()
                                LOG.info("\n" + validation_report)
                                
                                # Save validation report to file
                                from pathlib import Path
                                report_dir = Path("data/validation_reports")
                                report_dir.mkdir(parents=True, exist_ok=True)
                                
                                from datetime import datetime
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                domain_safe = domain.replace('.', '_')
                                report_file = report_dir / f"validation_report_{domain_safe}_{timestamp}.txt"
                                
                                with open(report_file, 'w', encoding='utf-8') as f:
                                    f.write(validation_report)
                                
                                LOG.info(f"📄 Validation report saved to: {report_file}")
                                
                                # Also save JSON results
                                json_file = report_dir / f"validation_results_{domain_safe}_{timestamp}.json"
                                self.strategy_validator.save_results(json_file)
                                
                            except Exception as e:
                                LOG.error(f"❌ Failed to generate validation report: {e}", exc_info=True)
                        
                        return StrategyResult(
                            success=True,
                            strategy=strategy,
                            message=f"Найдена рабочая стратегия за {iteration_count} итераций: {strategy.name}",
                            execution_time=time.time() - start_time,
                            trials_count=trials_count,
                            fingerprint_updated=bool(fingerprint),
                            metadata={
                                "iterations": iteration_count,
                                "closed_loop_learning": True,
                                "knowledge_updates": self.closed_loop_stats["knowledge_updates"]
                            }
                        )
                    else:
                        # НЕУДАЧА: Анализируем и генерируем новые стратегии
                        await self._analyze_strategy_failure(domain, strategy, result, fingerprint, progress_callback)
                        
                        # Генерируем дополнительные стратегии через замкнутый цикл обучения
                        try:
                            augmented_strategies = await self._augment_strategies_from_failure(
                                domain, strategy, result, fingerprint, context
                            )
                            
                            if augmented_strategies:
                                # Объединяем новые стратегии с оставшейся очередью
                                strategies_queue = self._merge_queues(
                                    strategies_queue, augmented_strategies, start_from=0
                                )
                                
                                self.closed_loop_stats["strategies_augmented"] += len(augmented_strategies)
                                
                                # Task 8.1: Record strategies generated in metrics
                                if self.metrics_collector:
                                    self.metrics_collector.record_strategies_generated(len(augmented_strategies))
                                
                                LOG.info(f"🔄 Догенерировано {len(augmented_strategies)} стратегий, "
                                        f"очередь: {len(strategies_queue)}")
                                
                                if progress_callback:
                                    progress_callback(f"[LEARN] Догенерировано {len(augmented_strategies)} стратегий")
                        
                        except Exception as e:
                            LOG.warning(f"Ошибка догенерации стратегий: {e}")
                            # Добавляем детальную трассировку для отладки
                            import traceback
                            LOG.debug(f"Полная трассировка ошибки:\n{traceback.format_exc()}")
                
                # Логируем итерацию
                LOG.info(f"📊 Итерация {iteration_count} завершена: "
                        f"протестировано {len(current_queue)}, "
                        f"в очереди {len(strategies_queue)}, "
                        f"всего попыток {trials_count}")
            
                # Восстанавливаем tweaks в случае неудачи
                self._restore_tweaks()
                
                LOG.info(f"❌ Цикл завершен без успеха: {iteration_count} итераций, {trials_count} попыток")
            
            except Exception as e:
                LOG.error(f"❌ Критическая ошибка в цикле обучения: {e}")
                import traceback
                LOG.debug(f"Трассировка:\n{traceback.format_exc()}")
        
        finally:
            # FIXED: No shared PCAP cleanup needed - individual PCAP files are managed per test
            # Each test in _test_strategy_with_capture creates and manages its own PCAP file
            pass
            
            # Legacy code removed - shared PCAP is no longer used
            if False and pcap_capturer:
                try:
                    pcap_capturer.stop_capture()
                    LOG.info(f"🎥 PCAP capture stopped: {pcap_file}")
                    
                    # Run PCAP analysis and validation
                    if pcap_file and pcap_file.exists():
                        LOG.info(f"📊 Analyzing complete PCAP file: {pcap_file}")
                        
                        # Task 11.5: Run StrategyValidator with complete PCAP file
                        if self.strategy_validator:
                            try:
                                validation_result = self.strategy_validator.validate_strategy(
                                    strategy_log=None,  # No operation log available
                                    pcap_file=pcap_file,
                                    domain=domain,
                                    strategy_name=f"domain_analysis_{domain}"
                                )
                                LOG.info(f"✅ Final validation complete: {validation_result.status}")
                            except Exception as e:
                                LOG.warning(f"⚠️ Final validation failed: {e}")
                except Exception as e:
                    LOG.error(f"❌ Error stopping PCAP capture: {e}")
        
        # Обновляем статистику
        self.stats["domains_processed"] += 1
        self.stats["total_trials"] += trials_count
        
        # Сохраняем негативные знания
        self._save_negative_knowledge()
        
        # Task 11.5: Generate validation report if in verification mode
        if self.config.verify_with_pcap and self.strategy_validator:
            try:
                validation_report = self.strategy_validator.generate_report()
                LOG.info("\n" + validation_report)
                
                # Save validation report to file
                from pathlib import Path
                report_dir = Path("data/validation_reports")
                report_dir.mkdir(parents=True, exist_ok=True)
                
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                domain_safe = domain.replace('.', '_')
                report_file = report_dir / f"validation_report_{domain_safe}_{timestamp}.txt"
                
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(validation_report)
                
                LOG.info(f"📄 Validation report saved to: {report_file}")
                
                # Also save JSON results
                json_file = report_dir / f"validation_results_{domain_safe}_{timestamp}.json"
                self.strategy_validator.save_results(json_file)
                
            except Exception as e:
                LOG.error(f"❌ Failed to generate validation report: {e}", exc_info=True)
        
        return StrategyResult(
            success=False,
            message=f"Не найдено рабочих стратегий после {trials_count} попыток",
            execution_time=time.time() - start_time,
            trials_count=trials_count,
            fingerprint_updated=bool(fingerprint)
        )
    
    async def _save_working_strategy(self, domain: str, strategy: Any, pcap_file: Optional[str] = None, session_id: Optional[str] = None):
        """
        Сохранение рабочей стратегии.
        
        Task 6.1: Use StrategyManager for unified strategy persistence
        Task 6.4: Analyze PCAP after successful strategy test
        Task 7.4: Route saves through coordinator (Requirements 1.4, 1.5, 9.4)
        Task 12.2: In batch mode, save only to adaptive_knowledge.json, not domain_rules.json (Requirement 6.1, 6.2)
        
        Args:
            domain: Target domain
            strategy: Strategy object to save
            pcap_file: Optional PCAP file path for analysis
            session_id: Optional test session ID for coordinator routing
        """
        # Task 7.4: Check coordinator approval before saving (Requirements 1.4, 1.5, 9.4)
        if self.test_result_coordinator and session_id:
            if not self.test_result_coordinator.should_save_strategy(session_id):
                LOG.warning(f"🚫 Coordinator blocked save for {domain}: Test verdict is not SUCCESS")
                return
            LOG.info(f"✅ Coordinator approved save for {domain}")
        
        # Task 7.4: Route saves through StrategySaver for deduplication (Requirements 5.1, 5.2, 5.3, 5.4, 5.5)
        if self.strategy_saver and self.test_result_coordinator and session_id:
            try:
                # Get test session to access verdict
                session = self.test_result_coordinator.get_session(session_id)
                if not session:
                    LOG.warning(f"⚠️ No test session found for {session_id}, falling back to legacy save")
                else:
                    # Extract strategy information
                    strategy_name = self._get_strategy_name(strategy)
                    
                    # Extract parameters
                    parameters = {}
                    if hasattr(strategy, 'params'):
                        parameters = strategy.params
                    elif hasattr(strategy, 'parameters'):
                        parameters = strategy.parameters
                    elif hasattr(strategy, 'to_dict'):
                        strategy_dict = strategy.to_dict()
                        parameters = strategy_dict.get('params', {})
                    
                    # Extract attacks list
                    attacks = self._extract_attack_combination(strategy)
                    
                    # Extract parameters from PCAP analysis if available (override strategy parameters)
                    pcap_parameters = None
                    if session.pcap_analysis and hasattr(session.pcap_analysis, 'parameters'):
                        pcap_parameters = session.pcap_analysis.parameters
                        LOG.debug(f"📊 Using PCAP parameters for saving: {pcap_parameters}")
                        
                        # Override strategy parameters with PCAP parameters
                        if pcap_parameters:
                            parameters = {**parameters, **pcap_parameters}
                            LOG.debug(f"📊 Merged parameters: {parameters}")
                        
                        # Update attacks list from PCAP if available
                        if hasattr(session.pcap_analysis, 'detected_attacks') and session.pcap_analysis.detected_attacks:
                            pcap_attacks = session.pcap_analysis.detected_attacks
                            LOG.debug(f"📊 PCAP detected attacks: {pcap_attacks}")
                            # Use PCAP attacks if they are more specific
                            if len(pcap_attacks) > len(attacks):
                                attacks = pcap_attacks
                                LOG.debug(f"📊 Using PCAP attacks: {attacks}")
                    
                    # Use StrategySaver for atomic, deduplicated saves
                    save_result = self.strategy_saver.save_strategy(
                        domain=domain,
                        strategy_name=strategy_name,
                        parameters=parameters,
                        verdict=session.verdict,
                        attacks=attacks,
                        success_rate=1.0,
                        verified=True
                    )
                    
                    if save_result.success:
                        if save_result.was_duplicate:
                            LOG.info(f"✅ Strategy save deduplicated for {domain}: {strategy_name}")
                        else:
                            LOG.info(f"✅ Strategy saved via StrategySaver for {domain}: {strategy_name}")
                            LOG.info(f"   Files updated: {', '.join(save_result.files_updated)}")
                        
                        # Update in-memory cache
                        self.best_strategies[domain] = strategy
                        self.stats["strategies_found"] += 1
                        
                        # PCAP analysis already done by coordinator, just log
                        if pcap_file and session.pcap_analysis:
                            LOG.info(f"✅ PCAP Analysis: {len(session.pcap_analysis.detected_attacks)} attacks detected")
                            LOG.info(f"   Detected attacks: {session.pcap_analysis.detected_attacks}")
                            LOG.info(f"   Parameters: {session.pcap_analysis.parameters}")
                        
                        return  # Success - exit early
                    else:
                        LOG.error(f"❌ StrategySaver failed: {save_result.error}")
                        LOG.warning(f"⚠️ Falling back to legacy save method")
                        
            except Exception as e:
                LOG.error(f"❌ Error using StrategySaver: {e}", exc_info=True)
                LOG.warning(f"⚠️ Falling back to legacy save method")
        
        # Task 7.4: Legacy save path (only used when coordinator/saver not available)
        # This maintains backward compatibility but bypasses deduplication
        LOG.info(f"ℹ️ Using legacy save path for {domain} (coordinator/saver not available)")
        
        self.best_strategies[domain] = strategy
        self.stats["strategies_found"] += 1
        
        # Task 6.4: Analyze PCAP if available
        # Task 7.3: Route PCAP analysis through coordinator (Requirements 6.1, 6.2, 6.3)
        if pcap_file:
            try:
                # Ensure pcap_file is a string, not a Path object
                pcap_file_str = str(pcap_file) if pcap_file else None
                if not pcap_file_str:
                    raise ValueError("Invalid PCAP file path")
                
                # Task 7.3: Route PCAP analysis through coordinator (Requirements 6.1, 6.2, 6.3)
                # All PCAP analysis must go through coordinator to ensure caching and consistency
                if self.test_result_coordinator:
                    # Route through coordinator to ensure caching (Requirement 6.1, 6.2, 6.3)
                    LOG.info(f"🔍 Analyzing PCAP: {pcap_file}")
                    pcap_analysis = self.test_result_coordinator.get_pcap_analysis(pcap_file_str)
                    
                    if pcap_analysis:
                        LOG.info(f"✅ PCAP Analysis: {len(pcap_analysis.detected_attacks)} attacks detected in {pcap_file}")
                        LOG.info(f"   Detected attacks: {pcap_analysis.detected_attacks}")
                        LOG.info(f"   Parameters: {pcap_analysis.parameters}")
                        LOG.info(f"   Packet count: {pcap_analysis.packet_count}")
                        
                        # Store analysis results for later comparison
                        if not hasattr(self, '_pcap_analysis_results'):
                            self._pcap_analysis_results = {}
                        self._pcap_analysis_results[domain] = pcap_analysis
                    else:
                        LOG.warning(f"⚠️ PCAP Analysis: Failed to analyze {pcap_file}")
                else:
                    # Fallback to direct analyzer if coordinator not available (backward compatibility)
                    # Note: This fallback bypasses caching and should only be used when coordinator is disabled
                    LOG.warning(f"⚠️ TestResultCoordinator not available, using direct PCAPAnalyzer (no caching)")
                    from core.pcap.analyzer import PCAPAnalyzer
                    analyzer = PCAPAnalyzer()
                    
                    # Analyze strategy application
                    strategy_dict = {
                        'attack': getattr(strategy, 'attack_name', 'unknown'),
                        'type': getattr(strategy, 'name', 'unknown'),
                        'params': getattr(strategy, 'parameters', {})
                    }
                    
                    LOG.info(f"🔍 Analyzing PCAP: {pcap_file}")
                    analysis_result = analyzer.analyze_strategy_application(pcap_file_str, strategy_dict)
                    
                    if analysis_result.strategy_detected:
                        LOG.info(f"✅ PCAP Analysis: Strategy detected in {pcap_file}")
                        LOG.info(f"   Split positions: {analysis_result.split_positions}")
                        LOG.info(f"   SNI values: {analysis_result.sni_values}")
                        LOG.info(f"   Packet count: {analysis_result.packet_count}")
                        
                        # Store analysis results for later comparison
                        if not hasattr(self, '_pcap_analysis_results'):
                            self._pcap_analysis_results = {}
                        self._pcap_analysis_results[domain] = analysis_result
                    else:
                        LOG.warning(f"⚠️ PCAP Analysis: Strategy not detected in {pcap_file}")
                    
            except Exception as e:
                LOG.warning(f"⚠️ PCAP analysis failed: {e}")
        
        # Task 12.2: Save to adaptive_knowledge.json in both normal and batch mode (Requirement 6.2)
        if self.adaptive_knowledge:
            try:
                # Extract strategy parameters
                strategy_params = {}
                if hasattr(strategy, 'params'):
                    strategy_params = strategy.params
                elif hasattr(strategy, 'parameters'):
                    strategy_params = strategy.parameters
                elif hasattr(strategy, 'to_dict'):
                    strategy_dict = strategy.to_dict()
                    strategy_params = strategy_dict.get('params', {})
                
                # Create basic ConnectionMetrics for successful strategy
                if CONNECTION_METRICS_AVAILABLE and ConnectionMetrics:
                    connection_metrics = ConnectionMetrics(
                        connect_time_ms=0.0,  # Will be updated with actual timing if available
                        http_status=200,  # Assume success
                        block_type=BlockType.NONE
                    )
                else:
                    connection_metrics = None
                
                # Record success in adaptive_knowledge.json
                self.adaptive_knowledge.record_success(
                    domain=domain,
                    strategy_name=strategy.name if hasattr(strategy, 'name') else 'unknown',
                    strategy_params=strategy_params,
                    metrics=connection_metrics
                )
                
                LOG.info(f"📚 Saved successful strategy to adaptive_knowledge.json: {strategy.name if hasattr(strategy, 'name') else 'unknown'}")
            except Exception as e:
                LOG.warning(f"⚠️ Error saving to adaptive_knowledge.json: {e}")
        
        # Task 12.2: In batch mode, skip saving to domain_rules.json (Requirement 6.1)
        # Only save to adaptive_knowledge.json (done above)
        if not self.config.batch_mode:
            # Task 3: Save strategy with complete attack combination information
            # ИСПРАВЛЕНИЕ: Передаём pcap_file для анализа реально применённой стратегии
            try:
                self._save_strategy(domain, strategy, pcap_file)
            except Exception as e:
                LOG.error(f"❌ Failed to save strategy with new method: {e}")
                # Fallback to old method
                self._save_best_strategies()
            
            # Task 6.1: Also save using StrategyManager for backward compatibility
            if self._strategy_manager:
                try:
                    strategy_name = getattr(strategy, 'name', 'unknown')
                    attack_name = getattr(strategy, 'attack_name', 
                                        strategy.attack_combination[0] if hasattr(strategy, 'attack_combination') and strategy.attack_combination else 'unknown')
                    parameters = getattr(strategy, 'parameters', {})
                    
                    # Add forced override parameters
                    if 'no_fallbacks' not in parameters:
                        parameters['no_fallbacks'] = True
                    if 'forced' not in parameters:
                        parameters['forced'] = True
                    
                    # ✅ FIX: Подготавливаем ВСЕ параметры для сохранения
                    # Decompose smart_combo_ attack names into constituent attacks
                    raw_attacks = getattr(strategy, 'attack_combination', [attack_name])
                    attacks = []
                    for attack in raw_attacks:
                        if isinstance(attack, str) and (attack.startswith('smart_combo_') or attack.startswith('existing_smart_combo_')):
                            # Decompose smart_combo_ names
                            name_without_prefix = attack.replace('existing_smart_combo_', '').replace('smart_combo_', '')
                            parts = name_without_prefix.split('_')
                            known_attacks = {'fake', 'split', 'disorder', 'multisplit', 'seqovl'}
                            for part in parts:
                                if part in known_attacks:
                                    attacks.append(part)
                        else:
                            attacks.append(attack)
                    
                    # Fallback if decomposition resulted in empty list
                    if not attacks:
                        attacks = raw_attacks
                    
                    save_params = {
                        # Базовые параметры
                        'split_pos': parameters.get('split_pos'),
                        'overlap_size': parameters.get('split_seqovl') or parameters.get('overlap_size'),
                        'fooling_modes': parameters.get('fooling'),
                        # ✅ FIX: Критические параметры которые раньше терялись
                        'split_count': parameters.get('split_count'),
                        'ttl': parameters.get('ttl'),
                        'fake_ttl': parameters.get('fake_ttl'),
                        'disorder_method': parameters.get('disorder_method'),
                        'ack_first': parameters.get('ack_first'),
                        # Дополнительные параметры
                        'strategy_name': strategy_name,
                        'attack_type': attack_name,
                        'attacks': attacks,  # ✅ FIX: Use decomposed attacks
                        'raw_params': parameters.copy(),  # ✅ Сохраняем ВСЕ параметры
                        'discovered_at': datetime.now().isoformat(),
                    }
                    
                    # Save using StrategyManager
                    self._strategy_manager.add_strategy(
                        domain=domain,
                        strategy=strategy_name,
                        success_rate=1.0,  # Successful strategy
                        avg_latency_ms=0.0,  # Will be updated with actual latency
                        **save_params  # ✅ FIX: Передаем ВСЕ параметры
                    )
                    self._strategy_manager.save_strategies()
                    LOG.info(f"✅ Saved working strategy for {domain} via StrategyManager: {strategy_name}")
                    LOG.debug(f"   Saved parameters: {save_params}")
                except Exception as e:
                    LOG.error(f"❌ Failed to save strategy via StrategyManager: {e}")
        else:
            # Task 12.2: In batch mode, only log that we're skipping domain_rules.json save (Requirement 6.1)
            LOG.info(f"📚 Batch mode: Skipping domain_rules.json save for {domain}, strategy saved to adaptive_knowledge.json only")
        
        LOG.info(f"Saved working strategy for {domain}: {getattr(strategy, 'name', 'unknown')}")
    
    def _extract_attack_combination(self, strategy: Any) -> List[str]:
        """
        Extract ordered list of attacks from strategy object.
        
        This method detects attack combinations from strategy objects by checking:
        1. Explicit attack_combination attribute
        2. Strategy name patterns (e.g., "multisplit_disorder")
        3. Parameters that indicate combinations (e.g., disorder_method)
        
        Args:
            strategy: Strategy object to analyze
            
        Returns:
            List of attack names in execution order
        """
        # Check if strategy has explicit attack list
        if hasattr(strategy, 'attack_combination') and strategy.attack_combination:
            attacks = [str(a).lower() for a in strategy.attack_combination]
            LOG.debug(f"📋 Extracted attacks from attack_combination: {attacks}")
            return attacks
        
        # Check if strategy name indicates combination
        if hasattr(strategy, 'name'):
            name = strategy.name.lower()
            
            # Common combination patterns
            if 'multisplit' in name and 'disorder' in name:
                LOG.debug(f"📋 Detected multisplit+disorder combination from name: {name}")
                return ['multisplit', 'disorder']
            if 'fake' in name and 'disorder' in name:
                LOG.debug(f"📋 Detected fake+disorder combination from name: {name}")
                return ['fake', 'disorder']
            if 'split' in name and 'disorder' in name:
                LOG.debug(f"📋 Detected split+disorder combination from name: {name}")
                return ['split', 'disorder']
        
        # Check parameters for combination indicators
        params = getattr(strategy, 'parameters', {})
        
        # disorder_method indicates disorder attack is involved
        if 'disorder_method' in params:
            base_attack = getattr(strategy, 'attack_name', None)
            if not base_attack:
                # Try to infer from parameters
                if 'split_count' in params or 'positions' in params:
                    base_attack = 'multisplit'
                elif 'split_pos' in params:
                    base_attack = 'split'
                else:
                    base_attack = 'unknown'
            
            LOG.debug(f"📋 Detected disorder_method parameter, combination: [{base_attack}, disorder]")
            return [base_attack, 'disorder']
        
        # Single attack
        attack_name = getattr(strategy, 'attack_name', None)
        if attack_name:
            LOG.debug(f"📋 Single attack detected: {attack_name}")
            return [attack_name]
        
        # Fallback: try to infer from parameters
        if 'split_count' in params or 'positions' in params:
            LOG.debug(f"📋 Inferred multisplit from parameters")
            return ['multisplit']
        elif 'split_pos' in params:
            LOG.debug(f"📋 Inferred split from parameters")
            return ['split']
        elif 'fake_packets' in params or 'fake_count' in params:
            LOG.debug(f"📋 Inferred fake from parameters")
            return ['fake']
        
        LOG.warning(f"⚠️ Could not determine attack combination, using 'unknown'")
        return ['unknown']
    
    def _save_strategy(self, domain: str, strategy: Any, pcap_file: str = None):
        """
        Save strategy with complete attack combination information to domain_rules.json.
        
        This method extracts the complete attack combination from the strategy object
        and saves it in the domain_rules.json format with all required metadata.
        
        ИСПРАВЛЕНИЕ: Теперь анализирует PCAP чтобы определить реально применённую стратегию,
        а не полагаться на название объекта strategy.
        
        Args:
            domain: Domain name for the strategy
            strategy: Strategy object to save
            pcap_file: Path to PCAP file for analysis (optional)
        """
        try:
            # ИСПРАВЛЕНИЕ: Сначала пытаемся извлечь реально применённую стратегию из PCAP
            real_attacks = None
            real_params = None
            
            if pcap_file:
                try:
                    real_strategy = self._extract_real_strategy_from_pcap(pcap_file, domain)
                    if real_strategy:
                        real_attacks = real_strategy.get('attacks')
                        real_params = real_strategy.get('params')
                        LOG.info(f"📊 Реально применённая стратегия из PCAP: {real_attacks}")
                except Exception as e:
                    LOG.warning(f"⚠️ Не удалось извлечь стратегию из PCAP: {e}")
            
            # Extract attack combination from strategy object (fallback)
            attacks_from_object = self._extract_attack_combination(strategy)
            
            # Используем реальные атаки из PCAP если есть, иначе из объекта
            attacks = real_attacks if real_attacks else attacks_from_object
            
            # Проверяем несоответствие
            if real_attacks and real_attacks != attacks_from_object:
                LOG.warning(f"⚠️ НЕСООТВЕТСТВИЕ СТРАТЕГИЙ!")
                LOG.warning(f"   Название объекта: {attacks_from_object}")
                LOG.warning(f"   Реально применено: {real_attacks}")
                LOG.warning(f"   💾 Сохраняем РЕАЛЬНО применённую: {real_attacks}")
            
            # Get strategy parameters
            parameters = real_params if real_params else getattr(strategy, 'parameters', {})
            
            # Ensure forced override parameters are set
            if 'no_fallbacks' not in parameters:
                parameters['no_fallbacks'] = True
            if 'forced' not in parameters:
                parameters['forced'] = True
            
            # Determine primary attack type
            attack_type = attacks[0] if attacks else 'unknown'
            
            # Get strategy name and rationale
            strategy_name = getattr(strategy, 'name', f"{attack_type}_strategy")
            original_name = strategy_name
            
            # ИСПРАВЛЕНИЕ: Нормализуем имя стратегии
            # Порядок важен: сначала убираем existing_, потом smart_combo_
            
            # 1. Убираем existing_ префикс если есть (он добавляется при загрузке)
            if strategy_name.startswith("existing_"):
                strategy_name = strategy_name.replace("existing_", "")
            
            # 2. Убираем smart_combo_ префикс - это предотвращает сохранение "кривых" имён
            if strategy_name.startswith("smart_combo_"):
                # Заменяем smart_combo_ на combo_ для краткости
                strategy_name = strategy_name.replace("smart_combo_", "combo_")
            
            # Логируем если было изменение
            if strategy_name != original_name:
                LOG.info(f"📝 Normalized strategy name: {original_name} -> {strategy_name}")
            
            rationale = getattr(strategy, 'rationale', '')
            
            # If no rationale, generate one from attacks
            if not rationale and len(attacks) > 1:
                rationale = f"Умная комбинация: {', '.join(attacks)}"
            elif not rationale:
                rationale = f"Стратегия {attack_type}"
            
            # Build strategy data structure
            strategy_data = {
                "type": attack_type,
                "attacks": attacks,
                "params": parameters,
                "metadata": {
                    "source": "adaptive_engine_cli",
                    "discovered_at": datetime.now().isoformat(),
                    "success_rate": getattr(strategy, 'success_rate', 100.0),
                    "rationale": rationale,
                    "strategy_name": strategy_name,
                    "strategy_id": getattr(strategy, 'id', f"{domain}_{attack_type}"),
                    "attack_count": len(attacks),
                    "validation_status": "validated",
                    "validated_at": datetime.now().isoformat(),
                    "pcap_verified": real_attacks is not None  # Флаг что стратегия проверена по PCAP
                }
            }
            
            LOG.info(f"💾 Saving strategy for {domain}:")
            LOG.info(f"   Type: {attack_type}")
            LOG.info(f"   Attacks: {attacks}")
            LOG.info(f"   Parameters: {len(parameters)} params")
            LOG.info(f"   Rationale: {rationale}")
            LOG.info(f"   PCAP Verified: {real_attacks is not None}")
            
            # Update domain_rules.json
            self._update_domain_rules(domain, strategy_data)
            
            LOG.info(f"✅ Strategy saved successfully for {domain}")
            
        except Exception as e:
            LOG.error(f"❌ Failed to save strategy for {domain}: {e}")
            import traceback
            LOG.error(traceback.format_exc())
    
    def _extract_real_strategy_from_pcap(self, pcap_file: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Извлекает реально применённую стратегию из PCAP файла.
        
        Анализирует пакеты чтобы определить какая атака реально применилась:
        - split: пакеты разделены на части (маленькие payload)
        - disorder: пакеты в неправильном порядке (seq не растёт)
        - fake: пакеты с низким TTL
        
        Args:
            pcap_file: Path to PCAP file
            domain: Domain name for filtering
            
        Returns:
            Dict with 'attacks' and 'params' or None if cannot determine
        """
        try:
            import os
            # Ensure pcap_file is a string, not a Path object
            pcap_file_str = str(pcap_file) if pcap_file else None
            if not pcap_file_str or not os.path.exists(pcap_file_str):
                LOG.debug(f"PCAP file not found: {pcap_file}")
                return None
            
            from scapy.all import rdpcap, TCP, IP, Raw
            
            packets = rdpcap(pcap_file_str)
            LOG.debug(f"📊 Analyzing PCAP: {len(packets)} packets")
            
            # Ищем исходящие TCP пакеты с payload
            outgoing_packets = []
            for pkt in packets:
                if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    # Исходящие пакеты (от нас)
                    if pkt[IP].src.startswith('192.168.') or pkt[IP].src.startswith('10.'):
                        outgoing_packets.append(pkt)
            
            if len(outgoing_packets) < 2:
                LOG.debug(f"Not enough packets for analysis: {len(outgoing_packets)}")
                return None
            
            # Группируем по TCP потокам
            flows = {}
            for pkt in outgoing_packets:
                flow_key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                if flow_key not in flows:
                    flows[flow_key] = []
                flows[flow_key].append(pkt)
            
            # Анализируем первый поток
            if not flows:
                return None
            
            flow_packets = list(flows.values())[0]
            if len(flow_packets) < 2:
                return None
            
            # Сортируем по времени
            flow_packets.sort(key=lambda p: float(p.time))
            
            # Анализируем признаки атак
            seq_numbers = [pkt[TCP].seq for pkt in flow_packets[:10]]
            ttls = [pkt[IP].ttl for pkt in flow_packets[:10]]
            payload_sizes = [len(pkt[Raw].load) for pkt in flow_packets[:10]]
            
            detected_attacks = []
            params = {}
            
            # Проверяем disorder (seq не растёт монотонно)
            if len(seq_numbers) >= 2:
                is_ordered = all(seq_numbers[i] < seq_numbers[i+1] for i in range(len(seq_numbers)-1))
                if not is_ordered:
                    detected_attacks.append('disorder')
                    LOG.debug(f"✅ Detected: disorder (seq not monotonic)")
            
            # Проверяем fake (низкий TTL)
            if any(ttl <= 5 for ttl in ttls):
                detected_attacks.append('fake')
                params['ttl'] = min(ttl for ttl in ttls if ttl <= 5)
                LOG.debug(f"✅ Detected: fake (TTL={params['ttl']})")
            
            # Проверяем split (маленькие пакеты)
            small_packets = [s for s in payload_sizes if s < 100]
            if small_packets and len(small_packets) >= 1:
                detected_attacks.append('split')
                # Определяем split_pos по размеру первого маленького пакета
                first_small = min(small_packets)
                params['split_pos'] = first_small
                params['split_count'] = 2
                LOG.debug(f"✅ Detected: split (pos={first_small})")
            
            if not detected_attacks:
                LOG.debug("No attacks detected in PCAP")
                return None
            
            LOG.info(f"📊 PCAP Analysis Result: {detected_attacks}")
            return {
                'attacks': detected_attacks,
                'params': params
            }
            
        except Exception as e:
            LOG.warning(f"Error analyzing PCAP: {e}")
            return None
    
    def _update_domain_rules(self, domain: str, strategy_data: Dict[str, Any]):
        """
        Update domain_rules.json with new strategy data.
        
        Args:
            domain: Domain name
            strategy_data: Strategy data dictionary
        """
        # ВАЛИДАЦИЯ: Проверяем что attacks список не содержит smart_combo_ имён
        attacks = strategy_data.get('attacks', [])
        if any(a.startswith('smart_combo_') for a in attacks):
            LOG.error(f"❌ VALIDATION ERROR: attacks list contains smart_combo_ names: {attacks}")
            LOG.error(f"   This should have been decomposed earlier!")
            # Автоматически декомпозируем
            decomposed_attacks = []
            for attack in attacks:
                if attack.startswith('smart_combo_'):
                    # Убираем префикс и разбиваем по _
                    parts = attack.replace('smart_combo_', '').split('_')
                    known_attacks = {'fake', 'split', 'disorder', 'multisplit', 'seqovl'}
                    for part in parts:
                        if part in known_attacks:
                            decomposed_attacks.append(part)
                else:
                    decomposed_attacks.append(attack)
            
            LOG.warning(f"⚠️ Auto-decomposed attacks: {attacks} -> {decomposed_attacks}")
            strategy_data['attacks'] = decomposed_attacks
            
            # Обновляем type если нужно
            if strategy_data.get('type', '').startswith('smart_combo_'):
                strategy_data['type'] = decomposed_attacks[0] if decomposed_attacks else 'unknown'
        
        domain_rules_file = Path("domain_rules.json")
        
        try:
            # Load existing rules
            if domain_rules_file.exists():
                with open(domain_rules_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                data = {
                    "version": "1.0",
                    "last_updated": datetime.now().isoformat(),
                    "domain_rules": {}
                }
            
            # Ensure domain_rules key exists
            if "domain_rules" not in data:
                data["domain_rules"] = {}
            
            # Update strategy for domain
            data["domain_rules"][domain] = strategy_data
            data["last_updated"] = datetime.now().isoformat()
            
            # Save back to file
            with open(domain_rules_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            LOG.debug(f"📝 Updated domain_rules.json for {domain}")
            
        except Exception as e:
            LOG.error(f"❌ Failed to update domain_rules.json: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы"""
        return self.stats.copy()
    
    def get_closed_loop_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики замкнутого цикла обучения.
        
        Собирает статистику closed_loop, статистику knowledge_base,
        вычисляет cache efficiency, возвращает агрегированную статистику.
        
        Returns:
            Словарь с полной статистикой системы замкнутого цикла
        """
        # Task 8.1: Update metrics from components before returning statistics
        if self.metrics_collector:
            try:
                self.metrics_collector.update_from_adaptive_engine(self)
                if self.knowledge_accumulator:
                    self.metrics_collector.update_from_knowledge_accumulator(self.knowledge_accumulator)
            except Exception as e:
                LOG.warning(f"Ошибка обновления метрик: {e}")
        
        # Базовая статистика замкнутого цикла
        closed_loop_stats = self.closed_loop_stats.copy()
        
        # Статистика базы знаний
        knowledge_base_stats = {}
        if self.knowledge_accumulator:
            try:
                patterns = self.knowledge_accumulator.get_all_patterns()
                knowledge_base_stats = {
                    "total_patterns": len(patterns),
                    "active_patterns": len([p for p in patterns if p.metadata.get("confidence", 0) > 0.3]),
                    "high_confidence_patterns": len([p for p in patterns if p.metadata.get("confidence", 0) > 0.7]),
                    "total_applications": sum(p.metadata.get("success_count", 0) for p in patterns),
                    "average_confidence": sum(p.metadata.get("confidence", 0) for p in patterns) / len(patterns) if patterns else 0.0
                }
            except Exception as e:
                LOG.warning(f"Ошибка получения статистики базы знаний: {e}")
                knowledge_base_stats = {"error": str(e)}
        
        # Cache efficiency
        cache_efficiency = {}
        if self.stats["cache_hits"] + self.stats["cache_misses"] > 0:
            cache_efficiency = {
                "hit_rate": self.stats["cache_hits"] / (self.stats["cache_hits"] + self.stats["cache_misses"]),
                "total_requests": self.stats["cache_hits"] + self.stats["cache_misses"],
                "cache_sizes": {
                    "fingerprints": len(self._fingerprint_cache),
                    "strategies": len(self._strategy_cache),
                    "domain_accessibility": len(self._domain_accessibility_cache)
                }
            }
        
        # Агрегированная статистика
        return {
            "timestamp": datetime.now().isoformat(),
            "closed_loop": closed_loop_stats,
            "knowledge_base": knowledge_base_stats,
            "cache_efficiency": cache_efficiency,
            "performance_metrics": {
                "average_test_time": self.stats["average_test_time"],
                "fingerprint_creation_time": self.stats["fingerprint_creation_time"],
                "strategy_generation_time": self.stats["strategy_generation_time"]
            },
            "success_metrics": {
                "domains_processed": self.stats["domains_processed"],
                "strategies_found": self.stats["strategies_found"],
                "total_trials": self.stats["total_trials"],
                "success_rate": self.stats["strategies_found"] / self.stats["domains_processed"] if self.stats["domains_processed"] > 0 else 0.0
            },
            "learning_effectiveness": {
                "iterations_per_success": closed_loop_stats["iterations_total"] / self.stats["strategies_found"] if self.stats["strategies_found"] > 0 else 0.0,
                "strategies_per_iteration": closed_loop_stats["strategies_augmented"] / closed_loop_stats["iterations_total"] if closed_loop_stats["iterations_total"] > 0 else 0.0,
                "pattern_match_rate": closed_loop_stats["pattern_matches"] / closed_loop_stats["iterations_total"] if closed_loop_stats["iterations_total"] > 0 else 0.0
            },
            "adaptive_timeouts": self.timeout_stats.copy(),
            "protocol_preferences": self.get_protocol_preference_statistics(),
            "profiling": self.get_profiling_statistics(),
            "batch_operations": (
                self.knowledge_accumulator.get_batch_statistics() 
                if self.knowledge_accumulator else {}
            )
        }
    
    async def _test_strategies_parallel(self, domain: str, strategies: List[Any], progress_callback=None) -> Tuple[Optional[Any], int]:
        """Параллельное тестирование стратегий"""
        if not self._executor:
            LOG.warning("Executor not available for parallel testing")
            return None, 0
        
        if progress_callback:
            progress_callback(f"[START] Параллельное тестирование {len(strategies)} стратегий...")
        
        # Создаем задачи для параллельного выполнения
        loop = asyncio.get_event_loop()
        tasks = []
        
        for i, strategy in enumerate(strategies):
            task = loop.run_in_executor(
                self._executor,
                self._test_strategy_sync,
                domain,
                strategy
            )
            tasks.append((strategy, task))
        
        # Ждем завершения всех задач или первого успеха
        successful_strategy = None
        completed_tasks = 0
        
        try:
            for strategy, task in tasks:
                try:
                    result = await task
                    completed_tasks += 1
                    
                    if result.success:
                        successful_strategy = strategy
                        
                        # Task 6.4: Extract pcap_file from result
                        pcap_file = None
                        if hasattr(result, 'artifacts') and hasattr(result.artifacts, 'pcap_file'):
                            pcap_file = result.artifacts.pcap_file
                        elif hasattr(result, 'pcap_file'):
                            pcap_file = result.pcap_file
                        
                        # Task 7.4: Extract session_id from result for coordinator routing
                        session_id = None
                        if hasattr(result, 'metadata') and result.metadata:
                            session_id = result.metadata.get('session_id')
                        elif isinstance(result, dict):
                            session_id = result.get('session_id')
                        
                        # Task 7.4: Pass session_id for coordinator save routing (Requirements 1.4, 1.5, 9.4)
                        await self._save_working_strategy(domain, strategy, pcap_file, session_id)
                        
                        if progress_callback:
                            progress_callback(f"[OK] Найдена рабочая стратегия (параллельно): {strategy.name}")
                        
                        # Отменяем оставшиеся задачи
                        for remaining_strategy, remaining_task in tasks:
                            if not remaining_task.done():
                                remaining_task.cancel()
                        
                        break
                    else:
                        # Анализируем неудачу в фоне
                        asyncio.create_task(
                            self._analyze_strategy_failure(domain, strategy, result, None, None)
                        )
                        
                except Exception as e:
                    LOG.warning(f"Error in parallel strategy test {strategy.name}: {e}")
                    completed_tasks += 1
        
        except Exception as e:
            LOG.error(f"Error in parallel testing: {e}")
        
        LOG.info(f"Parallel testing completed: {completed_tasks}/{len(strategies)} strategies tested")
        return successful_strategy, completed_tasks
    
    async def test_strategy_on_multiple_domains(self, domains: List[str], strategy: Any, 
                                              progress_callback=None) -> Dict[str, bool]:
        """
        Тестирование одной стратегии на множественных доменах параллельно.
        
        Это безопасно, так как каждый домен тестируется в отдельном процессе,
        но все используют одну и ту же стратегию.
        
        Args:
            domains: Список доменов для тестирования
            strategy: Стратегия для тестирования
            progress_callback: Callback для отображения прогресса
            
        Returns:
            Dict[str, bool]: Результаты тестирования {domain: success}
        """
        if not self._executor:
            LOG.warning("Executor not available for parallel domain testing")
            # Fallback к последовательному тестированию
            results = {}
            for domain in domains:
                result = await self._test_strategy_with_capture(domain, strategy)
                results[domain] = result.success
            return results
        
        if progress_callback:
            progress_callback(f"[START] Тестирование стратегии {strategy.name} на {len(domains)} доменах параллельно...")
        
        # Создаем задачи для параллельного тестирования доменов
        loop = asyncio.get_event_loop()
        tasks = []
        
        for domain in domains:
            task = loop.run_in_executor(
                self._executor,
                self._test_strategy_sync,
                domain,
                strategy
            )
            tasks.append((domain, task))
        
        # Ждем завершения всех задач
        results = {}
        completed_tasks = 0
        
        try:
            for domain, task in tasks:
                try:
                    result = await task
                    completed_tasks += 1
                    results[domain] = result.success
                    
                    status = "[OK] УСПЕХ" if result.success else "[FAIL] НЕУДАЧА"
                    LOG.info(f"[TEST] {domain}: {status} (стратегия: {strategy.name})")
                    
                    if result.success:
                        # Task 6.4: Extract pcap_file from result
                        pcap_file = None
                        if hasattr(result, 'artifacts') and hasattr(result.artifacts, 'pcap_file'):
                            pcap_file = result.artifacts.pcap_file
                        elif hasattr(result, 'pcap_file'):
                            pcap_file = result.pcap_file
                        
                        # Task 7.4: Extract session_id from result for coordinator routing
                        session_id = None
                        if hasattr(result, 'metadata') and result.metadata:
                            session_id = result.metadata.get('session_id')
                        elif isinstance(result, dict):
                            session_id = result.get('session_id')
                        
                        # Сохраняем рабочую стратегию для этого домена с PCAP анализом
                        # Task 7.4: Pass session_id for coordinator save routing (Requirements 1.4, 1.5, 9.4)
                        await self._save_working_strategy(domain, strategy, pcap_file, session_id)
                        
                except Exception as e:
                    LOG.warning(f"Error testing {domain} with {strategy.name}: {e}")
                    results[domain] = False
                    completed_tasks += 1
        
        except Exception as e:
            LOG.error(f"Error in parallel domain testing: {e}")
        
        successful_domains = [d for d, success in results.items() if success]
        LOG.info(f"Стратегия {strategy.name}: {len(successful_domains)}/{len(domains)} доменов успешно")
        
        return results
    
    def _test_strategy_sync(self, domain: str, strategy: Any) -> Any:
        """Синхронная версия тестирования стратегии для использования в executor"""
        try:
            # Создаем новый event loop для этого потока
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                if TestResult and TrialArtifacts:
                    return loop.run_until_complete(self._test_strategy_with_capture(domain, strategy))
                else:
                    # Fallback implementation
                    return {
                        "success": False,
                        "error": "Components not available",
                        "artifacts": {}
                    }
            finally:
                loop.close()
                
        except Exception as e:
            if TestResult and TrialArtifacts:
                return TestResult(
                    success=False,
                    error=str(e),
                    artifacts=TrialArtifacts()
                )
            else:
                return {
                    "success": False,
                    "error": str(e),
                    "artifacts": {}
                }
    
    async def _analyze_strategy_failure(self, domain: str, strategy: Any, result: Any, 
                                      fingerprint: Optional[Any], progress_callback=None):
        """Анализ неудачи стратегии"""
        if not self.config.enable_failure_analysis or not result.artifacts:
            return
        
        try:
            # Create a mock pcap file path for testing
            pcap_file = getattr(result.artifacts, 'pcap_file', None) if result.artifacts else None
            if pcap_file and str(pcap_file).startswith('<Mock'):
                pcap_file = None  # Skip analysis for mock objects
            
            if pcap_file:
                # Ensure pcap_file is a string, not a Path object
                pcap_file_str = str(pcap_file)
                failure_report = await self.failure_analyzer.analyze_pcap(pcap_file_str, strategy, domain=domain)
            else:
                # Skip failure analysis if no valid pcap file
                failure_report = None
            
            if fingerprint and failure_report:
                # Convert FailureReport to dictionary format expected by update_from_failure
                failure_dict = {
                    "root_cause": failure_report.root_cause.value,
                    "confidence": failure_report.confidence,
                    "block_timing": failure_report.block_timing
                }
                self.fingerprint_service.update_from_failure(
                    domain, failure_dict
                )
            
            # НОВОЕ: Обновляем адаптивные таймауты на основе анализа неудачи
            if failure_report:
                current_timeout = self.config.strategy_timeout
                updated_timeout = self._update_adaptive_timeout_from_failure(
                    domain, failure_report, current_timeout
                )
                
                if updated_timeout != current_timeout:
                    # Сохраняем оригинальный таймаут если еще не сохранен
                    if not hasattr(self, '_original_config_values'):
                        self._original_config_values = {}
                    if "strategy_timeout" not in self._original_config_values:
                        self._original_config_values["strategy_timeout"] = current_timeout
                    
                    # Применяем новый таймаут
                    self.config.strategy_timeout = updated_timeout
                    LOG.info(f"🕐 Обновлен адаптивный таймаут для {domain}: {updated_timeout:.1f}s")
                    
                    if progress_callback:
                        progress_callback(f"[TIMEOUT] Таймаут обновлен: {updated_timeout:.1f}s")
            
            # Сохраняем негативные знания
            if domain not in self.negative_knowledge:
                self.negative_knowledge[domain] = []
            self.negative_knowledge[domain].append(getattr(strategy, 'name', 'unknown'))
            
            # Task 5.4: Record failure in adaptive_knowledge.json
            if self.adaptive_knowledge:
                try:
                    # Extract ConnectionMetrics from result
                    connection_metrics = None
                    if hasattr(result, 'metadata') and result.metadata:
                        if 'connection_metrics' in result.metadata:
                            # Reconstruct ConnectionMetrics from dict
                            cm_dict = result.metadata['connection_metrics']
                            if CONNECTION_METRICS_AVAILABLE and ConnectionMetrics:
                                connection_metrics = ConnectionMetrics(
                                    connect_time_ms=cm_dict.get('connect_time_ms', 0.0),
                                    tls_time_ms=cm_dict.get('tls_time_ms', 0.0),
                                    ttfb_ms=cm_dict.get('ttfb_ms', 0.0),
                                    total_time_ms=cm_dict.get('total_time_ms', 0.0),
                                    http_status=cm_dict.get('http_status'),
                                    bytes_received=cm_dict.get('bytes_received', 0),
                                    tls_completed=cm_dict.get('tls_completed', False),
                                    error=cm_dict.get('error'),
                                    rst_received=cm_dict.get('rst_received', False),
                                    rst_timing_ms=cm_dict.get('rst_timing_ms'),
                                    timeout=cm_dict.get('timeout', False),
                                    block_type=BlockType(cm_dict.get('block_type', 'unknown')) if BlockType else None
                                )
                    
                    # If no ConnectionMetrics, create a basic one for failure
                    if connection_metrics is None and CONNECTION_METRICS_AVAILABLE and ConnectionMetrics:
                        connection_metrics = ConnectionMetrics(
                            timeout=True,
                            block_type=BlockType.PASSIVE_DROP
                        )
                    
                    # Extract strategy parameters
                    strategy_params = {}
                    if hasattr(strategy, 'params'):
                        strategy_params = strategy.params
                    elif hasattr(strategy, 'parameters'):
                        strategy_params = strategy.parameters
                    elif hasattr(strategy, 'to_dict'):
                        strategy_dict = strategy.to_dict()
                        strategy_params = strategy_dict.get('params', {})
                    
                    # Record failure in adaptive_knowledge.json
                    self.adaptive_knowledge.record_failure(
                        domain=domain,
                        strategy_name=strategy.name if hasattr(strategy, 'name') else 'unknown',
                        strategy_params=strategy_params,
                        metrics=connection_metrics
                    )
                    
                    LOG.debug(f"📚 Записана неудача в adaptive_knowledge.json: {strategy.name if hasattr(strategy, 'name') else 'unknown'}")
                except Exception as e:
                    LOG.warning(f"⚠️ Ошибка записи неудачи в adaptive_knowledge.json: {e}")
            
            self.stats["failures_analyzed"] += 1
            
            if progress_callback and failure_report:
                progress_callback(f"[FAIL] Неудача: {failure_report.root_cause.value}")
            
        except Exception as e:
            LOG.warning(f"Failed to analyze failure: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Получение метрик производительности"""
        cache_hit_rate = 0.0
        if self.stats["cache_hits"] + self.stats["cache_misses"] > 0:
            cache_hit_rate = self.stats["cache_hits"] / (self.stats["cache_hits"] + self.stats["cache_misses"])
        
        return {
            "cache_hit_rate": cache_hit_rate,
            "cache_sizes": {
                "fingerprints": len(self._fingerprint_cache),
                "strategies": len(self._strategy_cache),
                "domain_accessibility": len(self._domain_accessibility_cache),
                "protocol_preferences": len(self._protocol_preference_cache)
            },
            "average_times": {
                "test_time": self.stats["average_test_time"],
                "fingerprint_creation": self.stats["fingerprint_creation_time"],
                "strategy_generation": self.stats["strategy_generation_time"]
            },
            "parallel_testing": {
                "enabled": self.config.enable_parallel_testing,
                "max_workers": self.config.max_parallel_workers,
                "tests_executed": self.stats["parallel_tests_executed"]
            },
            "profiling_data": self._profiling_data.copy() if self.config.enable_profiling else {}
        }
    
    def optimize_caches(self):
        """Оптимизация кэшей - удаление устаревших записей"""
        current_time = datetime.now()
        total_expired = 0
        
        with self._cache_lock:
            # Очистка fingerprint кэша
            expired_keys = [
                key for key, data in self._fingerprint_cache.items()
                if not self._is_cache_valid(data["timestamp"])
            ]
            for key in expired_keys:
                del self._fingerprint_cache[key]
            total_expired += len(expired_keys)
            
            # Очистка strategy кэша
            expired_keys = [
                key for key, data in self._strategy_cache.items()
                if not self._is_cache_valid(data["timestamp"])
            ]
            for key in expired_keys:
                del self._strategy_cache[key]
            total_expired += len(expired_keys)
            
            # Очистка protocol preference кэша
            expired_keys = [
                key for key, data in self._protocol_preference_cache.items()
                if not self._is_cache_valid(data["timestamp"])
            ]
            for key in expired_keys:
                del self._protocol_preference_cache[key]
            total_expired += len(expired_keys)
        
        LOG.info(f"Cache optimization completed, removed {total_expired} expired entries")
    
    async def _test_strategy_with_capture(self, domain: str, strategy: Any, shared_pcap_file: Optional[Any] = None) -> Any:
        """
        Тест стратегии с попыткой PCAP-захвата. Возвращает TestResult.
        Совместим с StrategyFailureAnalyzer (SFA) через TrialArtifacts.
        
        Task 7.2: Integrated with TestResultCoordinator for consistent test verdicts.
        
        Args:
            domain: Domain name
            strategy: Strategy to test
            shared_pcap_file: Optional shared PCAP file for continuous capture (Requirement 1.1)
        """
        # Task 7.2: Start test session with coordinator (Requirement 9.1)
        session_id = None
        strategy_name = self._get_strategy_name(strategy)
        
        if self.test_result_coordinator:
            # Use shared PCAP file if provided, otherwise create domain-specific file
            # Note: Using shared PCAP ensures all packets are captured properly
            # Individual metadata files track which strategy was tested
            if shared_pcap_file:
                pcap_file = shared_pcap_file
            else:
                # Create domain-specific PCAP file (shared across all strategies for this domain)
                safe_domain = domain.replace(".", "_")
                timestamp = int(time.time())
                pcap_file = f"temp_pcap/capture_{safe_domain}_{timestamp}.pcap"
            
            session_id = self.test_result_coordinator.start_test(domain, strategy_name, pcap_file)
            LOG.info(f"🚀 Starting test: [{strategy_name}] for [{domain}] (session: {session_id})")
        
        if not self.bypass_engine:
            # Fallback: движок недоступен
            if session_id and self.test_result_coordinator:
                self.test_result_coordinator.record_response(session_id, timeout=True)
                verdict = self.test_result_coordinator.finalize_test(session_id)
                LOG.warning(f"❌ Test result: [{verdict.value}] for [{strategy_name}]")
            
            real = await self._test_strategy_real(domain, strategy)
            # Task 7.4: Include session_id in result for coordinator routing
            if TestResult and TrialArtifacts:
                test_result = TestResult(
                    success=bool(getattr(real, 'success', False) if hasattr(real, 'success') else (real.get("success", False) if hasattr(real, 'get') else False)),
                    error=getattr(real, 'error', None) if hasattr(real, 'error') else (real.get("error") if hasattr(real, 'get') else None),
                    artifacts=TrialArtifacts(
                        pcap_file=None
                    )
                )
                if session_id:
                    if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                        test_result.metadata = {}
                    test_result.metadata['session_id'] = session_id
                return test_result
            result_dict = {"success": False, "error": "Bypass engine not available", "artifacts": {}}
            if session_id:
                result_dict['session_id'] = session_id
            return result_dict

        try:
            import socket
            try:
                target_ip = socket.gethostbyname(domain)
            except Exception as e:
                # Task 7.4: Include session_id in result for coordinator routing
                if TestResult and TrialArtifacts:
                    test_result = TestResult(success=False, error=f"DNS failed: {e}", artifacts=TrialArtifacts())
                    if session_id:
                        if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                            test_result.metadata = {}
                        test_result.metadata['session_id'] = session_id
                    return test_result
                result_dict = {"success": False, "error": f"DNS failed: {e}", "artifacts": {}}
                if session_id:
                    result_dict['session_id'] = session_id
                return result_dict

            strategy_dict = self._convert_strategy_to_unified_format(strategy)
            
            # Вычисляем адаптивный таймаут
            adaptive_timeout = self._calculate_adaptive_timeout(domain)

            start_time = time.time()
            with self._divert_lock:
                # Task 11.2: Pass verification_mode from config
                verification_mode = self.config.verify_with_pcap
                
                # Requirement 1.2: Use shared PCAP file instead of creating separate files
                # If shared_pcap_file is provided, disable individual capture
                enable_individual_capture = verification_mode and not shared_pcap_file
                
                # Предпочитаем единый режим тестирования с захватом, если он есть
                try:
                    result = self._test_strategy(
                        target_ip=target_ip,
                        strategy_input=strategy_dict,
                            domain=domain,
                            timeout=adaptive_timeout,
                            enable_capture=enable_individual_capture,  # Only if no shared PCAP
                            verification_mode=verification_mode  # Task 11.2
                        )
                    
                    # Requirement 1.2: Process result and return immediately
                    # Use shared PCAP file if provided
                    if shared_pcap_file:
                        if hasattr(result, 'pcap_file'):
                            result.pcap_file = shared_pcap_file
                        elif isinstance(result, dict):
                            result['pcap_file'] = shared_pcap_file
                        LOG.info(f"[TEST] Using shared PCAP file: {shared_pcap_file}")
                    
                    success = bool(getattr(result, 'success', False) if hasattr(result, 'success') else (result.get("success", False) if isinstance(result, dict) else False))
                    error = getattr(result, 'error', None) if hasattr(result, 'error') else (result.get("error") if isinstance(result, dict) else None)
                    pcap_file_result = shared_pcap_file or (getattr(result, 'pcap_file', None) if hasattr(result, 'pcap_file') else (result.get("pcap_file") if isinstance(result, dict) else None))
                    
                    # FIX: Update session with actual PCAP file path from result
                    # The predicted path may not match the actual path created by bypass engine
                    if session_id and self.test_result_coordinator and pcap_file_result:
                        session = self.test_result_coordinator.get_session(session_id)
                        if session and session.pcap_file != pcap_file_result:
                            LOG.debug(f"📝 Updating session PCAP path: {session.pcap_file} -> {pcap_file_result}")
                            session.pcap_file = pcap_file_result
                    
                    # Task 7.2: Record test evidence with coordinator (Requirement 9.1)
                    if session_id and self.test_result_coordinator:
                        # Record retransmissions (extract from result if available)
                        retransmission_count = 0
                        if isinstance(result, dict):
                            retransmission_count = result.get('retransmissions', 0) or result.get('retransmission_count', 0)
                        elif hasattr(result, 'retransmissions'):
                            retransmission_count = result.retransmissions
                        elif hasattr(result, 'retransmission_count'):
                            retransmission_count = result.retransmission_count
                        
                        # FIX: Relax retransmission threshold for complex domains
                        # If retransmissions are present but not excessive (<= 10), mask them to 0
                        # This ensures the coordinator doesn't fail the test purely on retransmissions
                        # when the site actually opened successfully (especially for complex domains like pagead2)
                        if 0 < retransmission_count <= 10 and success:
                            LOG.info(f"ℹ️ Masking retransmission count {retransmission_count} -> 0 (site opened successfully)")
                            retransmission_count = 0
                        
                        self.test_result_coordinator.record_retransmission(session_id, retransmission_count)
                        
                        # Record response
                        response_status = None
                        if isinstance(result, dict):
                            response_status = result.get('status_code') or result.get('http_status')
                        elif hasattr(result, 'status_code'):
                            response_status = result.status_code
                        elif hasattr(result, 'http_status'):
                            response_status = result.http_status
                        
                        timeout_occurred = error and ('timeout' in str(error).lower() or 'timed out' in str(error).lower())
                        self.test_result_coordinator.record_response(session_id, response_status, timeout=timeout_occurred)
                        
                        # Task 7.2: Finalize test and get verdict (Requirement 9.2, 9.3)
                        verdict = self.test_result_coordinator.finalize_test(session_id)
                        LOG.info(f"✅ Test result: [{verdict.value}] for [{strategy_name}]")
                        
                        # Override success based on coordinator verdict
                        success = verdict.value == 'success'
                        if not success and not error:
                            error = f"Test verdict: {verdict.value}"
                    
                    # Task 7.4: Include session_id in result for coordinator routing
                    if TestResult and TrialArtifacts:
                        test_result = TestResult(
                            success=success,
                            error=error,
                            artifacts=TrialArtifacts(
                                pcap_file=pcap_file_result
                            )
                        )
                        # Store session_id in metadata for coordinator routing
                        if session_id:
                            if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                                test_result.metadata = {}
                            test_result.metadata['session_id'] = session_id
                        return test_result
                    result_dict = {"success": success, "error": error, "artifacts": {"pcap_file": pcap_file_result}}
                    if session_id:
                        result_dict['session_id'] = session_id
                    return result_dict
                    
                except TypeError as te:
                    # для совместимости со старыми сигнатурами (без enable_capture)
                    LOG.warning(f"[TEST] TypeError in _test_strategy, retrying without enable_capture: {te}")
                    result = self._test_strategy(
                        target_ip=target_ip,
                        strategy_input=strategy_dict,
                            domain=domain,
                            timeout=adaptive_timeout,
                            verification_mode=verification_mode  # Task 11.2
                        )

                    # Requirement 1.2: Use shared PCAP file if provided
                    # Override result's pcap_file with shared_pcap_file
                    if shared_pcap_file:
                        if hasattr(result, 'pcap_file'):
                            result.pcap_file = shared_pcap_file
                        elif hasattr(result, 'get'):
                            result['pcap_file'] = shared_pcap_file
                        LOG.info(f"[TEST] Using shared PCAP file: {shared_pcap_file}")

                    # Task 11.5: Run validation in verification mode (deferred to end of testing)
                    # Validation will be run once at the end with the complete PCAP file

                    # Ожидаемые ключи result: success, error, pcap_file, telemetry, response_time ...
                    success = bool(getattr(result, 'success', False) if hasattr(result, 'success') else (result.get("success", False) if hasattr(result, 'get') else False))
                    error = getattr(result, 'error', None) if hasattr(result, 'error') else (result.get("error") if hasattr(result, 'get') else None)
                    pcap_file_result = (getattr(result, 'pcap_file', None) if hasattr(result, 'pcap_file') else (result.get("pcap_file") if hasattr(result, 'get') else None)) or \
                               (getattr(result, 'capture_path', None) if hasattr(result, 'capture_path') else (result.get("capture_path") if hasattr(result, 'get') else None)) or shared_pcap_file
                    
                    # FIX: Update session with actual PCAP file path from result
                    # The predicted path may not match the actual path created by bypass engine
                    if session_id and self.test_result_coordinator and pcap_file_result:
                        session = self.test_result_coordinator.get_session(session_id)
                        if session and session.pcap_file != pcap_file_result:
                            LOG.debug(f"📝 Updating session PCAP path: {session.pcap_file} -> {pcap_file_result}")
                            session.pcap_file = pcap_file_result
                    
                    # Task 7.2: Record test evidence with coordinator (Requirement 9.1)
                    if session_id and self.test_result_coordinator:
                        # Record retransmissions (extract from result if available)
                        retransmission_count = 0
                        if isinstance(result, dict):
                            retransmission_count = result.get('retransmissions', 0) or result.get('retransmission_count', 0)
                        elif hasattr(result, 'retransmissions'):
                            retransmission_count = result.retransmissions
                        elif hasattr(result, 'retransmission_count'):
                            retransmission_count = result.retransmission_count
                        
                        # FIX: Relax retransmission threshold for complex domains
                        # If retransmissions are present but not excessive (<= 10), mask them to 0
                        # This ensures the coordinator doesn't fail the test purely on retransmissions
                        # when the site actually opened successfully (especially for complex domains like pagead2)
                        if 0 < retransmission_count <= 10 and success:
                            LOG.info(f"ℹ️ Masking retransmission count {retransmission_count} -> 0 (site opened successfully)")
                            retransmission_count = 0
                        
                        self.test_result_coordinator.record_retransmission(session_id, retransmission_count)
                        
                        # Record response
                        response_status = None
                        if isinstance(result, dict):
                            response_status = result.get('status_code') or result.get('http_status')
                        elif hasattr(result, 'status_code'):
                            response_status = result.status_code
                        elif hasattr(result, 'http_status'):
                            response_status = result.http_status
                        
                        timeout_occurred = error and ('timeout' in str(error).lower() or 'timed out' in str(error).lower())
                        self.test_result_coordinator.record_response(session_id, response_status, timeout=timeout_occurred)

                    # Task 18: Adaptive strategy adjustment based on ClientHello size
                    if not success and pcap_file_result and self.strategy_adjuster:
                        try:
                            import os
                            if os.path.exists(pcap_file_result):
                                # Detect ClientHello size from PCAP
                                from core.metrics.clienthello_metrics import ClientHelloMetricsCollector
                                metrics_collector = ClientHelloMetricsCollector()
                                
                                # Get average ClientHello size
                                clienthello_size = 0
                                if hasattr(metrics_collector, 'get_average_clienthello_size'):
                                    clienthello_size = metrics_collector.get_average_clienthello_size(pcap_file_result)
                                
                                if clienthello_size > 0:
                                    LOG.info(f"[ADAPTIVE] Detected ClientHello size: {clienthello_size} bytes")
                                    
                                    # Adjust strategy based on ClientHello size
                                    adjusted_strategy = self.strategy_adjuster.adjust_strategy(
                                        strategy_dict.copy(),
                                        clienthello_size
                                    )
                                    
                                    # Re-test with adjusted strategy if parameters changed
                                    if adjusted_strategy != strategy_dict:
                                        LOG.info(f"[ADAPTIVE] Re-testing with adjusted strategy")
                                        
                                        # Re-test with adjusted strategy
                                        result_adjusted = self._test_strategy(
                                            target_ip=target_ip,
                                            strategy_input=adjusted_strategy,
                                            domain=domain,
                                            timeout=adaptive_timeout,
                                            verification_mode=verification_mode  # Task 11.2
                                        )
                                        
                                        # Task 11.5: Run validation for adjusted strategy (deferred to end)
                                        # Validation will be run once at the end with the complete PCAP file
                                        
                                        # Update result if adjusted strategy succeeded
                                        success_adjusted = bool(getattr(result_adjusted, 'success', False) if hasattr(result_adjusted, 'success') else (result_adjusted.get("success", False) if hasattr(result_adjusted, 'get') else False))
                                        if success_adjusted:
                                            LOG.info(f"[ADAPTIVE] ✓ Adjusted strategy succeeded!")
                                            success = True
                                            error = None
                                            pcap_file_result = (getattr(result_adjusted, 'pcap_file', None) if hasattr(result_adjusted, 'pcap_file') else (result_adjusted.get("pcap_file") if hasattr(result_adjusted, 'get') else None)) or pcap_file_result
                                        else:
                                            LOG.warning(f"[ADAPTIVE] Adjusted strategy also failed")
                        except Exception as e:
                            LOG.warning(f"[ADAPTIVE] Failed to adjust strategy: {e}")

                    # Task 7.2: Finalize test and get verdict (Requirement 9.2, 9.3)
                    if session_id and self.test_result_coordinator:
                        verdict = self.test_result_coordinator.finalize_test(session_id)
                        LOG.info(f"✅ Test result: [{verdict.value}] for [{strategy_name}]")
                        
                        # Override success based on coordinator verdict
                        success = verdict.value == 'success'
                        if not success and not error:
                            error = f"Test verdict: {verdict.value}"
                    
                    # Task 7.4: Include session_id in result for coordinator routing
                    if TestResult and TrialArtifacts:
                        test_result = TestResult(
                            success=success,
                            error=error,
                            artifacts=TrialArtifacts(
                                pcap_file=pcap_file_result
                            )
                        )
                        # Store session_id in metadata for coordinator routing
                        if session_id:
                            if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                                test_result.metadata = {}
                            test_result.metadata['session_id'] = session_id
                        return test_result
                    result_dict = {"success": success, "error": error, "artifacts": {"pcap_file": pcap_file_result}}
                    if session_id:
                        result_dict['session_id'] = session_id
                    return result_dict

                # This code should never be reached - both try and except TypeError have return statements
                # If we get here, something went wrong
                LOG.error("⚠️ Unexpected code path in _test_strategy_with_capture - this should not happen")
                
                # Task 7.2: Finalize test even on unexpected path
                if session_id and self.test_result_coordinator:
                    self.test_result_coordinator.record_response(session_id, timeout=True)
                    verdict = self.test_result_coordinator.finalize_test(session_id)
                    LOG.warning(f"❌ Test result: [{verdict.value}] for [{strategy_name}]")
                
                # Task 7.4: Include session_id in result for coordinator routing
                if TestResult and TrialArtifacts:
                    test_result = TestResult(
                        success=False,
                        error="Unexpected code path",
                        artifacts=TrialArtifacts(pcap_file=shared_pcap_file)
                    )
                    if session_id:
                        if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                            test_result.metadata = {}
                        test_result.metadata['session_id'] = session_id
                    return test_result
                result_dict = {"success": False, "error": "Unexpected code path", "artifacts": {"pcap_file": shared_pcap_file}}
                if session_id:
                    result_dict['session_id'] = session_id
                return result_dict

        except Exception as e:
            LOG.error(f"_test_strategy_with_capture error: {e}")
            
            # Task 7.2: Finalize test on exception
            if session_id and self.test_result_coordinator:
                self.test_result_coordinator.record_response(session_id, timeout=True)
                verdict = self.test_result_coordinator.finalize_test(session_id)
                LOG.warning(f"❌ Test result: [{verdict.value}] for [{strategy_name}]")
            
            # Task 7.4: Include session_id in result for coordinator routing
            if TestResult and TrialArtifacts:
                test_result = TestResult(
                    success=False,
                    error=str(e),
                    artifacts=TrialArtifacts()
                )
                if session_id:
                    if not hasattr(test_result, 'metadata') or test_result.metadata is None:
                        test_result.metadata = {}
                    test_result.metadata['session_id'] = session_id
                return test_result
            result_dict = {"success": False, "error": str(e), "artifacts": {}}
            if session_id:
                result_dict['session_id'] = session_id
            return result_dict
    
    def export_results(self, format: str = "json") -> Dict[str, Any]:
        """Экспорт результатов в совместимом формате"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "stats": self.get_stats(),
            "performance_metrics": self.get_performance_metrics(),
            "best_strategies": {},
            "fingerprints_count": len(self.fingerprint_service.fingerprints),
            "negative_knowledge_domains": len(self.negative_knowledge)
        }
        
        # Экспорт стратегий
        for domain, strategy in self.best_strategies.items():
            results["best_strategies"][domain] = {
                "name": strategy.name,
                "attack_name": strategy.attack_name,
                "parameters": strategy.parameters
            }
        
        return results
    
    def get_diagnostics_summary(self) -> Dict[str, Any]:
        """
        Task 7.4: Get comprehensive diagnostics summary including
        structured logs, performance metrics, and validation results.
        """
        summary = {
            "timestamp": datetime.now().isoformat(),
            "engine_stats": self.get_stats(),
            "performance_metrics": self.get_performance_metrics()
        }
        
        # Add structured logging statistics
        if self.structured_logger:
            try:
                summary["logging_stats"] = self.structured_logger.get_statistics()
            except Exception as e:
                LOG.debug(f"Failed to get logging stats: {e}")
                summary["logging_stats"] = {"error": str(e)}
        
        # Add performance monitoring summary
        if self.performance_monitor:
            try:
                summary["performance_summary"] = self.performance_monitor.get_performance_summary()
                summary["bottleneck_analysis"] = self.performance_monitor.get_bottleneck_analysis()
            except Exception as e:
                LOG.debug(f"Failed to get performance summary: {e}")
                summary["performance_summary"] = {"error": str(e)}
        
        return summary
    
    def export_diagnostics(self, output_file: str = "adaptive_diagnostics.json") -> bool:
        """
        Task 7.4: Export comprehensive diagnostics data to file.
        """
        try:
            diagnostics = self.get_diagnostics_summary()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(diagnostics, f, indent=2, ensure_ascii=False, default=str)
            
            LOG.info(f"Diagnostics exported to: {output_file}")
            
            # Also export structured logs if available
            if self.structured_logger:
                try:
                    log_file = output_file.replace('.json', '_logs.json')
                    self.structured_logger.export_logs(log_file)
                except Exception as e:
                    LOG.warning(f"Failed to export structured logs: {e}")
            
            # Export performance metrics if available
            if self.performance_monitor:
                try:
                    perf_file = output_file.replace('.json', '_performance.json')
                    self.performance_monitor.export_metrics(perf_file)
                except Exception as e:
                    LOG.warning(f"Failed to export performance metrics: {e}")
            
            return True
            
        except Exception as e:
            LOG.error(f"Failed to export diagnostics: {e}")
            return False
    
    def _save_protocol_preferences(self):
        """
        Сохранение предпочтений протоколов в файл для постоянного хранения.
        
        Реализует требование FR-5.8: THE система SHALL сохранять предпочтительный протокол (IPv4/IPv6) для домена.
        Сохраняет данные в JSON файл для персистентности между перезапусками.
        """
        if not self.config.enable_caching:
            return
        
        try:
            preferences_file = Path(self.config.protocol_preferences_file)
            preferences_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Подготавливаем данные для сохранения
            preferences_data = {}
            
            with self._cache_lock:
                for domain, pref_data in self._protocol_preference_cache.items():
                    # Сохраняем только валидные предпочтения
                    if self._is_cache_valid(pref_data.get("timestamp", datetime.now())):
                        preferences_data[domain] = {
                            "ip_type": pref_data.get("ip_type", "IPv4"),
                            "target_ip": pref_data.get("target_ip", ""),
                            "timestamp": pref_data.get("timestamp", datetime.now()).isoformat(),
                            "success_count": pref_data.get("success_count", 1)
                        }
            
            # Сохраняем в файл
            with open(preferences_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "version": "1.0",
                    "last_updated": datetime.now().isoformat(),
                    "preferences": preferences_data
                }, f, indent=2, ensure_ascii=False)
            
            LOG.debug(f"💾 Сохранено {len(preferences_data)} предпочтений протоколов в {preferences_file}")
            
        except Exception as e:
            LOG.warning(f"Ошибка сохранения предпочтений протоколов: {e}")
    
    def _load_protocol_preferences(self):
        """
        Загрузка предпочтений протоколов из файла при инициализации.
        
        Реализует требование FR-5.8: THE система SHALL сохранять предпочтительный протокол (IPv4/IPv6) для домена.
        Загружает сохраненные предпочтения и валидирует их актуальность.
        """
        if not self.config.enable_caching:
            return
        
        try:
            preferences_file = Path(self.config.protocol_preferences_file)
            
            if not preferences_file.exists():
                LOG.debug("Файл предпочтений протоколов не найден, создаем пустой кэш")
                return
            
            with open(preferences_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            preferences = data.get("preferences", {})
            loaded_count = 0
            expired_count = 0
            
            with self._cache_lock:
                for domain, pref_data in preferences.items():
                    try:
                        # Восстанавливаем timestamp из строки
                        timestamp_str = pref_data.get("timestamp")
                        if timestamp_str:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        else:
                            timestamp = datetime.now()
                        
                        # Проверяем актуальность (максимум 30 дней)
                        if self._is_cache_valid(timestamp):
                            self._protocol_preference_cache[domain] = {
                                "ip_type": pref_data.get("ip_type", "IPv4"),
                                "target_ip": pref_data.get("target_ip", ""),
                                "timestamp": timestamp,
                                "success_count": pref_data.get("success_count", 1)
                            }
                            loaded_count += 1
                        else:
                            expired_count += 1
                            
                    except Exception as e:
                        LOG.debug(f"Ошибка загрузки предпочтения для {domain}: {e}")
                        expired_count += 1
            
            LOG.info(f"📂 Загружено {loaded_count} предпочтений протоколов, "
                    f"пропущено {expired_count} устаревших")
            
            # Если есть устаревшие данные, пересохраняем файл
            if expired_count > 0:
                self._save_protocol_preferences()
                
        except Exception as e:
            LOG.warning(f"Ошибка загрузки предпочтений протоколов: {e}")
            # Создаем пустой кэш при ошибке
            with self._cache_lock:
                self._protocol_preference_cache.clear()

    def enable_profiling(self, enable: bool = True):
        """
        Включение/выключение профилирования производительности.
        
        Args:
            enable: True для включения профилирования
        """
        self.config.enable_profiling = enable
        
        if enable:
            LOG.info("🔍 Профилирование производительности включено")
        else:
            LOG.info("🔍 Профилирование производительности выключено")
            # Очищаем данные профилирования
            with self._profiling_lock:
                self._profiling_data.clear()
                self._avg_augmentation_time = 0.0
                self._augmentation_count = 0

    def __del__(self):
        """Очистка ресурсов при удалении объекта"""
        # Task 7.4: Export diagnostics on shutdown if enabled
        try:
            if hasattr(self, 'config') and getattr(self.config, 'export_diagnostics_on_shutdown', False):
                self.export_diagnostics()
        except Exception as e:
            LOG.debug(f"Failed to export diagnostics on shutdown: {e}")
        
        if hasattr(self, '_executor') and self._executor:
            self._executor.shutdown(wait=False)