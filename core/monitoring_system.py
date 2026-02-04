"""
Monitoring System for DPI Bypass.

This module provides a comprehensive monitoring system for tracking site accessibility,
automatic recovery, and integration with bypass strategies.

Architecture:
    - MonitoringSystem: Main facade orchestrating all monitoring operations
    - Delegates to specialized modules in core.monitoring:
        - health_checker: Site connectivity checks
        - auto_recovery: Automatic recovery on failures
        - site_manager: Site lifecycle management
        - strategy_helpers: Strategy generation and validation
        - reporters: Status and metrics reporting
        - effectiveness: Rule effectiveness analysis
        - config_helpers: Configuration I/O

Key Features:
    - Asynchronous health checking with configurable intervals
    - Automatic recovery with adaptive strategy selection
    - Integration with modern bypass components (AttackRegistry, StrategyPoolManager)
    - Closed-loop metrics collection and reporting
    - Rule effectiveness analysis and visualization

Usage:
    >>> from core.monitoring_system import MonitoringSystem, MonitoringConfig
    >>> config = MonitoringConfig(check_interval_seconds=30)
    >>> monitor = MonitoringSystem(config)
    >>> monitor.add_site("example.com", 443)
    >>> await monitor.start()
    >>> report = monitor.get_status_report()
    >>> await monitor.stop()
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# Import models first to avoid circular dependencies
from core.monitoring.models import ConnectionHealth, MonitoringConfig

# Task 8.2: Import closed-loop metrics
try:
    from core.metrics.closed_loop_metrics import (
        get_closed_loop_metrics_collector,
        ClosedLoopMetricsCollector,
    )

    CLOSED_LOOP_METRICS_AVAILABLE = True
except ImportError:
    CLOSED_LOOP_METRICS_AVAILABLE = False
    get_closed_loop_metrics_collector = None
    ClosedLoopMetricsCollector = None

# Task 8.3: Import effectiveness reporter
try:
    from core.metrics.effectiveness_reporter import (
        get_effectiveness_reporter,
        EffectivenessReporter,
    )

    EFFECTIVENESS_REPORTER_AVAILABLE = True
except ImportError:
    EFFECTIVENESS_REPORTER_AVAILABLE = False
    get_effectiveness_reporter = None
    EffectivenessReporter = None
try:
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.strategies.pool_management import (
        StrategyPoolManager,
        BypassStrategy,
    )
    from core.bypass.validation.reliability_validator import ReliabilityValidator

    MODERN_BYPASS_MONITORING_AVAILABLE = True
except ImportError:
    MODERN_BYPASS_MONITORING_AVAILABLE = False

# Import monitoring components
# Import monitoring components
from core.monitoring.health_checker import HealthChecker
from core.monitoring.auto_recovery import AutoRecoverySystem
from core.monitoring.site_manager import SiteManager
from core.monitoring.strategy_helpers import (
    generate_registry_recovery_strategies,
    validate_recovery_strategies,
)
from core.monitoring.reporters import (
    generate_status_report,
    generate_health_summary,
)
from core.monitoring.effectiveness import (
    generate_rule_effectiveness_report,
    get_rule_effectiveness_summary,
)
from core.monitoring.config_helpers import (
    load_monitoring_config as _load_config,
    save_monitoring_config as _save_config,
)


class MonitoringSystem:
    """Основная система мониторинга."""

    def __init__(
        self,
        config: MonitoringConfig,
        learning_cache=None,
        enable_modern_bypass: bool = True,
    ):
        self.config = config
        self.learning_cache = learning_cache
        self.logger = logging.getLogger(__name__)

        # Initialize core components
        self._init_core_components()

        # Initialize modern bypass if enabled
        self.modern_bypass_enabled = enable_modern_bypass and MODERN_BYPASS_MONITORING_AVAILABLE
        if self.modern_bypass_enabled:
            self._init_modern_bypass()
        else:
            self._set_modern_bypass_disabled()

        # Initialize monitoring stats
        self._init_monitoring_stats()

        # Initialize metrics integration
        self._init_metrics_integration()

        # Initialize effectiveness reporter
        self._init_effectiveness_reporter()

        # Configure logging
        logging.basicConfig(level=getattr(logging, config.log_level))

    def _init_core_components(self):
        """Initialize core monitoring components."""
        self.health_checker = HealthChecker(timeout=5.0)
        self.auto_recovery = AutoRecoverySystem(self.learning_cache)
        self.site_manager = SiteManager(logger=self.logger)
        self.monitored_sites = self.site_manager.monitored_sites  # Backward compatibility
        self.is_running = False
        self.monitoring_task: Optional[asyncio.Task] = None
        # Semaphore for limiting concurrent checks
        self._check_semaphore: Optional[asyncio.Semaphore] = None

    def _init_modern_bypass(self):
        """Initialize modern bypass monitoring components."""
        try:
            self.attack_registry = AttackRegistry()
            self.pool_manager = StrategyPoolManager()
            self.reliability_validator = ReliabilityValidator()
            self.logger.info("Modern FORCED OVERRIDE bypass monitoring components initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize modern bypass monitoring: {e}")
            self.modern_bypass_enabled = False
            self._set_modern_bypass_disabled()

    def _set_modern_bypass_disabled(self):
        """Set modern bypass components to None when disabled."""
        self.attack_registry = None
        self.pool_manager = None
        self.reliability_validator = None

    def _init_monitoring_stats(self):
        """Initialize monitoring statistics."""
        self.monitoring_stats = {
            "total_checks": 0,
            "successful_recoveries": 0,
            "failed_recoveries": 0,
            "pool_strategy_uses": 0,
            "registry_strategy_uses": 0,
            "reliability_validations": 0,
        }

    def _init_metrics_integration(self):
        """Initialize closed-loop metrics integration (Task 8.2)."""
        self.closed_loop_metrics_collector = None
        if CLOSED_LOOP_METRICS_AVAILABLE and get_closed_loop_metrics_collector:
            try:
                self.closed_loop_metrics_collector = get_closed_loop_metrics_collector()
                self.logger.info("✅ Closed-loop metrics integration initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize closed-loop metrics: {e}")
                self.closed_loop_metrics_collector = None
        else:
            self.logger.warning("⚠️ Closed-loop metrics not available")

    def _init_effectiveness_reporter(self):
        """Initialize effectiveness reporter (Task 8.3)."""
        self.effectiveness_reporter = None
        if EFFECTIVENESS_REPORTER_AVAILABLE and get_effectiveness_reporter:
            try:
                self.effectiveness_reporter = get_effectiveness_reporter()
                self.logger.info("✅ Effectiveness reporter initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize effectiveness reporter: {e}")
                self.effectiveness_reporter = None
        else:
            self.logger.warning("⚠️ Effectiveness reporter not available")

    def add_site(self, domain: str, port: int = 443, current_strategy: Optional[str] = None):
        """Добавляет сайт для мониторинга."""
        return self.site_manager.add_site(domain, port, current_strategy)

    def remove_site(self, domain: str, port: int = 443):
        """Удаляет сайт из мониторинга."""
        return self.site_manager.remove_site(domain, port)

    async def check_site_health(self, site_key: str) -> ConnectionHealth:
        """Проверяет здоровье одного сайта."""
        return await self.site_manager.check_site_health(site_key, self.health_checker)

    async def monitoring_loop(self):
        """Основной цикл мониторинга."""
        self.logger.info("🚀 Starting monitoring system")

        # Initialize semaphore for concurrent checks
        self._check_semaphore = asyncio.Semaphore(self.config.max_concurrent_checks)

        async with self.health_checker:
            while self.is_running:
                try:
                    await self._check_all_sites()
                    await asyncio.sleep(self.config.check_interval_seconds)
                except asyncio.CancelledError:
                    # Don't swallow cancellation - re-raise to allow clean shutdown
                    self.logger.info("Monitoring loop cancelled")
                    raise
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    await asyncio.sleep(5)

    async def _check_all_sites(self):
        """Проверяет все отслеживаемые сайты с ограничением параллелизма."""

        async def limited_check(site_key: str):
            """Check site with semaphore limit."""
            async with self._check_semaphore:
                try:
                    health = await self.check_site_health(site_key)
                    await self._process_health_check_result(health)
                    return health
                except Exception as e:
                    self.logger.error(f"Error checking {site_key}: {e}")
                    return None

        # Create tasks for all sites
        tasks = [
            asyncio.create_task(limited_check(site_key))
            for site_key in list(self.monitored_sites.keys())
        ]

        # Wait for all checks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _process_health_check_result(self, health: ConnectionHealth):
        """Обрабатывает результат проверки здоровья сайта."""
        # Increment total checks counter
        self.monitoring_stats["total_checks"] += 1

        status = "✅" if health.is_accessible else "❌"
        self.logger.debug(f"{status} {health.domain} - {health.response_time_ms:.1f}ms")

        # Trigger recovery if needed
        if (
            not health.is_accessible
            and health.consecutive_failures >= self.config.failure_threshold
            and self.config.enable_auto_recovery
        ):
            await self._trigger_recovery(health)

    async def _trigger_recovery(self, health: ConnectionHealth):
        """Запускает процесс восстановления."""
        # Collect strategies from various sources
        available_strategies = []
        available_strategies.extend(self._collect_pool_strategies(health))
        available_strategies.extend(self._collect_registry_strategies(health, available_strategies))
        available_strategies.extend(
            self._collect_cache_or_default_strategies(health, available_strategies)
        )

        # Validate strategies if validator available
        available_strategies = await self._validate_strategies_if_enabled(
            health, available_strategies
        )

        # Attempt recovery
        success = await self.auto_recovery.attempt_recovery(health, available_strategies)

        # Handle recovery result
        await self._handle_recovery_result(health, success)

    def _collect_pool_strategies(self, health: ConnectionHealth) -> List[str]:
        """Collect strategies from pool manager."""
        strategies = []
        if self.modern_bypass_enabled and self.pool_manager:
            pool_strategy = self.pool_manager.get_strategy_for_domain(health.domain, health.port)
            if pool_strategy:
                strategies.append(pool_strategy.to_zapret_format())
                self.monitoring_stats["pool_strategy_uses"] += 1
                self.logger.info(f"Using pool strategy for {health.domain}")
        return strategies

    def _collect_registry_strategies(
        self, health: ConnectionHealth, current_strategies: List[str]
    ) -> List[str]:
        """Collect strategies from attack registry."""
        strategies = []
        if self.modern_bypass_enabled and self.attack_registry and (len(current_strategies) < 3):
            registry_attacks = self.attack_registry.list_attacks(enabled_only=True)
            if registry_attacks:
                registry_strategies = generate_registry_recovery_strategies(
                    self.attack_registry, registry_attacks
                )
                strategies.extend(registry_strategies)
                self.monitoring_stats["registry_strategy_uses"] += 1
                self.logger.info(f"Using {len(registry_strategies)} registry-based strategies")
        return strategies

    def _collect_cache_or_default_strategies(
        self, health: ConnectionHealth, current_strategies: List[str]
    ) -> List[str]:
        """Collect strategies from learning cache or use defaults."""
        strategies = []
        if len(current_strategies) < 3:
            if self.config.enable_adaptive_strategies and self.learning_cache:
                domain_recs = self.learning_cache.get_domain_recommendations(health.domain, 5)
                cache_strategies = [f"--dpi-desync={rec[0]}" for rec in domain_recs if rec[1] > 0.3]
                strategies.extend(cache_strategies)
            else:
                default_strategies = [
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
                    "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
                ]
                strategies.extend(default_strategies)
        return strategies

    async def _validate_strategies_if_enabled(
        self, health: ConnectionHealth, strategies: List[str]
    ) -> List[str]:
        """Validate strategies using reliability validator if enabled."""
        if self.modern_bypass_enabled and self.reliability_validator and strategies:
            validated_strategies = await validate_recovery_strategies(
                self.reliability_validator, health, strategies
            )
            if validated_strategies:
                self.monitoring_stats["reliability_validations"] += 1
                return validated_strategies
        return strategies

    async def _handle_recovery_result(self, health: ConnectionHealth, success: bool):
        """Handle the result of recovery attempt."""
        if success:
            self.monitoring_stats["successful_recoveries"] += 1
            self.logger.info(f"🎉 Successfully recovered {health.domain}")
            if self.modern_bypass_enabled and self.pool_manager and health.current_strategy:
                await self._update_pool_after_recovery(health)
        else:
            self.monitoring_stats["failed_recoveries"] += 1
            self.logger.warning(f"⚠️ Failed to recover {health.domain}")

    async def _update_pool_after_recovery(self, health: ConnectionHealth):
        """Update pool manager after successful recovery."""
        if not self.pool_manager or not health.current_strategy:
            return
        try:
            recovery_strategy = BypassStrategy(
                id=f"recovery_{health.domain}_{health.port}",
                name=f"Successful recovery strategy for {health.domain}",
                attacks=["tcp_fragmentation"],
                parameters={},
                success_rate=1.0,
                last_tested=datetime.now(),
            )
            existing_strategy = self.pool_manager.get_strategy_for_domain(
                health.domain, health.port
            )
            if not existing_strategy:
                pool = self.pool_manager.create_pool(
                    f"Recovery pool for {health.domain}",
                    recovery_strategy,
                    "Auto-created after successful recovery",
                )
                self.pool_manager.add_domain_to_pool(pool.id, health.domain)
                self.logger.info(f"Created new pool for recovered domain {health.domain}")
        except Exception as e:
            self.logger.error(f"Failed to update pool after recovery: {e}")

    async def start(self):
        """Запускает систему мониторинга."""
        if self.is_running:
            return
        self.is_running = True
        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
        self.logger.info("📊 Monitoring system started")

    async def stop(self):
        """Останавливает систему мониторинга."""
        if not self.is_running:
            return
        self.is_running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        self.logger.info("🛑 Monitoring system stopped")

    def get_status_report(self) -> dict:
        """Возвращает отчет о состоянии всех сайтов."""
        return generate_status_report(
            monitored_sites=self.monitored_sites,
            monitoring_stats=self.monitoring_stats,
            modern_bypass_enabled=self.modern_bypass_enabled,
            attack_registry=self.attack_registry,
            pool_manager=self.pool_manager,
            closed_loop_metrics_collector=self.closed_loop_metrics_collector,
            effectiveness_reporter=self.effectiveness_reporter,
        )

    def get_health_summary(self) -> str:
        """Возвращает краткое резюме состояния."""
        return generate_health_summary(self.monitored_sites)

    def get_closed_loop_metrics(self) -> Dict[str, Any]:
        """
        Task 8.2: Получение метрик замкнутого цикла обучения через MonitoringSystem.

        Экспортирует метрики через существующий MonitoringSystem с тегами
        для группировки (pattern_id, root_cause).

        Returns:
            Словарь с метриками замкнутого цикла или пустой словарь если недоступно
        """
        if not self.closed_loop_metrics_collector:
            return {}

        try:
            # Получаем базовые метрики
            metrics = self.closed_loop_metrics_collector.get_metrics_dict()

            # Добавляем теги для группировки
            tagged_metrics = {
                "closed_loop.iterations_count": {
                    "value": metrics.get("iterations_count", 0),
                    "tags": {"metric_type": "counter", "component": "closed_loop_learning"},
                },
                "closed_loop.intents_generated_total": {
                    "value": metrics.get("intents_generated_total", 0),
                    "tags": {"metric_type": "counter", "component": "intent_generation"},
                },
                "closed_loop.strategies_generated_per_iteration": {
                    "value": metrics.get("strategies_generated_per_iteration", 0.0),
                    "tags": {"metric_type": "gauge", "component": "strategy_generation"},
                },
                "closed_loop.pattern_matches_total": {
                    "value": metrics.get("pattern_matches_total", 0),
                    "tags": {"metric_type": "counter", "component": "pattern_matching"},
                },
                "closed_loop.knowledge_base_rules_count": {
                    "value": metrics.get("knowledge_base_rules_count", 0),
                    "tags": {"metric_type": "gauge", "component": "knowledge_base"},
                },
            }

            # Добавляем success_rate_by_pattern с тегами pattern_id
            success_rates = metrics.get("success_rate_by_pattern", {})
            for pattern_id, success_rate in success_rates.items():
                # Извлекаем root_cause из pattern_id если возможно
                root_cause = "unknown"
                if "_" in pattern_id:
                    parts = pattern_id.split("_")
                    if len(parts) > 1:
                        root_cause = "_".join(parts[1:])  # Убираем "pattern_" префикс

                tagged_metrics[f"closed_loop.success_rate_by_pattern.{pattern_id}"] = {
                    "value": success_rate,
                    "tags": {
                        "metric_type": "gauge",
                        "component": "pattern_effectiveness",
                        "pattern_id": pattern_id,
                        "root_cause": root_cause,
                    },
                }

            return tagged_metrics

        except Exception as e:
            self.logger.error(f"Failed to get closed-loop metrics: {e}")
            return {"error": str(e)}

    def export_closed_loop_metrics(
        self, file_path: str = "metrics/monitoring_closed_loop_metrics.json"
    ) -> bool:
        """
        Task 8.2: Экспорт метрик замкнутого цикла в JSON формате.

        Args:
            file_path: Путь к файлу для экспорта

        Returns:
            True если экспорт успешен
        """
        if not self.closed_loop_metrics_collector:
            self.logger.warning("Closed-loop metrics collector not available")
            return False

        try:
            # Экспортируем через коллектор метрик
            success = self.closed_loop_metrics_collector.export_metrics(file_path)

            if success:
                self.logger.info(f"📊 Closed-loop metrics exported to {file_path}")
            else:
                self.logger.error(f"Failed to export closed-loop metrics to {file_path}")

            return success

        except Exception as e:
            self.logger.error(f"Error exporting closed-loop metrics: {e}")
            return False

    def generate_rule_effectiveness_report(
        self, knowledge_accumulator, export_json: bool = True, export_visualization: bool = True
    ) -> Dict[str, Any]:
        """Task 8.3: Генерация отчетов об эффективности правил."""
        return generate_rule_effectiveness_report(
            self.effectiveness_reporter,
            knowledge_accumulator,
            export_json,
            export_visualization,
        )

    def get_rule_effectiveness_summary(self, knowledge_accumulator) -> Dict[str, Any]:
        """Task 8.3: Получение краткой сводки об эффективности правил."""
        return get_rule_effectiveness_summary(
            self.effectiveness_reporter,
            knowledge_accumulator,
        )


# Module-level configuration functions (re-exported for backward compatibility)
def load_monitoring_config(
    config_file: str = "monitoring_config.json",
) -> MonitoringConfig:
    """Загружает конфигурацию мониторинга из файла."""
    return _load_config(MonitoringConfig, config_file)


def save_monitoring_config(config: MonitoringConfig, config_file: str = "monitoring_config.json"):
    """Сохраняет конфигурацию мониторинга в файл."""
    return _save_config(config, config_file)


# Re-export models for backward compatibility
__all__ = [
    "MonitoringSystem",
    "MonitoringConfig",
    "ConnectionHealth",
    "load_monitoring_config",
    "save_monitoring_config",
]
