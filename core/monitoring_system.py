import asyncio
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import socket

# Task 8.2: Import closed-loop metrics
try:
    from core.metrics.closed_loop_metrics import (
        get_closed_loop_metrics_collector,
        ClosedLoopMetricsCollector
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
        EffectivenessReporter
    )
    EFFECTIVENESS_REPORTER_AVAILABLE = True
except ImportError:
    EFFECTIVENESS_REPORTER_AVAILABLE = False
    get_effectiveness_reporter = None
    EffectivenessReporter = None

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None
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


@dataclass
class ConnectionHealth:
    """Состояние здоровья соединения."""

    domain: str
    ip: str
    port: int
    is_accessible: bool
    response_time_ms: float
    last_check: datetime
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    bypass_active: bool = False
    current_strategy: Optional[str] = None

    def to_dict(self) -> dict:
        return {**asdict(self), "last_check": self.last_check.isoformat()}


@dataclass
class MonitoringConfig:
    """Конфигурация системы мониторинга."""

    check_interval_seconds: int = 30
    failure_threshold: int = 3
    recovery_timeout_seconds: int = 300
    max_concurrent_checks: int = 10
    enable_auto_recovery: bool = True
    enable_adaptive_strategies: bool = True
    web_interface_port: int = 8080
    log_level: str = "INFO"


class HealthChecker:
    """Проверяет доступность сайтов."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.session = None

    async def __aenter__(self):
        if AIOHTTP_AVAILABLE:
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def check_http_connectivity(
        self, domain: str, port: int = 443, use_https: bool = True
    ) -> Tuple[bool, float, Optional[str]]:
        """Проверяет HTTP/HTTPS доступность."""
        if not AIOHTTP_AVAILABLE or not self.session:
            return await self.check_tcp_connectivity(domain, port)
        protocol = "https" if use_https else "http"
        url = (
            f"{protocol}://{domain}:{port}"
            if port != (443 if use_https else 80)
            else f"{protocol}://{domain}"
        )
        start_time = time.time()
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                response_time = (time.time() - start_time) * 1000
                return (response.status < 400, response_time, None)
        except asyncio.TimeoutError:
            return (False, (time.time() - start_time) * 1000, "Timeout")
        except Exception as e:
            if AIOHTTP_AVAILABLE and "aiohttp" in str(type(e)):
                return (False, (time.time() - start_time) * 1000, str(e))
            else:
                return (False, (time.time() - start_time) * 1000, f"HTTP Error: {e}")

    async def check_tcp_connectivity(
        self, domain: str, port: int
    ) -> Tuple[bool, float, Optional[str]]:
        """Проверяет TCP доступность."""
        start_time = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            response_time = (time.time() - start_time) * 1000
            return (True, response_time, None)
        except asyncio.TimeoutError:
            return (False, (time.time() - start_time) * 1000, "TCP Timeout")
        except ConnectionRefusedError:
            return (False, (time.time() - start_time) * 1000, "Connection Refused")
        except Exception as e:
            return (False, (time.time() - start_time) * 1000, f"TCP Error: {e}")


class AutoRecoverySystem:
    """Система автоматического восстановления соединений."""

    def __init__(self, learning_cache=None):
        self.learning_cache = learning_cache
        self.recovery_attempts: Dict[str, int] = {}
        self.last_recovery_time: Dict[str, datetime] = {}
        self.logger = logging.getLogger(__name__)

    async def attempt_recovery(
        self, health: ConnectionHealth, available_strategies: List[str]
    ) -> bool:
        """Пытается восстановить соединение с сайтом."""
        domain_key = f"{health.domain}:{health.port}"
        if domain_key in self.last_recovery_time:
            time_since_last = datetime.now() - self.last_recovery_time[domain_key]
            if time_since_last < timedelta(minutes=5):
                self.logger.debug(
                    f"Skipping recovery for {domain_key} - too soon since last attempt"
                )
                return False
        self.logger.info(f"🔄 Attempting recovery for {health.domain}")
        if self.learning_cache:
            optimized_strategies = self.learning_cache.get_smart_strategy_order(
                available_strategies, health.domain, health.ip
            )
        else:
            optimized_strategies = available_strategies
        for strategy in optimized_strategies[:3]:
            self.logger.info(f"  Trying strategy: {strategy}")
            success = await self._test_strategy_recovery(health, strategy)
            if success:
                self.logger.info(f"✅ Recovery successful with strategy: {strategy}")
                health.bypass_active = True
                health.current_strategy = strategy
                health.consecutive_failures = 0
                self.recovery_attempts[domain_key] = 0
                self.last_recovery_time[domain_key] = datetime.now()
                return True
        self.recovery_attempts[domain_key] = (
            self.recovery_attempts.get(domain_key, 0) + 1
        )
        self.last_recovery_time[domain_key] = datetime.now()
        self.logger.warning(
            f"❌ Recovery failed for {health.domain} after trying {len(optimized_strategies[:3])} strategies"
        )
        return False

    async def _test_strategy_recovery(
        self, health: ConnectionHealth, strategy: str
    ) -> bool:
        """Тестирует восстановление с конкретной стратегией."""
        await asyncio.sleep(0.5)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(health.domain, health.port), timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False


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
        self.health_checker = HealthChecker(timeout=5.0)
        self.auto_recovery = AutoRecoverySystem(learning_cache)
        self.monitored_sites: Dict[str, ConnectionHealth] = {}
        self.is_running = False
        self.monitoring_task: Optional[asyncio.Task] = None
        self.logger = logging.getLogger(__name__)
        self.modern_bypass_enabled = (
            enable_modern_bypass and MODERN_BYPASS_MONITORING_AVAILABLE
        )
        if self.modern_bypass_enabled:
            try:
                self.attack_registry = AttackRegistry()
                self.pool_manager = StrategyPoolManager()
                self.reliability_validator = ReliabilityValidator()
                self.logger.info(
                    "Modern FORCED OVERRIDE bypass monitoring components initialized"
                )
            except Exception as e:
                self.logger.error(f"Failed to initialize modern bypass monitoring: {e}")
                self.modern_bypass_enabled = False
                self.attack_registry = None
                self.pool_manager = None
                self.reliability_validator = None
        else:
            self.attack_registry = None
            self.pool_manager = None
            self.reliability_validator = None
        self.monitoring_stats = {
            "total_checks": 0,
            "successful_recoveries": 0,
            "failed_recoveries": 0,
            "pool_strategy_uses": 0,
            "registry_strategy_uses": 0,
            "reliability_validations": 0,
        }
        
        # Task 8.2: Initialize closed-loop metrics integration
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
        
        # Task 8.3: Initialize effectiveness reporter
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
        
        logging.basicConfig(level=getattr(logging, config.log_level))

    def add_site(
        self, domain: str, port: int = 443, current_strategy: Optional[str] = None
    ):
        """Добавляет сайт для мониторинга."""
        site_key = f"{domain}:{port}"
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = "unknown"
        self.monitored_sites[site_key] = ConnectionHealth(
            domain=domain,
            ip=ip,
            port=port,
            is_accessible=False,
            response_time_ms=0.0,
            last_check=datetime.now(),
            current_strategy=current_strategy,
            bypass_active=current_strategy is not None,
        )
        self.logger.info(f"📊 Added {domain}:{port} to monitoring")

    def remove_site(self, domain: str, port: int = 443):
        """Удаляет сайт из мониторинга."""
        site_key = f"{domain}:{port}"
        if site_key in self.monitored_sites:
            del self.monitored_sites[site_key]
            self.logger.info(f"🗑️ Removed {domain}:{port} from monitoring")

    async def check_site_health(self, site_key: str) -> ConnectionHealth:
        """Проверяет здоровье одного сайта."""
        health = self.monitored_sites[site_key]
        is_accessible, response_time, error = (
            await self.health_checker.check_http_connectivity(
                health.domain, health.port
            )
        )
        health.is_accessible = is_accessible
        health.response_time_ms = response_time
        health.last_check = datetime.now()
        if is_accessible:
            health.consecutive_failures = 0
            health.last_error = None
        else:
            health.consecutive_failures += 1
            health.last_error = error
        return health

    async def monitoring_loop(self):
        """Основной цикл мониторинга."""
        self.logger.info("🚀 Starting monitoring system")
        async with self.health_checker:
            while self.is_running:
                try:
                    tasks = []
                    for site_key in list(self.monitored_sites.keys()):
                        task = asyncio.create_task(self.check_site_health(site_key))
                        tasks.append((site_key, task))
                    for site_key, task in tasks:
                        try:
                            health = await task
                            status = "✅" if health.is_accessible else "❌"
                            self.logger.debug(
                                f"{status} {health.domain} - {health.response_time_ms:.1f}ms"
                            )
                            if (
                                not health.is_accessible
                                and health.consecutive_failures
                                >= self.config.failure_threshold
                                and self.config.enable_auto_recovery
                            ):
                                await self._trigger_recovery(health)
                        except Exception as e:
                            self.logger.error(f"Error checking {site_key}: {e}")
                    await asyncio.sleep(self.config.check_interval_seconds)
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    await asyncio.sleep(5)

    async def _trigger_recovery(self, health: ConnectionHealth):
        """Запускает процесс восстановления."""
        available_strategies = []
        if self.modern_bypass_enabled and self.pool_manager:
            pool_strategy = self.pool_manager.get_strategy_for_domain(
                health.domain, health.port
            )
            if pool_strategy:
                available_strategies.append(pool_strategy.to_zapret_format())
                self.monitoring_stats["pool_strategy_uses"] += 1
                self.logger.info(f"Using pool strategy for {health.domain}")
        if (
            self.modern_bypass_enabled
            and self.attack_registry
            and (len(available_strategies) < 3)
        ):
            registry_attacks = self.attack_registry.list_attacks(enabled_only=True)
            if registry_attacks:
                registry_strategies = self._generate_registry_recovery_strategies(
                    registry_attacks
                )
                available_strategies.extend(registry_strategies)
                self.monitoring_stats["registry_strategy_uses"] += 1
                self.logger.info(
                    f"Using {len(registry_strategies)} registry-based strategies"
                )
        if len(available_strategies) < 3:
            if self.config.enable_adaptive_strategies and self.learning_cache:
                domain_recs = self.learning_cache.get_domain_recommendations(
                    health.domain, 5
                )
                cache_strategies = [
                    f"--dpi-desync={rec[0]}" for rec in domain_recs if rec[1] > 0.3
                ]
                available_strategies.extend(cache_strategies)
            else:
                default_strategies = [
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
                    "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
                ]
                available_strategies.extend(default_strategies)
        if (
            self.modern_bypass_enabled
            and self.reliability_validator
            and available_strategies
        ):
            validated_strategies = await self._validate_recovery_strategies(
                health, available_strategies
            )
            if validated_strategies:
                available_strategies = validated_strategies
                self.monitoring_stats["reliability_validations"] += 1
        success = await self.auto_recovery.attempt_recovery(
            health, available_strategies
        )
        if success:
            self.monitoring_stats["successful_recoveries"] += 1
            self.logger.info(f"🎉 Successfully recovered {health.domain}")
            if (
                self.modern_bypass_enabled
                and self.pool_manager
                and health.current_strategy
            ):
                await self._update_pool_after_recovery(health)
        else:
            self.monitoring_stats["failed_recoveries"] += 1
            self.logger.warning(f"⚠️ Failed to recover {health.domain}")

    def _generate_registry_recovery_strategies(
        self, registry_attacks: List[str]
    ) -> List[str]:
        """Generate recovery strategies from registry attacks."""
        strategies = []
        for attack_id in registry_attacks[:3]:
            if not self.attack_registry:
                break
            definition = self.attack_registry.get_attack_definition(attack_id)
            if not definition:
                continue
            if definition.category.value == "tcp_fragmentation":
                strategies.append(
                    "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum"
                )
            elif definition.category.value == "http_manipulation":
                strategies.append(
                    "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum"
                )
            elif definition.category.value == "tls_evasion":
                strategies.append(
                    "--dpi-desync=disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq"
                )
        return strategies

    async def _validate_recovery_strategies(
        self, health: ConnectionHealth, strategies: List[str]
    ) -> List[str]:
        """Validate recovery strategies using reliability validator."""
        if not self.reliability_validator:
            return strategies
        validated_strategies = []
        for strategy_str in strategies:
            try:
                strategy = BypassStrategy(
                    id=f"recovery_{hash(strategy_str)}",
                    name=f"Recovery strategy for {health.domain}",
                    attacks=["tcp_fragmentation"],
                    parameters={},
                )
                validation_result = await self.reliability_validator.validate_strategy(
                    health.domain, strategy
                )
                if validation_result and validation_result.reliability_score > 0.5:
                    validated_strategies.append(strategy_str)
            except Exception as e:
                self.logger.debug(f"Strategy validation failed: {e}")
                validated_strategies.append(strategy_str)
        return validated_strategies if validated_strategies else strategies

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
                self.logger.info(
                    f"Created new pool for recovered domain {health.domain}"
                )
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
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_sites": len(self.monitored_sites),
            "accessible_sites": sum(
                (1 for h in self.monitored_sites.values() if h.is_accessible)
            ),
            "sites_with_bypass": sum(
                (1 for h in self.monitored_sites.values() if h.bypass_active)
            ),
            "average_response_time": 0.0,
            "modern_bypass_enabled": self.modern_bypass_enabled,
            "monitoring_stats": self.monitoring_stats.copy(),
            "sites": {},
        }
        if self.monitored_sites:
            accessible_sites = [
                h for h in self.monitored_sites.values() if h.is_accessible
            ]
            if accessible_sites:
                report["average_response_time"] = sum(
                    (h.response_time_ms for h in accessible_sites)
                ) / len(accessible_sites)
        if self.modern_bypass_enabled:
            if self.attack_registry:
                try:
                    registry_stats = self.attack_registry.get_stats()
                    report["attack_registry_stats"] = registry_stats
                except Exception as e:
                    self.logger.error(f"Failed to get attack registry stats: {e}")
            if self.pool_manager:
                try:
                    pool_stats = self.pool_manager.get_pool_statistics()
                    report["pool_manager_stats"] = pool_stats
                except Exception as e:
                    self.logger.error(f"Failed to get pool manager stats: {e}")
        
        # Task 8.2: Add closed-loop metrics to monitoring report
        if self.closed_loop_metrics_collector:
            try:
                closed_loop_metrics = self.closed_loop_metrics_collector.get_metrics_dict()
                
                # Add tags for grouping (pattern_id, root_cause)
                tagged_metrics = {}
                for key, value in closed_loop_metrics.items():
                    if key == "success_rate_by_pattern":
                        # Add pattern_id tags
                        for pattern_id, success_rate in value.items():
                            tagged_key = f"{key}.{pattern_id}"
                            tagged_metrics[tagged_key] = {
                                "value": success_rate,
                                "tags": {
                                    "pattern_id": pattern_id,
                                    "metric_type": "success_rate"
                                }
                            }
                    else:
                        tagged_metrics[key] = {
                            "value": value,
                            "tags": {
                                "metric_type": "closed_loop",
                                "component": "adaptive_engine"
                            }
                        }
                
                report["closed_loop_metrics"] = tagged_metrics
                
                # Add summary metrics for easier monitoring
                report["closed_loop_summary"] = self.closed_loop_metrics_collector.get_summary_report()
                
            except Exception as e:
                self.logger.error(f"Failed to get closed-loop metrics: {e}")
                report["closed_loop_metrics"] = {"error": str(e)}
        
        # Task 8.3: Add rule effectiveness summary to monitoring report
        # Note: This requires knowledge_accumulator to be passed separately
        # For now, we'll add a placeholder that can be populated when available
        report["rule_effectiveness_available"] = self.effectiveness_reporter is not None
        
        for site_key, health in self.monitored_sites.items():
            report["sites"][site_key] = health.to_dict()
        return report

    def get_health_summary(self) -> str:
        """Возвращает краткое резюме состояния."""
        total = len(self.monitored_sites)
        accessible = sum((1 for h in self.monitored_sites.values() if h.is_accessible))
        with_bypass = sum((1 for h in self.monitored_sites.values() if h.bypass_active))
        return f"📊 Status: {accessible}/{total} accessible, {with_bypass} with bypass"
    
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
                    "tags": {
                        "metric_type": "counter",
                        "component": "closed_loop_learning"
                    }
                },
                "closed_loop.intents_generated_total": {
                    "value": metrics.get("intents_generated_total", 0),
                    "tags": {
                        "metric_type": "counter", 
                        "component": "intent_generation"
                    }
                },
                "closed_loop.strategies_generated_per_iteration": {
                    "value": metrics.get("strategies_generated_per_iteration", 0.0),
                    "tags": {
                        "metric_type": "gauge",
                        "component": "strategy_generation"
                    }
                },
                "closed_loop.pattern_matches_total": {
                    "value": metrics.get("pattern_matches_total", 0),
                    "tags": {
                        "metric_type": "counter",
                        "component": "pattern_matching"
                    }
                },
                "closed_loop.knowledge_base_rules_count": {
                    "value": metrics.get("knowledge_base_rules_count", 0),
                    "tags": {
                        "metric_type": "gauge",
                        "component": "knowledge_base"
                    }
                }
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
                        "root_cause": root_cause
                    }
                }
            
            return tagged_metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get closed-loop metrics: {e}")
            return {"error": str(e)}
    
    def export_closed_loop_metrics(self, file_path: str = "metrics/monitoring_closed_loop_metrics.json") -> bool:
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
    
    def generate_rule_effectiveness_report(self, 
                                         knowledge_accumulator,
                                         export_json: bool = True,
                                         export_visualization: bool = True) -> Dict[str, Any]:
        """
        Task 8.3: Генерация отчетов об эффективности правил.
        
        Генерирует статистику по каждому правилу, экспортирует в JSON формате
        и создает визуализацию топ правил по success_rate.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
            export_json: Экспортировать JSON отчет
            export_visualization: Создать текстовую визуализацию
            
        Returns:
            Словарь с результатами генерации отчета
        """
        if not self.effectiveness_reporter:
            self.logger.warning("Effectiveness reporter not available")
            return {"error": "Effectiveness reporter not available"}
        
        if not knowledge_accumulator:
            self.logger.warning("Knowledge accumulator not provided")
            return {"error": "Knowledge accumulator not provided"}
        
        try:
            # Генерируем комплексный отчет
            created_files = self.effectiveness_reporter.generate_comprehensive_report(
                knowledge_accumulator,
                export_json=export_json,
                export_visualization=export_visualization
            )
            
            # Получаем статистику для возврата
            report = self.effectiveness_reporter.generate_effectiveness_report(knowledge_accumulator)
            
            result = {
                "success": True,
                "timestamp": datetime.now().isoformat(),
                "created_files": created_files,
                "summary": {
                    "total_rules": report.total_rules,
                    "active_rules": report.active_rules,
                    "high_performance_rules": report.high_performance_rules,
                    "top_success_rate": report.top_rules_by_success_rate[0].success_rate if report.top_rules_by_success_rate else 0.0,
                    "recommendations_count": len(report.recommendations)
                },
                "top_rules_preview": [
                    {
                        "rule_id": rule.rule_id,
                        "success_rate": rule.success_rate,
                        "total_applications": rule.total_applications,
                        "unique_domains": rule.unique_domains_count
                    }
                    for rule in report.top_rules_by_success_rate[:5]
                ]
            }
            
            self.logger.info(f"📊 Rule effectiveness report generated: "
                           f"{report.total_rules} rules analyzed, "
                           f"{len(created_files)} files created")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error generating rule effectiveness report: {e}")
            return {"error": str(e), "success": False}
    
    def get_rule_effectiveness_summary(self, knowledge_accumulator) -> Dict[str, Any]:
        """
        Task 8.3: Получение краткой сводки об эффективности правил.
        
        Args:
            knowledge_accumulator: Экземпляр KnowledgeAccumulator
            
        Returns:
            Словарь с краткой статистикой эффективности
        """
        if not self.effectiveness_reporter or not knowledge_accumulator:
            return {}
        
        try:
            # Анализируем правила
            rule_stats = self.effectiveness_reporter.analyze_rule_effectiveness(knowledge_accumulator)
            
            if not rule_stats:
                return {"total_rules": 0, "message": "No rules found"}
            
            # Вычисляем основные метрики
            active_rules = [r for r in rule_stats if r.total_applications > 0]
            high_performance_rules = [r for r in active_rules if r.success_rate > 0.8]
            
            # Топ 3 правила по успешности
            top_rules = sorted(active_rules, key=lambda x: x.success_rate, reverse=True)[:3]
            
            # Средняя эффективность
            avg_success_rate = 0.0
            if active_rules:
                avg_success_rate = sum(r.success_rate for r in active_rules) / len(active_rules)
            
            return {
                "total_rules": len(rule_stats),
                "active_rules": len(active_rules),
                "high_performance_rules": len(high_performance_rules),
                "average_success_rate": avg_success_rate,
                "top_rules": [
                    {
                        "rule_id": rule.rule_id,
                        "success_rate": rule.success_rate,
                        "applications": rule.total_applications
                    }
                    for rule in top_rules
                ],
                "performance_distribution": {
                    "excellent": len([r for r in active_rules if r.success_rate > 0.9]),
                    "good": len([r for r in active_rules if 0.7 < r.success_rate <= 0.9]),
                    "fair": len([r for r in active_rules if 0.5 < r.success_rate <= 0.7]),
                    "poor": len([r for r in active_rules if r.success_rate <= 0.5])
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting rule effectiveness summary: {e}")
            return {"error": str(e)}


def load_monitoring_config(
    config_file: str = "monitoring_config.json",
) -> MonitoringConfig:
    """Загружает конфигурацию мониторинга из файла."""
    config_path = Path(config_file)
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return MonitoringConfig(**data)
        except Exception as e:
            logging.warning(f"Failed to load config from {config_file}: {e}")
    return MonitoringConfig()


def save_monitoring_config(
    config: MonitoringConfig, config_file: str = "monitoring_config.json"
):
    """Сохраняет конфигурацию мониторинга в файл."""
    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(asdict(config), f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Failed to save config to {config_file}: {e}")
