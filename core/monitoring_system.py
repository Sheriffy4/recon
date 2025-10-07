import asyncio
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import socket

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None
try:
    from recon.core.bypass.attacks.modern_registry import ModernAttackRegistry
    from recon.core.bypass.strategies.pool_management import (
        StrategyPoolManager,
        BypassStrategy,
    )
    from recon.core.bypass.validation.reliability_validator import ReliabilityValidator

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
                self.attack_registry = ModernAttackRegistry()
                self.pool_manager = StrategyPoolManager()
                self.reliability_validator = ReliabilityValidator()
                self.logger.info("Modern FORCED OVERRIDE bypass monitoring components initialized")
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
        for site_key, health in self.monitored_sites.items():
            report["sites"][site_key] = health.to_dict()
        return report

    def get_health_summary(self) -> str:
        """Возвращает краткое резюме состояния."""
        total = len(self.monitored_sites)
        accessible = sum((1 for h in self.monitored_sites.values() if h.is_accessible))
        with_bypass = sum((1 for h in self.monitored_sites.values() if h.bypass_active))
        return f"📊 Status: {accessible}/{total} accessible, {with_bypass} with bypass"


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
