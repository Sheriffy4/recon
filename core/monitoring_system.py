# recon/core/monitoring_system.py - Система мониторинга и автовосстановления

import asyncio
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import socket
from urllib.parse import urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None

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
        return {
            **asdict(self),
            'last_check': self.last_check.isoformat()
        }

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
    
    async def check_http_connectivity(self, domain: str, port: int = 443, use_https: bool = True) -> Tuple[bool, float, Optional[str]]:
        """Проверяет HTTP/HTTPS доступность."""
        if not AIOHTTP_AVAILABLE or not self.session:
            # Fallback к TCP проверке если aiohttp недоступен
            return await self.check_tcp_connectivity(domain, port)
        
        protocol = "https" if use_https else "http"
        url = f"{protocol}://{domain}:{port}" if port != (443 if use_https else 80) else f"{protocol}://{domain}"
        
        start_time = time.time()
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                response_time = (time.time() - start_time) * 1000
                return response.status < 400, response_time, None
        except asyncio.TimeoutError:
            return False, (time.time() - start_time) * 1000, "Timeout"
        except Exception as e:
            if AIOHTTP_AVAILABLE and 'aiohttp' in str(type(e)):
                return False, (time.time() - start_time) * 1000, str(e)
            else:
                return False, (time.time() - start_time) * 1000, f"HTTP Error: {e}"
    
    async def check_tcp_connectivity(self, domain: str, port: int) -> Tuple[bool, float, Optional[str]]:
        """Проверяет TCP доступность."""
        start_time = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            response_time = (time.time() - start_time) * 1000
            return True, response_time, None
        except asyncio.TimeoutError:
            return False, (time.time() - start_time) * 1000, "TCP Timeout"
        except ConnectionRefusedError:
            return False, (time.time() - start_time) * 1000, "Connection Refused"
        except Exception as e:
            return False, (time.time() - start_time) * 1000, f"TCP Error: {e}"

class AutoRecoverySystem:
    """Система автоматического восстановления соединений."""
    
    def __init__(self, learning_cache=None):
        self.learning_cache = learning_cache
        self.recovery_attempts: Dict[str, int] = {}
        self.last_recovery_time: Dict[str, datetime] = {}
        self.logger = logging.getLogger(__name__)
    
    async def attempt_recovery(self, health: ConnectionHealth, available_strategies: List[str]) -> bool:
        """Пытается восстановить соединение с сайтом."""
        domain_key = f"{health.domain}:{health.port}"
        
        # Проверяем, не слишком ли часто пытаемся восстанавливать
        if domain_key in self.last_recovery_time:
            time_since_last = datetime.now() - self.last_recovery_time[domain_key]
            if time_since_last < timedelta(minutes=5):
                self.logger.debug(f"Skipping recovery for {domain_key} - too soon since last attempt")
                return False
        
        self.logger.info(f"🔄 Attempting recovery for {health.domain}")
        
        # Получаем оптимальные стратегии из кэша обучения
        if self.learning_cache:
            optimized_strategies = self.learning_cache.get_smart_strategy_order(
                available_strategies, health.domain, health.ip
            )
        else:
            optimized_strategies = available_strategies
        
        # Пробуем стратегии по порядку
        for strategy in optimized_strategies[:3]:  # Пробуем только топ-3
            self.logger.info(f"  Trying strategy: {strategy}")
            
            # Здесь должна быть интеграция с BypassEngine
            # Пока что имитируем попытку восстановления
            success = await self._test_strategy_recovery(health, strategy)
            
            if success:
                self.logger.info(f"✅ Recovery successful with strategy: {strategy}")
                health.bypass_active = True
                health.current_strategy = strategy
                health.consecutive_failures = 0
                self.recovery_attempts[domain_key] = 0
                self.last_recovery_time[domain_key] = datetime.now()
                return True
        
        # Увеличиваем счетчик неудачных попыток
        self.recovery_attempts[domain_key] = self.recovery_attempts.get(domain_key, 0) + 1
        self.last_recovery_time[domain_key] = datetime.now()
        
        self.logger.warning(f"❌ Recovery failed for {health.domain} after trying {len(optimized_strategies[:3])} strategies")
        return False
    
    async def _test_strategy_recovery(self, health: ConnectionHealth, strategy: str) -> bool:
        """Тестирует восстановление с конкретной стратегией."""
        # Заглушка для тестирования стратегии
        # В реальной реализации здесь будет запуск BypassEngine с данной стратегией
        await asyncio.sleep(0.5)  # Имитация времени тестирования
        
        # Простая проверка доступности после применения стратегии
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(health.domain, health.port),
                timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

class MonitoringSystem:
    """Основная система мониторинга."""
    
    def __init__(self, config: MonitoringConfig, learning_cache=None):
        self.config = config
        self.learning_cache = learning_cache
        self.health_checker = HealthChecker(timeout=5.0)
        self.auto_recovery = AutoRecoverySystem(learning_cache)
        self.monitored_sites: Dict[str, ConnectionHealth] = {}
        self.is_running = False
        self.monitoring_task: Optional[asyncio.Task] = None
        self.logger = logging.getLogger(__name__)
        
        # Настройка логирования
        logging.basicConfig(level=getattr(logging, config.log_level))
    
    def add_site(self, domain: str, port: int = 443, current_strategy: Optional[str] = None):
        """Добавляет сайт для мониторинга."""
        site_key = f"{domain}:{port}"
        
        # Резолвим IP
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
            bypass_active=current_strategy is not None
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
        
        # Проверяем HTTP доступность
        is_accessible, response_time, error = await self.health_checker.check_http_connectivity(
            health.domain, health.port
        )
        
        # Обновляем состояние
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
                    # Проверяем все сайты параллельно
                    tasks = []
                    for site_key in list(self.monitored_sites.keys()):
                        task = asyncio.create_task(self.check_site_health(site_key))
                        tasks.append((site_key, task))
                    
                    # Ждем завершения всех проверок
                    for site_key, task in tasks:
                        try:
                            health = await task
                            
                            # Логируем состояние
                            status = "✅" if health.is_accessible else "❌"
                            self.logger.debug(f"{status} {health.domain} - {health.response_time_ms:.1f}ms")
                            
                            # Проверяем необходимость восстановления
                            if (not health.is_accessible and 
                                health.consecutive_failures >= self.config.failure_threshold and
                                self.config.enable_auto_recovery):
                                
                                await self._trigger_recovery(health)
                        
                        except Exception as e:
                            self.logger.error(f"Error checking {site_key}: {e}")
                    
                    # Ждем до следующей проверки
                    await asyncio.sleep(self.config.check_interval_seconds)
                
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    await asyncio.sleep(5)  # Короткая пауза при ошибке
    
    async def _trigger_recovery(self, health: ConnectionHealth):
        """Запускает процесс восстановления."""
        if self.config.enable_adaptive_strategies and self.learning_cache:
            # Получаем рекомендуемые стратегии из кэша
            domain_recs = self.learning_cache.get_domain_recommendations(health.domain, 5)
            available_strategies = [f"--dpi-desync={rec[0]}" for rec in domain_recs if rec[1] > 0.3]
        else:
            # Базовые стратегии
            available_strategies = [
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
                "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=2"
            ]
        
        success = await self.auto_recovery.attempt_recovery(health, available_strategies)
        
        if success:
            self.logger.info(f"🎉 Successfully recovered {health.domain}")
        else:
            self.logger.warning(f"⚠️ Failed to recover {health.domain}")
    
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
            "accessible_sites": sum(1 for h in self.monitored_sites.values() if h.is_accessible),
            "sites_with_bypass": sum(1 for h in self.monitored_sites.values() if h.bypass_active),
            "average_response_time": 0.0,
            "sites": {}
        }
        
        if self.monitored_sites:
            accessible_sites = [h for h in self.monitored_sites.values() if h.is_accessible]
            if accessible_sites:
                report["average_response_time"] = sum(h.response_time_ms for h in accessible_sites) / len(accessible_sites)
        
        for site_key, health in self.monitored_sites.items():
            report["sites"][site_key] = health.to_dict()
        
        return report
    
    def get_health_summary(self) -> str:
        """Возвращает краткое резюме состояния."""
        total = len(self.monitored_sites)
        accessible = sum(1 for h in self.monitored_sites.values() if h.is_accessible)
        with_bypass = sum(1 for h in self.monitored_sites.values() if h.bypass_active)
        
        return f"📊 Status: {accessible}/{total} accessible, {with_bypass} with bypass"

# Утилиты для работы с конфигурацией
def load_monitoring_config(config_file: str = "monitoring_config.json") -> MonitoringConfig:
    """Загружает конфигурацию мониторинга из файла."""
    config_path = Path(config_file)
    
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return MonitoringConfig(**data)
        except Exception as e:
            logging.warning(f"Failed to load config from {config_file}: {e}")
    
    # Возвращаем конфигурацию по умолчанию
    return MonitoringConfig()

def save_monitoring_config(config: MonitoringConfig, config_file: str = "monitoring_config.json"):
    """Сохраняет конфигурацию мониторинга в файл."""
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(config), f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Failed to save config to {config_file}: {e}")