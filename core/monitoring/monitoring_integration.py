"""
Monitoring Integration - Интеграция Real-Time Monitor с существующим monitoring_system.py
Реализует требования FR-4, FR-8 для адаптивной системы мониторинга.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass

# Импорт существующих компонентов
try:
    from monitoring_system import MonitoringSystem, MonitoringConfig as BaseMonitoringConfig
    from core.monitoring.real_time_monitor import RealTimeMonitor, MonitoringConfig as RTMConfig, TrafficEvent
    from core.adaptive_engine import AdaptiveEngine
    MONITORING_COMPONENTS_AVAILABLE = True
except ImportError as e:
    MONITORING_COMPONENTS_AVAILABLE = False
    logging.warning(f"Monitoring components not available: {e}")

LOG = logging.getLogger("monitoring_integration")


@dataclass
class IntegratedMonitoringConfig:
    """Объединенная конфигурация для интегрированной системы мониторинга"""
    
    # Базовые настройки мониторинга
    base_monitoring: BaseMonitoringConfig
    
    # Настройки Real-Time Monitor
    real_time_monitoring: RTMConfig
    
    # Интеграция
    enable_cross_validation: bool = True
    enable_adaptive_triggers: bool = True
    sync_interval_seconds: int = 60
    
    # Уведомления
    enable_combined_notifications: bool = True
    notification_webhook_url: Optional[str] = None


class EnhancedMonitoringSystem:
    """
    Расширенная система мониторинга, объединяющая:
    - Существующий MonitoringSystem (активные проверки)
    - RealTimeMonitor (пассивный анализ трафика)
    - AdaptiveEngine (автоматическая калибровка)
    """
    
    def __init__(self, config: IntegratedMonitoringConfig, adaptive_engine: Optional[AdaptiveEngine] = None):
        if not MONITORING_COMPONENTS_AVAILABLE:
            raise ImportError("Required monitoring components not available")
        
        self.config = config
        self.adaptive_engine = adaptive_engine
        
        # Инициализация компонентов
        self.base_monitor = MonitoringSystem(
            config.base_monitoring,
            enable_modern_bypass=True
        )
        
        self.real_time_monitor = RealTimeMonitor(
            config.real_time_monitoring,
            adaptive_engine=adaptive_engine
        )
        
        # Состояние интеграции
        self.is_running = False
        self.sync_task: Optional[asyncio.Task] = None
        self.cross_validation_task: Optional[asyncio.Task] = None
        
        # Статистика интеграции
        self.integration_stats = {
            "start_time": None,
            "cross_validations": 0,
            "adaptive_triggers": 0,
            "combined_notifications": 0,
            "sync_operations": 0,
            "correlation_matches": 0
        }
        
        # Кэш для корреляции событий
        self.event_correlation_cache: Dict[str, List[Dict[str, Any]]] = {}
        
        LOG.info("EnhancedMonitoringSystem initialized")
    
    async def start(self):
        """Запуск интегрированной системы мониторинга"""
        if self.is_running:
            LOG.warning("EnhancedMonitoringSystem is already running")
            return
        
        LOG.info("Starting EnhancedMonitoringSystem...")
        
        self.is_running = True
        self.integration_stats["start_time"] = datetime.now()
        
        # Запускаем базовый мониторинг
        await self.base_monitor.start()
        
        # Запускаем Real-Time Monitor
        await self.real_time_monitor.start()
        
        # Запускаем задачи интеграции
        self.sync_task = asyncio.create_task(self._sync_loop())
        
        if self.config.enable_cross_validation:
            self.cross_validation_task = asyncio.create_task(self._cross_validation_loop())
        
        LOG.info("EnhancedMonitoringSystem started successfully")
    
    async def stop(self):
        """Остановка интегрированной системы мониторинга"""
        if not self.is_running:
            return
        
        LOG.info("Stopping EnhancedMonitoringSystem...")
        
        self.is_running = False
        
        # Останавливаем задачи интеграции
        if self.sync_task:
            self.sync_task.cancel()
        if self.cross_validation_task:
            self.cross_validation_task.cancel()
        
        # Останавливаем компоненты
        await self.base_monitor.stop()
        await self.real_time_monitor.stop()
        
        LOG.info("EnhancedMonitoringSystem stopped")
    
    def add_site(self, domain: str, port: int = 443, current_strategy: Optional[str] = None):
        """Добавление сайта для мониторинга в обе системы"""
        # Добавляем в базовый мониторинг
        self.base_monitor.add_site(domain, port, current_strategy)
        
        LOG.info(f"Added {domain}:{port} to integrated monitoring")
    
    def remove_site(self, domain: str, port: int = 443):
        """Удаление сайта из мониторинга"""
        self.base_monitor.remove_site(domain, port)
        
        LOG.info(f"Removed {domain}:{port} from integrated monitoring")
    
    async def _sync_loop(self):
        """Цикл синхронизации между компонентами"""
        while self.is_running:
            try:
                await self._perform_sync()
                await asyncio.sleep(self.config.sync_interval_seconds)
            except Exception as e:
                LOG.error(f"Error in sync loop: {e}")
                await asyncio.sleep(10)
    
    async def _perform_sync(self):
        """Выполнение синхронизации данных"""
        try:
            # Получаем данные от обеих систем
            base_status = self.base_monitor.get_status_report()
            rtm_status = self.real_time_monitor.get_status_report()
            
            # Синхронизируем список доменов
            await self._sync_monitored_domains(base_status)
            
            # Корреляция событий
            await self._correlate_events(base_status, rtm_status)
            
            self.integration_stats["sync_operations"] += 1
            
        except Exception as e:
            LOG.error(f"Error performing sync: {e}")
    
    async def _sync_monitored_domains(self, base_status: Dict[str, Any]):
        """Синхронизация списка отслеживаемых доменов"""
        # Извлекаем домены из базового мониторинга
        monitored_sites = base_status.get("sites", {})
        
        # Обновляем кэш корреляции для новых доменов
        for site_key, site_info in monitored_sites.items():
            domain = site_info.get("domain")
            if domain and domain not in self.event_correlation_cache:
                self.event_correlation_cache[domain] = []
    
    async def _correlate_events(self, base_status: Dict[str, Any], rtm_status: Dict[str, Any]):
        """Корреляция событий между активным и пассивным мониторингом"""
        
        # Получаем недавние события от Real-Time Monitor
        recent_rtm_events = await self.real_time_monitor.get_recent_events(limit=50)
        
        # Получаем информацию о сайтах из базового мониторинга
        monitored_sites = base_status.get("sites", {})
        
        for site_key, site_info in monitored_sites.items():
            domain = site_info.get("domain")
            if not domain:
                continue
            
            # Ищем корреляции для этого домена
            correlations = await self._find_correlations_for_domain(
                domain, site_info, recent_rtm_events
            )
            
            if correlations:
                await self._handle_correlations(domain, correlations)
    
    async def _find_correlations_for_domain(self, domain: str, site_info: Dict[str, Any], 
                                          rtm_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Поиск корреляций для конкретного домена"""
        correlations = []
        
        # Фильтруем события Real-Time Monitor для этого домена
        domain_events = [
            event for event in rtm_events
            if event.get("domain") == domain or 
               (event.get("dest_ip") == site_info.get("ip") and 
                event.get("dest_port") == site_info.get("port"))
        ]
        
        if not domain_events:
            return correlations
        
        # Проверяем корреляции с состоянием базового мониторинга
        is_accessible = site_info.get("is_accessible", True)
        consecutive_failures = site_info.get("consecutive_failures", 0)
        
        for event in domain_events:
            correlation = await self._analyze_event_correlation(
                event, is_accessible, consecutive_failures
            )
            
            if correlation:
                correlations.append(correlation)
        
        return correlations
    
    async def _analyze_event_correlation(self, rtm_event: Dict[str, Any], 
                                       is_accessible: bool, consecutive_failures: int) -> Optional[Dict[str, Any]]:
        """Анализ корреляции между событием RTM и состоянием базового мониторинга"""
        
        event_type = rtm_event.get("event_type")
        event_confidence = rtm_event.get("confidence", 0.0)
        
        # Корреляция: RTM обнаружил блокировку + базовый мониторинг показывает недоступность
        if (event_type in ["connection_blocked", "rst_injection", "tls_handshake_fail"] and
            not is_accessible and consecutive_failures >= 2):
            
            return {
                "type": "blocking_confirmation",
                "rtm_event": rtm_event,
                "base_monitoring": {
                    "is_accessible": is_accessible,
                    "consecutive_failures": consecutive_failures
                },
                "correlation_confidence": min(0.95, event_confidence + 0.2),
                "timestamp": datetime.now().isoformat(),
                "recommended_action": "trigger_adaptive_calibration"
            }
        
        # Корреляция: RTM показывает успешные соединения + базовый мониторинг показывает проблемы
        elif (event_type == "connection_success" and 
              not is_accessible and consecutive_failures >= 1):
            
            return {
                "type": "monitoring_discrepancy",
                "rtm_event": rtm_event,
                "base_monitoring": {
                    "is_accessible": is_accessible,
                    "consecutive_failures": consecutive_failures
                },
                "correlation_confidence": 0.7,
                "timestamp": datetime.now().isoformat(),
                "recommended_action": "recheck_base_monitoring"
            }
        
        return None
    
    async def _handle_correlations(self, domain: str, correlations: List[Dict[str, Any]]):
        """Обработка найденных корреляций"""
        
        for correlation in correlations:
            correlation_type = correlation.get("type")
            recommended_action = correlation.get("recommended_action")
            confidence = correlation.get("correlation_confidence", 0.0)
            
            LOG.info(f"🔗 Correlation found for {domain}: {correlation_type} (confidence: {confidence:.2f})")
            
            # Выполняем рекомендуемые действия
            if recommended_action == "trigger_adaptive_calibration" and self.config.enable_adaptive_triggers:
                await self._trigger_adaptive_calibration(domain, correlation)
            
            elif recommended_action == "recheck_base_monitoring":
                await self._trigger_base_monitoring_recheck(domain)
            
            # Отправляем уведомление о корреляции
            if self.config.enable_combined_notifications:
                await self._send_correlation_notification(domain, correlation)
            
            self.integration_stats["correlation_matches"] += 1
    
    async def _trigger_adaptive_calibration(self, domain: str, correlation: Dict[str, Any]):
        """Запуск адаптивной калибровки на основе корреляции"""
        
        if not self.adaptive_engine:
            LOG.warning(f"AdaptiveEngine not available for calibration of {domain}")
            return
        
        try:
            LOG.info(f"🔧 Triggering adaptive calibration for {domain} based on correlation")
            
            # Запускаем калибровку в фоне
            calibration_task = asyncio.create_task(
                self.adaptive_engine.find_best_strategy(
                    domain,
                    progress_callback=lambda msg: LOG.info(f"Calibration {domain}: {msg}")
                )
            )
            
            self.integration_stats["adaptive_triggers"] += 1
            
        except Exception as e:
            LOG.error(f"Error triggering adaptive calibration for {domain}: {e}")
    
    async def _trigger_base_monitoring_recheck(self, domain: str):
        """Запуск повторной проверки в базовом мониторинге"""
        
        try:
            # Находим сайт в базовом мониторинге
            for site_key, health in self.base_monitor.monitored_sites.items():
                if health.domain == domain:
                    LOG.info(f"🔄 Triggering recheck for {domain}")
                    
                    # Выполняем внеочередную проверку
                    await self.base_monitor.check_site_health(site_key)
                    break
                    
        except Exception as e:
            LOG.error(f"Error triggering recheck for {domain}: {e}")
    
    async def _send_correlation_notification(self, domain: str, correlation: Dict[str, Any]):
        """Отправка уведомления о корреляции"""
        
        notification = {
            "type": "correlation_detected",
            "domain": domain,
            "correlation": correlation,
            "timestamp": datetime.now().isoformat(),
            "integration_stats": self.integration_stats.copy()
        }
        
        # Здесь можно добавить отправку webhook'а или другие уведомления
        if self.config.notification_webhook_url:
            await self._send_webhook_notification(notification)
        
        LOG.info(f"📢 Correlation notification sent for {domain}")
        self.integration_stats["combined_notifications"] += 1
    
    async def _send_webhook_notification(self, notification: Dict[str, Any]):
        """Отправка webhook уведомления"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.notification_webhook_url,
                    json=notification,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        LOG.debug("Webhook notification sent successfully")
                    else:
                        LOG.warning(f"Webhook notification failed: {response.status}")
                        
        except Exception as e:
            LOG.error(f"Error sending webhook notification: {e}")
    
    async def _cross_validation_loop(self):
        """Цикл кросс-валидации между системами"""
        while self.is_running:
            try:
                await self._perform_cross_validation()
                await asyncio.sleep(120)  # Каждые 2 минуты
            except Exception as e:
                LOG.error(f"Error in cross-validation loop: {e}")
                await asyncio.sleep(30)
    
    async def _perform_cross_validation(self):
        """Выполнение кросс-валидации"""
        
        try:
            # Получаем список заблокированных доменов от Real-Time Monitor
            detected_blocks = self.real_time_monitor.get_detected_blocks()
            
            # Проверяем их в базовом мониторинге
            for block_event in detected_blocks:
                domain = block_event.get("domain")
                dest_ip = block_event.get("dest_ip")
                dest_port = block_event.get("dest_port", 443)
                
                if domain:
                    await self._cross_validate_domain(domain, dest_port, block_event)
            
            self.integration_stats["cross_validations"] += 1
            
        except Exception as e:
            LOG.error(f"Error performing cross-validation: {e}")
    
    async def _cross_validate_domain(self, domain: str, port: int, block_event: Dict[str, Any]):
        """Кросс-валидация конкретного домена"""
        
        # Проверяем, есть ли домен в базовом мониторинге
        site_key = f"{domain}:{port}"
        
        if site_key not in self.base_monitor.monitored_sites:
            # Добавляем домен в базовый мониторинг для проверки
            self.base_monitor.add_site(domain, port)
            LOG.info(f"Added {domain} to base monitoring for cross-validation")
        
        # Выполняем проверку
        health = await self.base_monitor.check_site_health(site_key)
        
        # Анализируем результаты
        if not health.is_accessible:
            LOG.info(f"✅ Cross-validation confirmed blocking for {domain}")
            
            # Если блокировка подтверждена, запускаем калибровку
            if self.config.enable_adaptive_triggers and self.adaptive_engine:
                await self._trigger_adaptive_calibration(domain, {
                    "type": "cross_validation_confirmed",
                    "rtm_event": block_event,
                    "base_monitoring_result": health.to_dict()
                })
        else:
            LOG.info(f"❓ Cross-validation shows {domain} is accessible (possible false positive)")
    
    def get_integrated_status_report(self) -> Dict[str, Any]:
        """Получение объединенного отчета о состоянии"""
        
        base_status = self.base_monitor.get_status_report()
        rtm_status = self.real_time_monitor.get_status_report()
        
        # Вычисляем дополнительные метрики интеграции
        uptime_seconds = 0
        if self.integration_stats["start_time"]:
            uptime_seconds = (datetime.now() - self.integration_stats["start_time"]).total_seconds()
        
        return {
            "integration": {
                "is_running": self.is_running,
                "uptime_seconds": uptime_seconds,
                "statistics": self.integration_stats.copy(),
                "config": {
                    "cross_validation_enabled": self.config.enable_cross_validation,
                    "adaptive_triggers_enabled": self.config.enable_adaptive_triggers,
                    "combined_notifications_enabled": self.config.enable_combined_notifications
                }
            },
            "base_monitoring": base_status,
            "real_time_monitoring": rtm_status,
            "correlation_cache_size": len(self.event_correlation_cache),
            "adaptive_engine_available": self.adaptive_engine is not None
        }
    
    def get_health_summary(self) -> str:
        """Получение краткого резюме состояния интегрированной системы"""
        
        base_summary = self.base_monitor.get_health_summary()
        rtm_status = self.real_time_monitor.get_status_report()
        
        rtm_blocks = len(rtm_status.get("recent_blocks", []))
        correlations = self.integration_stats["correlation_matches"]
        
        return (f"{base_summary} | "
                f"RTM: {rtm_blocks} blocks detected, {correlations} correlations found")


# Функция для создания интегрированной системы
def create_integrated_monitoring_system(
    sites_file: str = "sites.txt",
    adaptive_engine: Optional[AdaptiveEngine] = None,
    enable_real_time: bool = True,
    webhook_url: Optional[str] = None
) -> EnhancedMonitoringSystem:
    """
    Создание интегрированной системы мониторинга
    
    Args:
        sites_file: Файл со списком сайтов для мониторинга
        adaptive_engine: Экземпляр AdaptiveEngine для автоматической калибровки
        enable_real_time: Включить Real-Time Monitor
        webhook_url: URL для отправки уведомлений
    
    Returns:
        Настроенная EnhancedMonitoringSystem
    """
    
    # Базовая конфигурация мониторинга
    base_config = BaseMonitoringConfig(
        check_interval_seconds=60,
        failure_threshold=3,
        enable_auto_recovery=True,
        enable_adaptive_strategies=True
    )
    
    # Конфигурация Real-Time Monitor
    rtm_config = RTMConfig(
        enabled=enable_real_time,
        capture_filter="tcp port 443",
        auto_trigger_calibration=True,
        enable_dpi_fingerprinting=True,
        notification_cooldown_seconds=300
    )
    
    # Интегрированная конфигурация
    integrated_config = IntegratedMonitoringConfig(
        base_monitoring=base_config,
        real_time_monitoring=rtm_config,
        enable_cross_validation=True,
        enable_adaptive_triggers=bool(adaptive_engine),
        enable_combined_notifications=True,
        notification_webhook_url=webhook_url
    )
    
    # Создаем систему
    system = EnhancedMonitoringSystem(integrated_config, adaptive_engine)
    
    # Загружаем сайты из файла
    if Path(sites_file).exists():
        try:
            with open(sites_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Поддерживаем формат "domain:port" или просто "domain"
                        if ':' in line:
                            domain, port = line.split(':', 1)
                            system.add_site(domain.strip(), int(port.strip()))
                        else:
                            system.add_site(line.strip())
            
            LOG.info(f"Loaded sites from {sites_file}")
            
        except Exception as e:
            LOG.error(f"Error loading sites from {sites_file}: {e}")
    
    return system


# Пример использования
if __name__ == "__main__":
    import asyncio
    
    async def test_integrated_monitoring():
        # Создаем интегрированную систему
        system = create_integrated_monitoring_system(
            sites_file="sites.txt",
            enable_real_time=True,
            webhook_url=None  # Можно указать URL для уведомлений
        )
        
        try:
            # Запускаем систему
            await system.start()
            
            print("Integrated monitoring system started")
            print("Monitoring both active checks and passive traffic analysis...")
            
            # Мониторим в течение некоторого времени
            for i in range(60):  # 1 минута
                await asyncio.sleep(1)
                
                if i % 15 == 0:
                    status = system.get_integrated_status_report()
                    summary = system.get_health_summary()
                    print(f"Status: {summary}")
            
        except KeyboardInterrupt:
            print("\nStopping integrated monitoring...")
        finally:
            await system.stop()
            
            # Финальный отчет
            final_status = system.get_integrated_status_report()
            print(f"\nFinal integration statistics:")
            print(f"  Correlations found: {final_status['integration']['statistics']['correlation_matches']}")
            print(f"  Adaptive triggers: {final_status['integration']['statistics']['adaptive_triggers']}")
            print(f"  Cross-validations: {final_status['integration']['statistics']['cross_validations']}")
    
    # Запускаем тест
    asyncio.run(test_integrated_monitoring())