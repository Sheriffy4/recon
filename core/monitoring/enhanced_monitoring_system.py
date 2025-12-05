"""
Enhanced Monitoring System with Online Analysis Integration

Расширяет существующую систему мониторинга интеграцией с онлайн анализом трафика,
автоматическим переключением стратегий и улучшенной системой метрик.
"""

import asyncio
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
import json
from pathlib import Path

try:
    from core.monitoring_system import MonitoringSystem, MonitoringConfig, ConnectionHealth
    MONITORING_SYSTEM_AVAILABLE = True
except ImportError:
    MONITORING_SYSTEM_AVAILABLE = False
    MonitoringSystem = None
    MonitoringConfig = None

from .online_analysis_integration import OnlineAnalysisIntegration
from .real_time_traffic_analyzer import BlockingEvent, BlockingType


class EnhancedMonitoringSystem:
    """Расширенная система мониторинга с интеграцией онлайн анализа"""
    
    def __init__(self, 
                 config: Optional[Dict[str, Any]] = None,
                 enable_online_analysis: bool = True):
        self.logger = logging.getLogger(f"{__name__}.EnhancedMonitoringSystem")
        self.config = config or {}
        self.enable_online_analysis = enable_online_analysis
        
        # Инициализируем базовую систему мониторинга
        if MONITORING_SYSTEM_AVAILABLE:
            monitoring_config = MonitoringConfig(
                check_interval_seconds=self.config.get('check_interval_seconds', 30),
                failure_threshold=self.config.get('failure_threshold', 3),
                recovery_timeout_seconds=self.config.get('recovery_timeout_seconds', 300),
                max_concurrent_checks=self.config.get('max_concurrent_checks', 10),
                enable_auto_recovery=self.config.get('enable_auto_recovery', True),
                enable_adaptive_strategies=True,  # Всегда включаем для интеграции
                web_interface_port=self.config.get('web_interface_port', 8080),
                log_level=self.config.get('log_level', 'INFO')
            )
            
            self.base_monitoring = MonitoringSystem(
                config=monitoring_config,
                enable_modern_bypass=True
            )
        else:
            self.base_monitoring = None
            self.logger.warning("Base monitoring system not available")
        
        # Инициализируем онлайн анализ
        self.online_analysis: Optional[OnlineAnalysisIntegration] = None
        if enable_online_analysis:
            try:
                self.online_analysis = OnlineAnalysisIntegration(
                    monitoring_system=self.base_monitoring,
                    config_file=self.config.get('online_analysis_config', 'online_analysis_config.json')
                )
                
                # Настраиваем интеграцию
                self._setup_online_analysis_integration()
                
            except Exception as e:
                self.logger.error(f"Failed to initialize online analysis: {e}")
                self.online_analysis = None
        
        # Дополнительные метрики
        self.enhanced_metrics = {
            'total_blocking_events': 0,
            'automatic_recoveries': 0,
            'manual_interventions': 0,
            'strategy_switches': 0,
            'avg_recovery_time_seconds': 0.0,
            'online_analysis_uptime': 0.0
        }
        
        self.running = False
        self.start_time = None
        
        self.logger.info("Enhanced monitoring system initialized")
    
    def _setup_online_analysis_integration(self):
        """Настраивает интеграцию с онлайн анализом"""
        if not self.online_analysis:
            return
        
        # Добавляем callback для алертов
        self.online_analysis.add_alert_callback(self._handle_online_analysis_alert)
        
        self.logger.info("Online analysis integration configured")
    
    def _handle_online_analysis_alert(self, alert: Dict[str, Any]):
        """Обрабатывает алерты от онлайн анализа"""
        self.logger.warning(f"Online analysis alert: {alert['message']}")
        
        # Можно добавить дополнительную логику обработки алертов
        if alert['severity'] == 'critical':
            # Критические алерты требуют немедленного внимания
            self._handle_critical_alert(alert)
    
    def _handle_critical_alert(self, alert: Dict[str, Any]):
        """Обрабатывает критические алерты"""
        self.logger.critical(f"CRITICAL ALERT: {alert['message']}")
        
        # Здесь можно добавить логику для:
        # - Отправки уведомлений администраторам
        # - Автоматического переключения в безопасный режим
        # - Создания детального отчета о проблеме
        pass
    
    async def start(self):
        """Запускает расширенную систему мониторинга"""
        if self.running:
            self.logger.warning("Enhanced monitoring system is already running")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Запускаем базовую систему мониторинга
        if self.base_monitoring:
            await self.base_monitoring.start()
            self.logger.info("Base monitoring system started")
        
        # Запускаем онлайн анализ
        if self.online_analysis:
            self.online_analysis.start()
            self.logger.info("Online analysis started")
        
        self.logger.info("Enhanced monitoring system started")
    
    async def stop(self):
        """Останавливает расширенную систему мониторинга"""
        if not self.running:
            return
        
        self.running = False
        
        # Останавливаем онлайн анализ
        if self.online_analysis:
            self.online_analysis.stop()
            self.logger.info("Online analysis stopped")
        
        # Останавливаем базовую систему мониторинга
        if self.base_monitoring:
            await self.base_monitoring.stop()
            self.logger.info("Base monitoring system stopped")
        
        self.logger.info("Enhanced monitoring system stopped")
    
    def add_site(self, domain: str, port: int = 443, enable_online_monitoring: bool = True):
        """Добавляет сайт для мониторинга"""
        # Добавляем в базовую систему
        if self.base_monitoring:
            self.base_monitoring.add_site(domain, port)
        
        # Если включен онлайн мониторинг, настраиваем дополнительное отслеживание
        if enable_online_monitoring and self.online_analysis:
            # Онлайн анализ автоматически отслеживает весь трафик
            # Дополнительная настройка не требуется
            pass
        
        self.logger.info(f"Added {domain}:{port} to enhanced monitoring")
    
    def remove_site(self, domain: str, port: int = 443):
        """Удаляет сайт из мониторинга"""
        if self.base_monitoring:
            self.base_monitoring.remove_site(domain, port)
        
        self.logger.info(f"Removed {domain}:{port} from enhanced monitoring")
    
    def force_strategy_switch(self, domain: str, strategy_id: str) -> bool:
        """Принудительно переключает стратегию для домена"""
        if not self.online_analysis:
            self.logger.error("Online analysis not available for strategy switching")
            return False
        
        success = self.online_analysis.force_strategy_switch(domain, strategy_id)
        
        if success:
            self.enhanced_metrics['manual_interventions'] += 1
            self.enhanced_metrics['strategy_switches'] += 1
        
        return success
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Возвращает комплексный статус системы"""
        status = {
            'timestamp': datetime.now().isoformat(),
            'system_uptime_seconds': time.time() - (self.start_time or time.time()),
            'enhanced_metrics': self.enhanced_metrics.copy()
        }
        
        # Добавляем статус базовой системы
        if self.base_monitoring:
            base_status = self.base_monitoring.get_status_report()
            status['base_monitoring'] = base_status
        
        # Добавляем статус онлайн анализа
        if self.online_analysis:
            online_status = self.online_analysis.get_comprehensive_stats()
            status['online_analysis'] = online_status
            
            # Обновляем enhanced метрики на основе онлайн анализа
            online_metrics = online_status.get('online_analysis_metrics', {})
            self.enhanced_metrics['total_blocking_events'] = online_metrics.get('blocking_events_detected', 0)
            self.enhanced_metrics['automatic_recoveries'] = online_metrics.get('successful_bypasses', 0)
            self.enhanced_metrics['online_analysis_uptime'] = online_metrics.get('uptime_seconds', 0.0)
        
        return status
    
    def get_health_summary(self) -> str:
        """Возвращает краткое резюме состояния"""
        summary_parts = []
        
        # Базовая система
        if self.base_monitoring:
            base_summary = self.base_monitoring.get_health_summary()
            summary_parts.append(base_summary)
        
        # Онлайн анализ
        if self.online_analysis:
            online_stats = self.online_analysis.get_comprehensive_stats()
            online_metrics = online_stats.get('online_analysis_metrics', {})
            
            blocking_events = online_metrics.get('blocking_events_detected', 0)
            successful_bypasses = online_metrics.get('successful_bypasses', 0)
            
            summary_parts.append(
                f"🔍 Online: {blocking_events} blocks detected, {successful_bypasses} bypassed"
            )
        
        return " | ".join(summary_parts) if summary_parts else "📊 Enhanced monitoring active"
    
    def get_recent_events(self, seconds: int = 300) -> List[Dict[str, Any]]:
        """Возвращает недавние события"""
        events = []
        
        if self.online_analysis:
            # Получаем события блокировки
            blocking_events = self.online_analysis.traffic_analyzer.get_recent_blocking_events(seconds)
            for event in blocking_events:
                events.append({
                    'type': 'blocking_detected',
                    'timestamp': event['timestamp'],
                    'domain': event['domain'],
                    'details': event
                })
            
            # Получаем переключения стратегий
            strategy_switches = self.online_analysis.strategy_orchestrator.get_recent_switches(seconds)
            for switch in strategy_switches:
                events.append({
                    'type': 'strategy_switch',
                    'timestamp': switch.timestamp,
                    'domain': switch.domain,
                    'details': {
                        'old_strategy': switch.old_strategy,
                        'new_strategy': switch.new_strategy,
                        'reason': switch.reason,
                        'success': switch.success,
                        'response_time_ms': switch.response_time_ms
                    }
                })
        
        # Сортируем по времени
        events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return events
    
    def export_metrics(self, filepath: str):
        """Экспортирует метрики в файл"""
        try:
            status = self.get_comprehensive_status()
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(status, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Metrics exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error exporting metrics: {e}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Возвращает отчет о производительности"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'reporting_period_hours': 24,  # Последние 24 часа
            'summary': {}
        }
        
        if self.online_analysis:
            online_stats = self.online_analysis.get_comprehensive_stats()
            online_metrics = online_stats.get('online_analysis_metrics', {})
            
            # Основные метрики производительности
            report['summary'] = {
                'total_blocking_events': online_metrics.get('blocking_events_detected', 0),
                'successful_bypasses': online_metrics.get('successful_bypasses', 0),
                'failed_bypasses': online_metrics.get('failed_bypasses', 0),
                'bypass_success_rate': online_metrics.get('avg_bypass_success_rate', 0.0),
                'avg_detection_time_ms': online_metrics.get('avg_detection_time_ms', 0.0),
                'avg_strategy_generation_time_ms': online_metrics.get('avg_strategy_generation_time_ms', 0.0),
                'strategies_generated': online_metrics.get('strategies_generated', 0),
                'strategies_tested': online_metrics.get('strategies_tested', 0)
            }
            
            # Детальная статистика
            report['detailed_stats'] = online_stats
        
        if self.base_monitoring:
            base_status = self.base_monitoring.get_status_report()
            report['base_monitoring_stats'] = base_status
        
        return report


def create_enhanced_monitoring_system(config_file: str = "enhanced_monitoring_config.json") -> EnhancedMonitoringSystem:
    """Создает экземпляр расширенной системы мониторинга"""
    config = {}
    
    config_path = Path(config_file)
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception as e:
            logging.error(f"Error loading enhanced monitoring config: {e}")
    
    return EnhancedMonitoringSystem(
        config=config,
        enable_online_analysis=config.get('enable_online_analysis', True)
    )