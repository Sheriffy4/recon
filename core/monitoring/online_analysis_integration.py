"""
Online Analysis Integration

Интегрирует Real-Time Traffic Analyzer и Adaptive Strategy Generator
в существующую систему мониторинга, реализует автоматическое переключение
стратегий при обнаружении блокировок, создает систему метрик для оценки
эффективности онлайн анализа и обеспечивает совместимость с AdaptiveEngine.
"""

import asyncio
import logging
import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any
import json
from pathlib import Path

from .real_time_traffic_analyzer import (
    RealTimeTrafficAnalyzer,
    BlockingEvent,
)
from .adaptive_online_strategy_generator import (
    AdaptiveOnlineStrategyGenerator,
    StrategyCandidate,
)

try:
    from core.monitoring_system import MonitoringSystem
    from core.monitoring.models import ConnectionHealth

    MONITORING_SYSTEM_AVAILABLE = True
except ImportError:
    MONITORING_SYSTEM_AVAILABLE = False
    MonitoringSystem = None
    ConnectionHealth = None

try:
    from core.adaptive_refactored.facade import AdaptiveEngine

    ADAPTIVE_ENGINE_AVAILABLE = True
except ImportError:
    ADAPTIVE_ENGINE_AVAILABLE = False
    AdaptiveEngine = None


@dataclass
class OnlineAnalysisMetrics:
    """Метрики онлайн анализа"""

    blocking_events_detected: int = 0
    strategies_generated: int = 0
    strategies_tested: int = 0
    successful_bypasses: int = 0
    failed_bypasses: int = 0
    ab_tests_completed: int = 0
    avg_detection_time_ms: float = 0.0
    avg_strategy_generation_time_ms: float = 0.0
    avg_bypass_success_rate: float = 0.0
    uptime_seconds: float = 0.0
    last_activity: Optional[float] = None


@dataclass
class StrategySwitch:
    """Событие переключения стратегии"""

    timestamp: float
    domain: str
    old_strategy: Optional[str]
    new_strategy: str
    reason: str
    success: bool
    response_time_ms: float


class NotificationManager:
    """Менеджер уведомлений и алертов"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.NotificationManager")
        self.alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self.notification_history = deque(maxlen=1000)
        self.alert_thresholds = {
            "blocking_rate_threshold": 0.5,  # 50% блокировок за период
            "strategy_failure_threshold": 0.8,  # 80% неудач стратегий
            "detection_delay_threshold": 10.0,  # 10 секунд на обнаружение
        }

    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Добавляет callback для алертов"""
        self.alert_callbacks.append(callback)

    def check_and_send_alerts(
        self, metrics: OnlineAnalysisMetrics, recent_events: List[BlockingEvent]
    ):
        """Проверяет условия и отправляет алерты"""
        alerts = []

        # Проверяем высокий уровень блокировок
        if len(recent_events) > 0:
            blocking_rate = len(recent_events) / max(1, metrics.strategies_tested)
            if blocking_rate > self.alert_thresholds["blocking_rate_threshold"]:
                alerts.append(
                    {
                        "type": "high_blocking_rate",
                        "severity": "warning",
                        "message": f"High blocking rate detected: {blocking_rate:.2%}",
                        "details": {
                            "blocking_rate": blocking_rate,
                            "events_count": len(recent_events),
                        },
                    }
                )

        # Проверяем низкую эффективность стратегий
        if metrics.strategies_tested > 10:
            failure_rate = metrics.failed_bypasses / metrics.strategies_tested
            if failure_rate > self.alert_thresholds["strategy_failure_threshold"]:
                alerts.append(
                    {
                        "type": "high_strategy_failure_rate",
                        "severity": "critical",
                        "message": f"High strategy failure rate: {failure_rate:.2%}",
                        "details": {
                            "failure_rate": failure_rate,
                            "total_tested": metrics.strategies_tested,
                        },
                    }
                )

        # Проверяем задержки обнаружения
        if (
            metrics.avg_detection_time_ms
            > self.alert_thresholds["detection_delay_threshold"] * 1000
        ):
            alerts.append(
                {
                    "type": "slow_detection",
                    "severity": "warning",
                    "message": f"Slow blocking detection: {metrics.avg_detection_time_ms:.1f}ms",
                    "details": {"avg_detection_time_ms": metrics.avg_detection_time_ms},
                }
            )

        # Отправляем алерты
        for alert in alerts:
            self._send_alert(alert)

    def _send_alert(self, alert: Dict[str, Any]):
        """Отправляет алерт всем подписчикам"""
        alert["timestamp"] = time.time()
        self.notification_history.append(alert)

        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")

        self.logger.warning(f"ALERT [{alert['severity']}]: {alert['message']}")


class StrategyOrchestrator:
    """Оркестратор стратегий - управляет применением и переключением стратегий"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.StrategyOrchestrator")
        self.active_strategies: Dict[str, str] = {}  # domain -> strategy_id
        self.strategy_switches: deque = deque(maxlen=1000)
        self.bypass_engine = None
        self.adaptive_engine = None

        # Инициализируем движки если доступны
        if ADAPTIVE_ENGINE_AVAILABLE:
            try:
                self.adaptive_engine = AdaptiveEngine()
                self.logger.info("AdaptiveEngine initialized for strategy orchestration")
            except Exception as e:
                self.logger.error(f"Failed to initialize AdaptiveEngine: {e}")

    async def apply_strategy(self, domain: str, strategy: StrategyCandidate) -> bool:
        """Применяет стратегию к домену"""
        start_time = time.time()

        try:
            # Если доступен AdaptiveEngine, используем его
            if self.adaptive_engine:
                success = await self._apply_via_adaptive_engine(domain, strategy)
            else:
                # Fallback к простому тестированию
                success = await self._apply_via_simple_test(domain, strategy)

            response_time = (time.time() - start_time) * 1000

            # Записываем переключение стратегии
            old_strategy = self.active_strategies.get(domain)
            switch = StrategySwitch(
                timestamp=time.time(),
                domain=domain,
                old_strategy=old_strategy,
                new_strategy=strategy.id,
                reason="blocking_detected",
                success=success,
                response_time_ms=response_time,
            )

            self.strategy_switches.append(switch)

            if success:
                self.active_strategies[domain] = strategy.id
                self.logger.info(f"Successfully applied strategy {strategy.id} to {domain}")
            else:
                self.logger.warning(f"Failed to apply strategy {strategy.id} to {domain}")

            return success

        except Exception as e:
            self.logger.error(f"Error applying strategy {strategy.id} to {domain}: {e}")
            return False

    async def _apply_via_adaptive_engine(self, domain: str, strategy: StrategyCandidate) -> bool:
        """Применяет стратегию через AdaptiveEngine"""
        try:
            # Конвертируем StrategyCandidate в формат AdaptiveEngine
            engine_strategy = self._convert_to_engine_format(strategy)

            # Тестируем стратегию
            result = await self.adaptive_engine.test_strategy(domain, engine_strategy)
            return result.success

        except Exception as e:
            self.logger.error(f"Error in AdaptiveEngine strategy application: {e}")
            return False

    async def _apply_via_simple_test(self, domain: str, strategy: StrategyCandidate) -> bool:
        """Простое тестирование стратегии (fallback)"""
        try:
            # Простая проверка доступности домена
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=10.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"https://{domain}") as response:
                    return response.status < 400

        except Exception as e:
            self.logger.debug(f"Simple test failed for {domain}: {e}")
            return False

    def _convert_to_engine_format(self, strategy: StrategyCandidate) -> Dict[str, Any]:
        """Конвертирует StrategyCandidate в формат для движка"""
        # Базовая конвертация - может потребоваться расширение
        return {
            "id": strategy.id,
            "type": strategy.strategy_type.value,
            "parameters": strategy.parameters,
            "confidence": strategy.confidence,
        }

    def get_active_strategy(self, domain: str) -> Optional[str]:
        """Возвращает активную стратегию для домена"""
        return self.active_strategies.get(domain)

    def get_recent_switches(self, seconds: int = 300) -> List[StrategySwitch]:
        """Возвращает недавние переключения стратегий"""
        cutoff = time.time() - seconds
        return [switch for switch in self.strategy_switches if switch.timestamp >= cutoff]


class OnlineAnalysisIntegration:
    """Основной класс интеграции онлайн анализа"""

    def __init__(
        self,
        monitoring_system: Optional[MonitoringSystem] = None,
        config_file: str = "online_analysis_config.json",
    ):
        self.logger = logging.getLogger(f"{__name__}.OnlineAnalysisIntegration")
        self.config_file = Path(config_file)
        self.monitoring_system = monitoring_system

        # Загружаем конфигурацию
        self.config = self._load_config()

        # Инициализируем компоненты
        self.traffic_analyzer = RealTimeTrafficAnalyzer(
            interface=self.config.get("interface"),
            capture_filter=self.config.get("capture_filter", "tcp port 443 or tcp port 80"),
            buffer_size=self.config.get("buffer_size", 10000),
        )

        self.strategy_generator = AdaptiveOnlineStrategyGenerator(
            strategy_cache_file=self.config.get(
                "strategy_cache_file", "online_strategies_cache.json"
            )
        )

        self.strategy_orchestrator = StrategyOrchestrator()
        self.notification_manager = NotificationManager()

        # Метрики и статистика
        self.metrics = OnlineAnalysisMetrics()
        self.start_time = time.time()
        self.running = False

        # Потоки обработки
        self.processing_thread: Optional[threading.Thread] = None
        self.metrics_thread: Optional[threading.Thread] = None

        # Настраиваем callbacks
        self.traffic_analyzer.add_blocking_callback(self._on_blocking_detected)

        self.logger.info("Online analysis integration initialized")

    def _load_config(self) -> Dict[str, Any]:
        """Загружает конфигурацию"""
        default_config = {
            "interface": None,
            "capture_filter": "tcp port 443 or tcp port 80",
            "buffer_size": 10000,
            "strategy_cache_file": "online_strategies_cache.json",
            "enable_ab_testing": True,
            "ab_test_ratio": 0.2,
            "auto_strategy_switching": True,
            "metrics_update_interval": 30,
            "max_strategies_per_blocking": 3,
            "strategy_timeout_seconds": 30,
        }

        if not self.config_file.exists():
            return default_config

        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                user_config = json.load(f)

            default_config.update(user_config)
            return default_config

        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return default_config

    def start(self):
        """Запускает интеграцию онлайн анализа"""
        if self.running:
            self.logger.warning("Online analysis integration is already running")
            return

        self.running = True
        self.start_time = time.time()

        # Запускаем анализатор трафика
        self.traffic_analyzer.start()

        # Запускаем поток обработки событий
        self.processing_thread = threading.Thread(
            target=self._processing_loop, name="OnlineAnalysisProcessing", daemon=True
        )
        self.processing_thread.start()

        # Запускаем поток обновления метрик
        self.metrics_thread = threading.Thread(
            target=self._metrics_loop, name="OnlineAnalysisMetrics", daemon=True
        )
        self.metrics_thread.start()

        # Интегрируемся с существующей системой мониторинга
        if self.monitoring_system and MONITORING_SYSTEM_AVAILABLE:
            self._integrate_with_monitoring_system()

        self.logger.info("Online analysis integration started")

    def stop(self):
        """Останавливает интеграцию онлайн анализа"""
        if not self.running:
            return

        self.running = False

        # Останавливаем анализатор трафика
        self.traffic_analyzer.stop()

        # Ждем завершения потоков
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5.0)

        if self.metrics_thread and self.metrics_thread.is_alive():
            self.metrics_thread.join(timeout=5.0)

        self.logger.info("Online analysis integration stopped")

    def _on_blocking_detected(self, blocking_event: BlockingEvent):
        """Обработчик события блокировки"""
        self.metrics.blocking_events_detected += 1
        self.metrics.last_activity = time.time()

        self.logger.info(
            f"Blocking detected: {blocking_event.domain} "
            f"({blocking_event.blocking_type.value}) confidence={blocking_event.confidence:.2f}"
        )

        # Если включено автоматическое переключение стратегий
        if self.config.get("auto_strategy_switching", True):
            # Запускаем обработку в отдельном потоке чтобы не блокировать анализатор
            threading.Thread(
                target=self._handle_blocking_async, args=(blocking_event,), daemon=True
            ).start()

    def _handle_blocking_async(self, blocking_event: BlockingEvent):
        """Асинхронная обработка события блокировки"""
        try:
            # Генерируем стратегии
            generation_start = time.time()
            strategies = self.strategy_generator.generate_strategies_for_blocking(
                blocking_event, count=self.config.get("max_strategies_per_blocking", 3)
            )
            generation_time = (time.time() - generation_start) * 1000

            self.metrics.strategies_generated += len(strategies)
            self.metrics.avg_strategy_generation_time_ms = (
                self.metrics.avg_strategy_generation_time_ms
                * (self.metrics.strategies_generated - len(strategies))
                + generation_time
            ) / self.metrics.strategies_generated

            if not strategies:
                self.logger.warning(f"No strategies generated for {blocking_event.domain}")
                return

            # Тестируем стратегии
            for strategy in strategies:
                success = asyncio.run(
                    self.strategy_orchestrator.apply_strategy(blocking_event.domain, strategy)
                )

                self.metrics.strategies_tested += 1

                if success:
                    self.metrics.successful_bypasses += 1

                    # Записываем успешный результат
                    self.strategy_generator.record_strategy_result(
                        strategy.id, blocking_event.domain, True, 0.0
                    )

                    self.logger.info(
                        f"Successfully bypassed {blocking_event.domain} with {strategy.id}"
                    )
                    break
                else:
                    self.metrics.failed_bypasses += 1

                    # Записываем неудачный результат
                    self.strategy_generator.record_strategy_result(
                        strategy.id, blocking_event.domain, False, 0.0, "Strategy failed"
                    )

            # Обновляем среднюю эффективность
            if self.metrics.strategies_tested > 0:
                self.metrics.avg_bypass_success_rate = (
                    self.metrics.successful_bypasses / self.metrics.strategies_tested
                )

        except Exception as e:
            self.logger.error(f"Error handling blocking event: {e}")

    def _processing_loop(self):
        """Основной цикл обработки"""
        self.logger.info("Starting online analysis processing loop")

        while self.running:
            try:
                # Обрабатываем A/B тесты
                self._process_ab_tests()

                # Обновляем статистику
                self._update_metrics()

                time.sleep(1.0)

            except Exception as e:
                self.logger.error(f"Error in processing loop: {e}")
                time.sleep(5.0)

        self.logger.info("Online analysis processing loop ended")

    def _process_ab_tests(self):
        """Обрабатывает A/B тесты"""
        if not self.config.get("enable_ab_testing", True):
            return

        # Здесь можно добавить логику для автоматического запуска A/B тестов
        # на основе накопленных данных
        pass

    def _metrics_loop(self):
        """Цикл обновления метрик"""
        self.logger.info("Starting metrics update loop")

        while self.running:
            try:
                interval = self.config.get("metrics_update_interval", 30)

                # Обновляем метрики
                self.metrics.uptime_seconds = time.time() - self.start_time

                # Получаем недавние события для анализа
                recent_events = self.traffic_analyzer.traffic_buffer.get_recent_events(300)

                # Проверяем алерты
                self.notification_manager.check_and_send_alerts(self.metrics, recent_events)

                # Интегрируемся с системой мониторинга
                if self.monitoring_system:
                    self._update_monitoring_system_metrics()

                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"Error in metrics loop: {e}")
                time.sleep(30.0)

        self.logger.info("Metrics update loop ended")

    def _integrate_with_monitoring_system(self):
        """Интегрируется с существующей системой мониторинга"""
        if not self.monitoring_system:
            return

        try:
            # Добавляем callback для уведомлений
            def monitoring_alert_callback(alert: Dict[str, Any]):
                self.logger.info(f"Monitoring alert: {alert['message']}")

            self.notification_manager.add_alert_callback(monitoring_alert_callback)

            self.logger.info("Integrated with existing monitoring system")

        except Exception as e:
            self.logger.error(f"Error integrating with monitoring system: {e}")

    def _update_monitoring_system_metrics(self):
        """Обновляет метрики в системе мониторинга"""
        if not self.monitoring_system:
            return

        try:
            # Добавляем наши метрики в систему мониторинга
            # Это зависит от конкретной реализации MonitoringSystem
            pass

        except Exception as e:
            self.logger.error(f"Error updating monitoring system metrics: {e}")

    def _update_metrics(self):
        """Обновляет внутренние метрики"""
        # Обновляем время обнаружения
        traffic_stats = self.traffic_analyzer.get_stats()
        if traffic_stats.get("last_activity"):
            detection_time = (time.time() - traffic_stats["last_activity"]) * 1000
            if self.metrics.avg_detection_time_ms == 0:
                self.metrics.avg_detection_time_ms = detection_time
            else:
                # Экспоненциальное сглаживание
                alpha = 0.1
                self.metrics.avg_detection_time_ms = (
                    alpha * detection_time + (1 - alpha) * self.metrics.avg_detection_time_ms
                )

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Возвращает комплексную статистику"""
        stats = {
            "online_analysis_metrics": {
                "blocking_events_detected": self.metrics.blocking_events_detected,
                "strategies_generated": self.metrics.strategies_generated,
                "strategies_tested": self.metrics.strategies_tested,
                "successful_bypasses": self.metrics.successful_bypasses,
                "failed_bypasses": self.metrics.failed_bypasses,
                "avg_bypass_success_rate": self.metrics.avg_bypass_success_rate,
                "avg_detection_time_ms": self.metrics.avg_detection_time_ms,
                "avg_strategy_generation_time_ms": self.metrics.avg_strategy_generation_time_ms,
                "uptime_seconds": self.metrics.uptime_seconds,
            },
            "traffic_analyzer_stats": self.traffic_analyzer.get_stats(),
            "strategy_generator_stats": self.strategy_generator.get_stats(),
            "active_strategies": dict(self.strategy_orchestrator.active_strategies),
            "recent_strategy_switches": [
                {
                    "timestamp": switch.timestamp,
                    "domain": switch.domain,
                    "old_strategy": switch.old_strategy,
                    "new_strategy": switch.new_strategy,
                    "reason": switch.reason,
                    "success": switch.success,
                    "response_time_ms": switch.response_time_ms,
                }
                for switch in self.strategy_orchestrator.get_recent_switches(300)
            ],
            "recent_blocking_events": self.traffic_analyzer.get_recent_blocking_events(300),
            "config": self.config,
        }

        return stats

    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Добавляет callback для алертов"""
        self.notification_manager.add_alert_callback(callback)

    def force_strategy_switch(self, domain: str, strategy_id: str) -> bool:
        """Принудительно переключает стратегию для домена"""
        if strategy_id not in self.strategy_generator.strategy_cache:
            self.logger.error(f"Strategy {strategy_id} not found in cache")
            return False

        strategy = self.strategy_generator.strategy_cache[strategy_id]
        success = asyncio.run(self.strategy_orchestrator.apply_strategy(domain, strategy))

        if success:
            self.logger.info(f"Manually switched {domain} to strategy {strategy_id}")
        else:
            self.logger.warning(f"Failed to manually switch {domain} to strategy {strategy_id}")

        return success
