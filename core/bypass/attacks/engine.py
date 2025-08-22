"""Базовый класс для всех движков обхода DPI."""
from abc import ABC, abstractmethod
from typing import Dict, Set, Optional, Any
import threading
from dataclasses import dataclass
from recon.core.bypass.diagnostics.metrics import MetricsCollector
from recon.core.bypass.diagnostics.logger import get_logger

@dataclass
class EngineConfig:
    """Конфигурация движка."""
    debug: bool = False
    max_packet_size: int = 1500
    socket_timeout: float = 2.0
    retry_on_timeout: int = 3
    enable_diagnostics: bool = True
    enable_caching: bool = True
    cache_ttl: int = 300
    performance_monitoring: bool = True

class BaseEngine(ABC):
    """Абстрактный базовый класс для всех движков обхода DPI."""

    def __init__(self, config: Optional[EngineConfig]=None):
        """
        Инициализация базового движка.

        Args:
            config: Конфигурация движка
        """
        self.config = config or EngineConfig()
        self.logger = get_logger(self.__class__.__name__, self.config.debug)
        self.metrics = MetricsCollector(self.__class__.__name__)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._initialize_components()
        self.logger.info(f'{self.__class__.__name__} initialized')

    @abstractmethod
    def _initialize_components(self) -> None:
        """Инициализация специфичных компонентов движка."""
        pass

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict]) -> Optional[threading.Thread]:
        """
        Запуск движка в отдельном потоке.

        Args:
            target_ips: Множество целевых IP-адресов
            strategy_map: Карта стратегий (IP -> стратегия)

        Returns:
            Thread объект или None при ошибке
        """
        if self._running:
            self.logger.warning('Engine already running')
            return None
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(target_ips, strategy_map), daemon=True, name=f'{self.__class__.__name__}-Thread')
        self._thread.start()
        self.logger.info(f'Engine started for {len(target_ips)} targets')
        return self._thread

    def stop(self) -> None:
        """Остановка движка."""
        if not self._running:
            self.logger.warning('Engine already stopped')
            return
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._cleanup()
        self.logger.info('Engine stopped')

    @abstractmethod
    def _run(self, target_ips: Set[str], strategy_map: Dict[str, Dict]) -> None:
        """
        Основной цикл работы движка.

        Args:
            target_ips: Множество целевых IP-адресов
            strategy_map: Карта стратегий
        """
        pass

    @abstractmethod
    def _cleanup(self) -> None:
        """Очистка ресурсов при остановке."""
        pass

    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики работы движка."""
        return self.metrics.get_stats()

    def get_diagnostics(self) -> Dict[str, Any]:
        """Получение диагностической информации."""
        return {'running': self._running, 'config': self.config.__dict__, 'stats': self.get_stats(), 'thread_alive': self._thread.is_alive() if self._thread else False}