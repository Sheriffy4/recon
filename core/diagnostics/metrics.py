"""Система сбора метрик."""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
from threading import Lock
import statistics
from core.diagnostics.logger import get_logger


@dataclass
class MetricPoint:
    """Точка метрики."""

    timestamp: float
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Коллектор метрик для мониторинга производительности."""

    def __init__(self, name: str, max_history: int = 1000):
        """
        Инициализация коллектора.

        Args:
            name: Имя коллектора
            max_history: Максимальный размер истории метрик
        """
        self.name = name
        self.max_history = max_history
        self.logger = get_logger(f"Metrics.{name}")
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self._timers: Dict[str, float] = {}
        self._lock = Lock()
        self._start_time = time.time()

    def increment_counter(
        self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Увеличение счетчика.

        Args:
            name: Имя счетчика
            value: Значение инкремента
            labels: Метки метрики
        """
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """
        Установка значения gauge.

        Args:
            name: Имя gauge
            value: Значение
            labels: Метки метрики
        """
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value

    def record_histogram(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Запись значения в гистограмму.

        Args:
            name: Имя гистограммы
            value: Значение
            labels: Метки метрики
        """
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(MetricPoint(time.time(), value, labels or {}))

    def start_timer(self, name: str) -> None:
        """
        Запуск таймера.

        Args:
            name: Имя таймера
        """
        with self._lock:
            self._timers[name] = time.time()

    def stop_timer(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """
        Остановка таймера и запись времени.

        Args:
            name: Имя таймера
            labels: Метки метрики

        Returns:
            Время выполнения в секундах
        """
        with self._lock:
            if name not in self._timers:
                self.logger.warning(f"Timer '{name}' not started")
                return None
            elapsed = time.time() - self._timers[name]
            del self._timers[name]
            self.record_histogram(f"{name}_duration", elapsed, labels)
            return elapsed

    def get_all_metrics(self) -> dict:
        """Возвращает словарь со всеми собранными метриками."""
        with self._lock:
            return {"counters": self._counters.copy(), "gauges": self._gauges.copy()}

    def get_counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> int:
        """Получение значения счетчика."""
        with self._lock:
            key = self._make_key(name, labels)
            return self._counters.get(key, 0)

    def get_gauge(self, name: str, labels: Optional[Dict[str, str]] = None) -> Optional[float]:
        """Получение значения gauge."""
        with self._lock:
            key = self._make_key(name, labels)
            return self._gauges.get(key)

    def get_histogram_stats(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> Dict[str, float]:
        """
        Получение статистики гистограммы.

        Args:
            name: Имя гистограммы
            labels: Метки метрики

        Returns:
            Словарь со статистикой
        """
        with self._lock:
            key = self._make_key(name, labels)
            points = self._histograms.get(key, deque())
            if not points:
                return {
                    "count": 0,
                    "min": 0.0,
                    "max": 0.0,
                    "mean": 0.0,
                    "median": 0.0,
                    "p95": 0.0,
                    "p99": 0.0,
                }
            values = [p.value for p in points]
            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "p95": self._percentile(values, 0.95),
                "p99": self._percentile(values, 0.99),
            }

    def get_stats(self) -> Dict[str, Any]:
        """Получение всей статистики."""
        with self._lock:
            stats = {
                "name": self.name,
                "uptime": time.time() - self._start_time,
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {},
            }
            for key in self._histograms:
                stats["histograms"][key] = self.get_histogram_stats(key)
            return stats

    def reset(self) -> None:
        """Сброс всех метрик."""
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._timers.clear()
            self._start_time = time.time()
        self.logger.info("Metrics reset")

    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Создание ключа для метрики."""
        if not labels:
            return name
        label_parts = [f"{k}={v}" for k, v in sorted(labels.items())]
        return f"{name}{{{','.join(label_parts)}}}"

    def _percentile(self, values: List[float], percentile: float) -> float:
        """Расчет перцентиля."""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile)
        if index >= len(sorted_values):
            return sorted_values[-1]
        return sorted_values[index]


class Timer:
    """Контекстный менеджер для измерения времени."""

    def __init__(
        self,
        metrics: MetricsCollector,
        name: str,
        labels: Optional[Dict[str, str]] = None,
    ):
        """
        Инициализация таймера.

        Args:
            metrics: Коллектор метрик
            name: Имя таймера
            labels: Метки метрики
        """
        self.metrics = metrics
        self.name = name
        self.labels = labels
        self.start_time = None

    def __enter__(self):
        """Вход в контекст - запуск таймера."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Выход из контекста - остановка таймера."""
        if self.start_time:
            elapsed = time.time() - self.start_time
            self.metrics.record_histogram(self.name, elapsed, self.labels)
