# recon/core/metrics.py
# Реализация системы метрик качества обхода, предложенная Экспертом 2.

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class MetricData:
    """Data structure for storing metric information."""

    name: str
    value: float
    timestamp: datetime
    metadata: Dict[str, Any]


class MetricsCollector:
    """Collects and manages bypass performance metrics."""

    def __init__(self):
        self.metrics: List[MetricData] = []
        self.aggregated_metrics: Dict[str, Any] = {}

    def record_metric(
        self, name: str, value: float, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a single metric value."""
        metric = MetricData(
            name=name, value=value, timestamp=datetime.now(), metadata=metadata or {}
        )
        self.metrics.append(metric)

    def get_metrics(self, name: Optional[str] = None) -> List[MetricData]:
        """Get metrics, optionally filtered by name."""
        if name:
            return [m for m in self.metrics if m.name == name]
        return self.metrics.copy()

    def clear_metrics(self) -> None:
        """Clear all stored metrics."""
        self.metrics.clear()
        self.aggregated_metrics.clear()

    def get_average(self, name: str) -> Optional[float]:
        """Get average value for a metric."""
        values = [m.value for m in self.metrics if m.name == name]
        return sum(values) / len(values) if values else None


class BypassQualityMetrics:
    """Рассчитывает комплексную оценку качества успешной стратегии обхода."""

    def _calc_speed_score(self, rtt: float) -> float:
        """Оценка скорости: чем меньше RTT, тем выше оценка."""
        if rtt < 0.1:
            return 1.0  # Отлично
        if rtt > 2.0:
            return 0.1  # Очень медленно
        return max(0.1, 1.0 - (rtt / 2.0))

    def _calc_complexity_score(self, task: dict) -> float:
        """Оценка сложности: чем проще техника, тем выше оценка."""
        tech_type = task.get("type", "")
        if "combo" in tech_type:
            return 0.4  # Комбинированные атаки сложны
        if "split" in tech_type or "disorder" in tech_type:
            return 0.7  # Средняя сложность
        return 1.0  # Простые атаки

    def calculate_score(self, result: dict) -> dict:
        """
        Возвращает словарь с метриками и итоговой оценкой.
        result - элемент из списка results в cli.py
        """
        rtt = result.get("rtt", 1.0)
        task = result.get("task", {})

        speed = self._calc_speed_score(rtt)
        complexity = self._calc_complexity_score(task)

        # Итоговая оценка как средневзвешенное
        total_score = (speed * 0.6) + (complexity * 0.4)

        return {
            "speed": f"{speed:.2f}",
            "complexity": f"{complexity:.2f}",
            "total_score": f"{total_score:.2f}",
        }
