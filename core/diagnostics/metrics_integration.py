"""
Diagnostics Metrics Integration

Интеграция метрик диагностики с существующей MonitoringSystem.
Добавляет метрики успешности стратегий, DoH резолюции и PCAP захвата.

Requirements: 11.1, 11.2, 11.6
"""

import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

LOG = logging.getLogger(__name__)


@dataclass
class StrategyMetrics:
    """Метрики успешности стратегий."""

    strategy_type: str
    domain: str
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        """Вычисляет процент успешности."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    @property
    def average_latency_ms(self) -> float:
        """Вычисляет среднюю задержку."""
        if self.successful_attempts == 0:
            return 0.0
        return self.total_latency_ms / self.successful_attempts

    def record_success(self, latency_ms: float) -> None:
        """Записывает успешное применение."""
        self.total_attempts += 1
        self.successful_attempts += 1
        self.total_latency_ms += latency_ms
        self.min_latency_ms = min(self.min_latency_ms, latency_ms)
        self.max_latency_ms = max(self.max_latency_ms, latency_ms)
        self.last_success = datetime.now()

    def record_failure(self) -> None:
        """Записывает неудачное применение."""
        self.total_attempts += 1
        self.failed_attempts += 1
        self.last_failure = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь."""
        return {
            "strategy_type": self.strategy_type,
            "domain": self.domain,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "success_rate": self.success_rate,
            "average_latency_ms": self.average_latency_ms,
            "min_latency_ms": self.min_latency_ms if self.min_latency_ms != float("inf") else 0.0,
            "max_latency_ms": self.max_latency_ms,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_failure": self.last_failure.isoformat() if self.last_failure else None,
        }


@dataclass
class DoHMetrics:
    """Метрики DoH резолюции."""

    provider: str
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_resolution_time_ms: float = 0.0
    min_resolution_time_ms: float = float("inf")
    max_resolution_time_ms: float = 0.0
    last_query: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        """Вычисляет процент успешности."""
        if self.total_queries == 0:
            return 0.0
        return self.successful_queries / self.total_queries

    @property
    def cache_hit_rate(self) -> float:
        """Вычисляет процент попаданий в кэш."""
        total_cache_ops = self.cache_hits + self.cache_misses
        if total_cache_ops == 0:
            return 0.0
        return self.cache_hits / total_cache_ops

    @property
    def average_resolution_time_ms(self) -> float:
        """Вычисляет среднее время резолюции."""
        if self.successful_queries == 0:
            return 0.0
        return self.total_resolution_time_ms / self.successful_queries

    def record_query(
        self, success: bool, resolution_time_ms: float, cache_hit: bool = False
    ) -> None:
        """Записывает запрос."""
        self.total_queries += 1
        self.last_query = datetime.now()

        if success:
            self.successful_queries += 1
            self.total_resolution_time_ms += resolution_time_ms
            self.min_resolution_time_ms = min(self.min_resolution_time_ms, resolution_time_ms)
            self.max_resolution_time_ms = max(self.max_resolution_time_ms, resolution_time_ms)
        else:
            self.failed_queries += 1

        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь."""
        return {
            "provider": self.provider,
            "total_queries": self.total_queries,
            "successful_queries": self.successful_queries,
            "failed_queries": self.failed_queries,
            "success_rate": self.success_rate,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hit_rate,
            "average_resolution_time_ms": self.average_resolution_time_ms,
            "min_resolution_time_ms": (
                self.min_resolution_time_ms if self.min_resolution_time_ms != float("inf") else 0.0
            ),
            "max_resolution_time_ms": self.max_resolution_time_ms,
            "last_query": self.last_query.isoformat() if self.last_query else None,
        }


@dataclass
class PCAPMetrics:
    """Метрики PCAP захвата."""

    total_captures: int = 0
    successful_captures: int = 0
    failed_captures: int = 0
    total_packets_captured: int = 0
    total_bytes_captured: int = 0
    total_capture_duration_ms: float = 0.0
    last_capture: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        """Вычисляет процент успешности."""
        if self.total_captures == 0:
            return 0.0
        return self.successful_captures / self.total_captures

    @property
    def average_packets_per_capture(self) -> float:
        """Вычисляет среднее количество пакетов на захват."""
        if self.successful_captures == 0:
            return 0.0
        return self.total_packets_captured / self.successful_captures

    @property
    def average_capture_duration_ms(self) -> float:
        """Вычисляет среднюю длительность захвата."""
        if self.successful_captures == 0:
            return 0.0
        return self.total_capture_duration_ms / self.successful_captures

    def record_capture(
        self, success: bool, packets: int = 0, bytes_captured: int = 0, duration_ms: float = 0.0
    ) -> None:
        """Записывает захват."""
        self.total_captures += 1
        self.last_capture = datetime.now()

        if success:
            self.successful_captures += 1
            self.total_packets_captured += packets
            self.total_bytes_captured += bytes_captured
            self.total_capture_duration_ms += duration_ms
        else:
            self.failed_captures += 1

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь."""
        return {
            "total_captures": self.total_captures,
            "successful_captures": self.successful_captures,
            "failed_captures": self.failed_captures,
            "success_rate": self.success_rate,
            "total_packets_captured": self.total_packets_captured,
            "total_bytes_captured": self.total_bytes_captured,
            "average_packets_per_capture": self.average_packets_per_capture,
            "average_capture_duration_ms": self.average_capture_duration_ms,
            "last_capture": self.last_capture.isoformat() if self.last_capture else None,
        }


class DiagnosticsMetricsCollector:
    """
    Коллектор метрик диагностики.

    Собирает и агрегирует метрики успешности стратегий,
    DoH резолюции и PCAP захвата.

    Requirements: 11.1, 11.2, 11.6
    """

    def __init__(self):
        """Инициализация коллектора."""
        self.logger = LOG

        # Strategy metrics by domain and strategy type
        self.strategy_metrics: Dict[str, StrategyMetrics] = {}

        # DoH metrics by provider
        self.doh_metrics: Dict[str, DoHMetrics] = {}

        # PCAP metrics (global)
        self.pcap_metrics = PCAPMetrics()

        # Time-series data for trending
        self.strategy_success_history: List[Dict[str, Any]] = []
        self.doh_query_history: List[Dict[str, Any]] = []
        self.pcap_capture_history: List[Dict[str, Any]] = []

        # Retention period for history (24 hours)
        self.history_retention = timedelta(hours=24)

        self.logger.info("✅ DiagnosticsMetricsCollector initialized")

    def record_strategy_success(self, domain: str, strategy_type: str, latency_ms: float) -> None:
        """
        Записывает успешное применение стратегии.

        Args:
            domain: Доменное имя
            strategy_type: Тип стратегии
            latency_ms: Задержка в миллисекундах
        """
        key = f"{domain}:{strategy_type}"

        if key not in self.strategy_metrics:
            self.strategy_metrics[key] = StrategyMetrics(strategy_type=strategy_type, domain=domain)

        self.strategy_metrics[key].record_success(latency_ms)

        # Add to history
        self.strategy_success_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "domain": domain,
                "strategy_type": strategy_type,
                "success": True,
                "latency_ms": latency_ms,
            }
        )

        self._cleanup_history()

        self.logger.debug(f"✅ Strategy success: {domain} ({strategy_type}) - {latency_ms:.1f}ms")

    def record_strategy_failure(self, domain: str, strategy_type: str) -> None:
        """
        Записывает неудачное применение стратегии.

        Args:
            domain: Доменное имя
            strategy_type: Тип стратегии
        """
        key = f"{domain}:{strategy_type}"

        if key not in self.strategy_metrics:
            self.strategy_metrics[key] = StrategyMetrics(strategy_type=strategy_type, domain=domain)

        self.strategy_metrics[key].record_failure()

        # Add to history
        self.strategy_success_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "domain": domain,
                "strategy_type": strategy_type,
                "success": False,
            }
        )

        self._cleanup_history()

        self.logger.debug(f"❌ Strategy failure: {domain} ({strategy_type})")

    def record_doh_query(
        self, provider: str, success: bool, resolution_time_ms: float, cache_hit: bool = False
    ) -> None:
        """
        Записывает DoH запрос.

        Args:
            provider: Провайдер DoH
            success: Успешность запроса
            resolution_time_ms: Время резолюции в миллисекундах
            cache_hit: Попадание в кэш
        """
        if provider not in self.doh_metrics:
            self.doh_metrics[provider] = DoHMetrics(provider=provider)

        self.doh_metrics[provider].record_query(success, resolution_time_ms, cache_hit)

        # Add to history
        self.doh_query_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "provider": provider,
                "success": success,
                "resolution_time_ms": resolution_time_ms,
                "cache_hit": cache_hit,
            }
        )

        self._cleanup_history()

        status = "✅" if success else "❌"
        cache_status = "📋" if cache_hit else "🌐"
        self.logger.debug(
            f"{status}{cache_status} DoH query: {provider} - {resolution_time_ms:.1f}ms"
        )

    def record_pcap_capture(
        self, success: bool, packets: int = 0, bytes_captured: int = 0, duration_ms: float = 0.0
    ) -> None:
        """
        Записывает PCAP захват.

        Args:
            success: Успешность захвата
            packets: Количество захваченных пакетов
            bytes_captured: Количество захваченных байт
            duration_ms: Длительность захвата в миллисекундах
        """
        self.pcap_metrics.record_capture(success, packets, bytes_captured, duration_ms)

        # Add to history
        self.pcap_capture_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "success": success,
                "packets": packets,
                "bytes": bytes_captured,
                "duration_ms": duration_ms,
            }
        )

        self._cleanup_history()

        status = "✅" if success else "❌"
        self.logger.debug(
            f"{status} PCAP capture: {packets} packets, {bytes_captured} bytes, {duration_ms:.1f}ms"
        )

    def get_strategy_metrics(
        self, domain: Optional[str] = None, strategy_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Получает метрики стратегий.

        Args:
            domain: Фильтр по домену (опционально)
            strategy_type: Фильтр по типу стратегии (опционально)

        Returns:
            Словарь с метриками стратегий
        """
        filtered_metrics = {}

        for key, metrics in self.strategy_metrics.items():
            if domain and metrics.domain != domain:
                continue
            if strategy_type and metrics.strategy_type != strategy_type:
                continue

            filtered_metrics[key] = metrics.to_dict()

        return filtered_metrics

    def get_doh_metrics(self, provider: Optional[str] = None) -> Dict[str, Any]:
        """
        Получает метрики DoH.

        Args:
            provider: Фильтр по провайдеру (опционально)

        Returns:
            Словарь с метриками DoH
        """
        if provider:
            if provider in self.doh_metrics:
                return {provider: self.doh_metrics[provider].to_dict()}
            return {}

        return {p: m.to_dict() for p, m in self.doh_metrics.items()}

    def get_pcap_metrics(self) -> Dict[str, Any]:
        """
        Получает метрики PCAP.

        Returns:
            Словарь с метриками PCAP
        """
        return self.pcap_metrics.to_dict()

    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Получает все метрики.

        Returns:
            Словарь со всеми метриками
        """
        return {
            "strategy_metrics": self.get_strategy_metrics(),
            "doh_metrics": self.get_doh_metrics(),
            "pcap_metrics": self.get_pcap_metrics(),
            "summary": {
                "total_strategies": len(self.strategy_metrics),
                "total_doh_providers": len(self.doh_metrics),
                "strategy_success_rate": self._calculate_overall_strategy_success_rate(),
                "doh_success_rate": self._calculate_overall_doh_success_rate(),
                "pcap_success_rate": self.pcap_metrics.success_rate,
            },
        }

    def _calculate_overall_strategy_success_rate(self) -> float:
        """Вычисляет общий процент успешности стратегий."""
        if not self.strategy_metrics:
            return 0.0

        total_attempts = sum(m.total_attempts for m in self.strategy_metrics.values())
        successful_attempts = sum(m.successful_attempts for m in self.strategy_metrics.values())

        if total_attempts == 0:
            return 0.0

        return successful_attempts / total_attempts

    def _calculate_overall_doh_success_rate(self) -> float:
        """Вычисляет общий процент успешности DoH."""
        if not self.doh_metrics:
            return 0.0

        total_queries = sum(m.total_queries for m in self.doh_metrics.values())
        successful_queries = sum(m.successful_queries for m in self.doh_metrics.values())

        if total_queries == 0:
            return 0.0

        return successful_queries / total_queries

    def _cleanup_history(self) -> None:
        """Очищает старые записи из истории."""
        cutoff_time = datetime.now() - self.history_retention

        # Clean strategy history
        self.strategy_success_history = [
            h
            for h in self.strategy_success_history
            if datetime.fromisoformat(h["timestamp"]) > cutoff_time
        ]

        # Clean DoH history
        self.doh_query_history = [
            h
            for h in self.doh_query_history
            if datetime.fromisoformat(h["timestamp"]) > cutoff_time
        ]

        # Clean PCAP history
        self.pcap_capture_history = [
            h
            for h in self.pcap_capture_history
            if datetime.fromisoformat(h["timestamp"]) > cutoff_time
        ]

    def reset_metrics(self) -> None:
        """Сбрасывает все метрики."""
        self.strategy_metrics.clear()
        self.doh_metrics.clear()
        self.pcap_metrics = PCAPMetrics()
        self.strategy_success_history.clear()
        self.doh_query_history.clear()
        self.pcap_capture_history.clear()

        self.logger.info("🔄 Metrics reset")


# Global singleton instance
_metrics_collector: Optional[DiagnosticsMetricsCollector] = None


def get_diagnostics_metrics_collector() -> DiagnosticsMetricsCollector:
    """
    Получает глобальный экземпляр коллектора метрик.

    Returns:
        DiagnosticsMetricsCollector
    """
    global _metrics_collector

    if _metrics_collector is None:
        _metrics_collector = DiagnosticsMetricsCollector()

    return _metrics_collector
