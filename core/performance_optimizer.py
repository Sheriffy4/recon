# recon/core/performance_optimizer.py

"""
Performance optimization system for FastBypassEngine.
Implements caching, efficient strategy selection, and performance monitoring.
"""

import time
import threading
import logging
import statistics
from typing import Dict, List, Any, Optional
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache, wraps
import hashlib


@dataclass
class PerformanceMetrics:
    """Performance metrics for tracking system performance."""

    technique_name: str
    execution_time_ms: float
    success_rate: float
    packet_size: int
    segments_created: int
    memory_usage_mb: float
    cpu_usage_percent: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class CacheEntry:
    """Cache entry for fingerprints and strategy results."""

    data: Any
    timestamp: float
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    ttl_seconds: float = 3600  # 1 hour default TTL


@dataclass
class StrategyPerformance:
    """Performance data for a specific strategy."""

    strategy_type: str
    avg_execution_time_ms: float
    success_rate: float
    total_executions: int
    recent_performance: deque = field(default_factory=lambda: deque(maxlen=100))
    last_updated: float = field(default_factory=time.time)


class PerformanceCache:
    """High-performance cache with TTL and LRU eviction."""

    def __init__(self, max_size: int = 1000, default_ttl: float = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: deque = deque()
        self._lock = threading.RLock()

        # Performance metrics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache with LRU tracking."""
        with self._lock:
            if key not in self._cache:
                self.misses += 1
                return None

            entry = self._cache[key]

            # Check TTL
            if time.time() - entry.timestamp > entry.ttl_seconds:
                del self._cache[key]
                self.misses += 1
                return None

            # Update access tracking
            entry.access_count += 1
            entry.last_access = time.time()

            # Move to end of access order
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

            self.hits += 1
            return entry.data

    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Put item in cache with optional TTL."""
        with self._lock:
            ttl = ttl or self.default_ttl

            # If key exists, update it
            if key in self._cache:
                self._cache[key].data = value
                self._cache[key].timestamp = time.time()
                self._cache[key].ttl_seconds = ttl
                return

            # Check if we need to evict
            if len(self._cache) >= self.max_size:
                self._evict_lru()

            # Add new entry
            self._cache[key] = CacheEntry(
                data=value, timestamp=time.time(), ttl_seconds=ttl
            )
            self._access_order.append(key)

    def _evict_lru(self) -> None:
        """Evict least recently used item."""
        if not self._access_order:
            return

        lru_key = self._access_order.popleft()
        if lru_key in self._cache:
            del self._cache[lru_key]
            self.evictions += 1

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        with self._lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests) if total_requests > 0 else 0.0

            return {
                "cache_size": len(self._cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": hit_rate,
                "total_requests": total_requests,
            }


class StrategySelector:
    """Efficient strategy selection algorithm with performance-based optimization."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("StrategySelector")

        # Strategy performance tracking
        self.strategy_performance: Dict[str, StrategyPerformance] = {}
        self.domain_strategy_cache = PerformanceCache(
            max_size=500, default_ttl=1800
        )  # 30 min

        # Performance thresholds
        self.min_success_rate = 0.7
        self.max_execution_time_ms = 100.0
        self.performance_window_size = 50

        self._lock = threading.RLock()

    def select_optimal_strategy(
        self,
        domain: str,
        available_strategies: List[Dict[str, Any]],
        fingerprint: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Select optimal strategy based on performance metrics and domain characteristics."""

        # Check cache first
        cache_key = self._generate_cache_key(domain, available_strategies)
        cached_strategy = self.domain_strategy_cache.get(cache_key)
        if cached_strategy:
            self.logger.debug(f"Using cached strategy for {domain}")
            return cached_strategy

        # Score strategies based on performance
        scored_strategies = []

        for strategy in available_strategies:
            strategy_type = strategy.get("type", "unknown")
            score = self._calculate_strategy_score(strategy_type, domain, fingerprint)
            scored_strategies.append((score, strategy))

        # Sort by score (higher is better)
        scored_strategies.sort(key=lambda x: x[0], reverse=True)

        if scored_strategies:
            best_strategy = scored_strategies[0][1]

            # Cache the result
            self.domain_strategy_cache.put(cache_key, best_strategy)

            self.logger.debug(
                f"Selected strategy {best_strategy.get('type')} for {domain} with score {scored_strategies[0][0]:.3f}"
            )
            return best_strategy

        return None

    def _calculate_strategy_score(
        self, strategy_type: str, domain: str, fingerprint: Optional[Any] = None
    ) -> float:
        """Calculate performance score for a strategy."""
        with self._lock:
            perf = self.strategy_performance.get(strategy_type)

            if not perf:
                # New strategy, give it a neutral score
                return 0.5

            # Base score from success rate
            success_score = perf.success_rate

            # Time penalty (faster is better)
            time_score = max(
                0.0, 1.0 - (perf.avg_execution_time_ms / self.max_execution_time_ms)
            )

            # Recency bonus (more recent data is more valuable)
            recency_score = max(
                0.0, 1.0 - (time.time() - perf.last_updated) / 3600
            )  # 1 hour decay

            # Execution count bonus (more data is more reliable)
            reliability_score = min(1.0, perf.total_executions / 100.0)

            # Fingerprint compatibility (if available)
            fingerprint_score = 1.0
            if fingerprint:
                fingerprint_score = self._calculate_fingerprint_compatibility(
                    strategy_type, fingerprint
                )

            # Weighted combination
            total_score = (
                success_score * 0.4
                + time_score * 0.2
                + recency_score * 0.1
                + reliability_score * 0.1
                + fingerprint_score * 0.2
            )

            return total_score

    def _calculate_fingerprint_compatibility(
        self, strategy_type: str, fingerprint: Any
    ) -> float:
        """Calculate compatibility score between strategy and DPI fingerprint."""
        # This would be enhanced with actual fingerprint analysis
        # For now, return a neutral score
        return 1.0

    def update_strategy_performance(
        self,
        strategy_type: str,
        execution_time_ms: float,
        success: bool,
        packet_size: int = 0,
    ) -> None:
        """Update performance metrics for a strategy."""
        with self._lock:
            if strategy_type not in self.strategy_performance:
                self.strategy_performance[strategy_type] = StrategyPerformance(
                    strategy_type=strategy_type,
                    avg_execution_time_ms=execution_time_ms,
                    success_rate=1.0 if success else 0.0,
                    total_executions=1,
                )
            else:
                perf = self.strategy_performance[strategy_type]

                # Update recent performance
                perf.recent_performance.append(
                    {
                        "execution_time_ms": execution_time_ms,
                        "success": success,
                        "timestamp": time.time(),
                        "packet_size": packet_size,
                    }
                )

                # Recalculate averages
                recent_successes = sum(
                    1 for p in perf.recent_performance if p["success"]
                )
                recent_times = [p["execution_time_ms"] for p in perf.recent_performance]

                perf.success_rate = recent_successes / len(perf.recent_performance)
                perf.avg_execution_time_ms = (
                    statistics.mean(recent_times) if recent_times else execution_time_ms
                )
                perf.total_executions += 1
                perf.last_updated = time.time()

    def _generate_cache_key(self, domain: str, strategies: List[Dict[str, Any]]) -> str:
        """Generate cache key for domain and strategies."""
        strategy_types = sorted([s.get("type", "unknown") for s in strategies])
        key_data = f"{domain}:{':'.join(strategy_types)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get strategy selection performance statistics."""
        with self._lock:
            stats = {
                "total_strategies": len(self.strategy_performance),
                "cache_stats": self.domain_strategy_cache.get_stats(),
                "strategy_performance": {},
            }

            for strategy_type, perf in self.strategy_performance.items():
                stats["strategy_performance"][strategy_type] = {
                    "avg_execution_time_ms": perf.avg_execution_time_ms,
                    "success_rate": perf.success_rate,
                    "total_executions": perf.total_executions,
                    "recent_executions": len(perf.recent_performance),
                }

            return stats


class PacketBuilderOptimizer:
    """Optimizations for PacketBuilder operations."""

    def __init__(self):
        self.checksum_cache = PerformanceCache(max_size=200, default_ttl=300)  # 5 min
        self.header_template_cache = PerformanceCache(
            max_size=100, default_ttl=600
        )  # 10 min

        # Pre-computed values
        self._ip_header_template = None
        self._tcp_header_template = None

        self.logger = logging.getLogger("PacketBuilderOptimizer")

    @lru_cache(maxsize=128)
    def get_optimized_checksum(self, data_hash: str, data_length: int) -> int:
        """Get checksum with caching for identical data."""
        # This would be called with a hash of the data to enable caching
        # The actual checksum calculation would be done elsewhere
        return 0

    def optimize_packet_assembly(
        self, packet_count: int, payload_size: int
    ) -> Dict[str, Any]:
        """Provide optimization recommendations for packet assembly."""
        recommendations = {
            "use_batch_processing": packet_count > 10,
            "enable_checksum_caching": payload_size < 1500,
            "use_header_templates": packet_count > 5,
            "parallel_processing": packet_count > 20,
        }

        return recommendations

    def get_stats(self) -> Dict[str, Any]:
        """Get PacketBuilder optimization statistics."""
        return {
            "checksum_cache": self.checksum_cache.get_stats(),
            "header_template_cache": self.header_template_cache.get_stats(),
        }


class PerformanceMonitor:
    """Real-time performance monitoring and alerting system."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("PerformanceMonitor")

        # Performance metrics storage
        self.metrics_history: deque = deque(maxlen=1000)
        self.current_metrics = {}

        # Alerting thresholds
        self.thresholds = {
            "max_execution_time_ms": 200.0,
            "min_success_rate": 0.8,
            "max_memory_usage_mb": 100.0,
            "max_cpu_usage_percent": 80.0,
        }

        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        self._lock = threading.RLock()

        # Performance alerts
        self.alerts: deque = deque(maxlen=100)

    def start_monitoring(self, fast_bypass_engine) -> None:
        """Start performance monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop, args=(fast_bypass_engine,), daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("Performance monitoring started")

    def stop_monitoring(self) -> None:
        """Stop performance monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        self.logger.info("Performance monitoring stopped")

    def _monitoring_loop(self, fast_bypass_engine) -> None:
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect current metrics
                metrics = self._collect_metrics(fast_bypass_engine)

                with self._lock:
                    self.metrics_history.append(metrics)
                    self.current_metrics = metrics

                # Check for alerts
                self._check_alerts(metrics)

                # Sleep for monitoring interval
                time.sleep(5.0)  # Monitor every 5 seconds

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)

    def _collect_metrics(self, fast_bypass_engine) -> Dict[str, Any]:
        """Collect current performance metrics."""
        try:
            # Get stats from FastBypassEngine
            engine_stats = fast_bypass_engine.get_combined_stats()

            # Calculate derived metrics
            total_packets = engine_stats.get("packets_captured", 0)
            bypassed_packets = engine_stats.get(
                "tls_packets_bypassed", 0
            ) + engine_stats.get("http_packets_bypassed", 0)

            success_rate = (
                (bypassed_packets / total_packets) if total_packets > 0 else 0.0
            )

            metrics = {
                "timestamp": time.time(),
                "total_packets": total_packets,
                "bypassed_packets": bypassed_packets,
                "success_rate": success_rate,
                "fragments_sent": engine_stats.get("fragments_sent", 0),
                "fake_packets_sent": engine_stats.get("fake_packets_sent", 0),
                "possible_dpi_injections": engine_stats.get(
                    "possible_dpi_injections", 0
                ),
                "memory_usage_mb": self._get_memory_usage(),
                "cpu_usage_percent": self._get_cpu_usage(),
            }

            return metrics

        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            return {"timestamp": time.time(), "error": str(e)}

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil

            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
        except Exception:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil

            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return 0.0
        except Exception:
            return 0.0

    def _check_alerts(self, metrics: Dict[str, Any]) -> None:
        """Check metrics against thresholds and generate alerts."""
        alerts = []

        # Check success rate
        success_rate = metrics.get("success_rate", 0.0)
        if success_rate < self.thresholds["min_success_rate"]:
            alerts.append(
                {
                    "type": "low_success_rate",
                    "message": f"Success rate {success_rate:.2%} below threshold {self.thresholds['min_success_rate']:.2%}",
                    "severity": "warning",
                    "timestamp": time.time(),
                }
            )

        # Check memory usage
        memory_usage = metrics.get("memory_usage_mb", 0.0)
        if memory_usage > self.thresholds["max_memory_usage_mb"]:
            alerts.append(
                {
                    "type": "high_memory_usage",
                    "message": f"Memory usage {memory_usage:.1f}MB above threshold {self.thresholds['max_memory_usage_mb']}MB",
                    "severity": "warning",
                    "timestamp": time.time(),
                }
            )

        # Check CPU usage
        cpu_usage = metrics.get("cpu_usage_percent", 0.0)
        if cpu_usage > self.thresholds["max_cpu_usage_percent"]:
            alerts.append(
                {
                    "type": "high_cpu_usage",
                    "message": f"CPU usage {cpu_usage:.1f}% above threshold {self.thresholds['max_cpu_usage_percent']}%",
                    "severity": "warning",
                    "timestamp": time.time(),
                }
            )

        # Store alerts
        with self._lock:
            for alert in alerts:
                self.alerts.append(alert)
                if self.debug:
                    self.logger.warning(f"ALERT: {alert['message']}")

    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self._lock:
            return self.current_metrics.copy()

    def get_metrics_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical performance metrics."""
        with self._lock:
            return list(self.metrics_history)[-limit:]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        with self._lock:
            return list(self.alerts)[-limit:]

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics."""
        with self._lock:
            if not self.metrics_history:
                return {}

            recent_metrics = list(self.metrics_history)[-20:]  # Last 20 measurements

            success_rates = [
                m.get("success_rate", 0.0)
                for m in recent_metrics
                if "success_rate" in m
            ]
            memory_usage = [
                m.get("memory_usage_mb", 0.0)
                for m in recent_metrics
                if "memory_usage_mb" in m
            ]
            cpu_usage = [
                m.get("cpu_usage_percent", 0.0)
                for m in recent_metrics
                if "cpu_usage_percent" in m
            ]

            summary = {
                "avg_success_rate": (
                    statistics.mean(success_rates) if success_rates else 0.0
                ),
                "min_success_rate": min(success_rates) if success_rates else 0.0,
                "max_success_rate": max(success_rates) if success_rates else 0.0,
                "avg_memory_usage_mb": (
                    statistics.mean(memory_usage) if memory_usage else 0.0
                ),
                "max_memory_usage_mb": max(memory_usage) if memory_usage else 0.0,
                "avg_cpu_usage_percent": (
                    statistics.mean(cpu_usage) if cpu_usage else 0.0
                ),
                "max_cpu_usage_percent": max(cpu_usage) if cpu_usage else 0.0,
                "total_alerts": len(self.alerts),
                "recent_alerts": len(
                    [a for a in self.alerts if time.time() - a["timestamp"] < 300]
                ),  # Last 5 minutes
            }

            return summary


def performance_timer(func):
    """Decorator to measure function execution time."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            success = True
        except Exception:
            result = None
            success = False
            raise
        finally:
            execution_time = (
                time.time() - start_time
            ) * 1000  # Convert to milliseconds

            # Try to log performance if possible
            try:
                if hasattr(args[0], "performance_monitor"):
                    # This would be enhanced to integrate with the performance monitoring system
                    pass
            except:
                pass

        return result

    return wrapper


class PerformanceOptimizer:
    """Main performance optimization coordinator."""

    def __init__(self, fast_bypass_engine, debug: bool = False):
        self.fast_bypass_engine = fast_bypass_engine
        self.debug = debug
        self.logger = logging.getLogger("PerformanceOptimizer")

        # Initialize components
        self.strategy_selector = StrategySelector(debug=debug)
        self.packet_builder_optimizer = PacketBuilderOptimizer()
        self.performance_monitor = PerformanceMonitor(debug=debug)

        # Fingerprint cache
        self.fingerprint_cache = PerformanceCache(
            max_size=300, default_ttl=7200
        )  # 2 hours

        # Performance optimization settings
        self.optimization_enabled = True
        self.batch_processing_threshold = 10
        self.parallel_processing_threshold = 20

    def start_optimization(self) -> None:
        """Start performance optimization systems."""
        self.performance_monitor.start_monitoring(self.fast_bypass_engine)
        self.logger.info("Performance optimization started")

    def stop_optimization(self) -> None:
        """Stop performance optimization systems."""
        self.performance_monitor.stop_monitoring()
        self.logger.info("Performance optimization stopped")

    def optimize_strategy_selection(
        self,
        domain: str,
        available_strategies: List[Dict[str, Any]],
        fingerprint: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Optimize strategy selection using performance data."""
        if not self.optimization_enabled:
            return available_strategies[0] if available_strategies else None

        return self.strategy_selector.select_optimal_strategy(
            domain, available_strategies, fingerprint
        )

    def cache_fingerprint(
        self, domain: str, fingerprint: Any, ttl: Optional[float] = None
    ) -> None:
        """Cache domain fingerprint for performance."""
        self.fingerprint_cache.put(domain, fingerprint, ttl)

    def get_cached_fingerprint(self, domain: str) -> Optional[Any]:
        """Get cached domain fingerprint."""
        return self.fingerprint_cache.get(domain)

    def update_technique_performance(
        self,
        technique: str,
        execution_time_ms: float,
        success: bool,
        packet_size: int = 0,
    ) -> None:
        """Update performance metrics for a technique."""
        self.strategy_selector.update_strategy_performance(
            technique, execution_time_ms, success, packet_size
        )

    def get_optimization_recommendations(self) -> Dict[str, Any]:
        """Get performance optimization recommendations."""
        current_metrics = self.performance_monitor.get_current_metrics()
        performance_summary = self.performance_monitor.get_performance_summary()

        recommendations = {
            "enable_caching": True,
            "use_batch_processing": current_metrics.get("total_packets", 0)
            > self.batch_processing_threshold,
            "enable_parallel_processing": current_metrics.get("total_packets", 0)
            > self.parallel_processing_threshold,
            "optimize_memory": performance_summary.get("max_memory_usage_mb", 0) > 50,
            "tune_thresholds": performance_summary.get("avg_success_rate", 1.0) < 0.9,
        }

        return recommendations

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        return {
            "strategy_selector": self.strategy_selector.get_performance_stats(),
            "packet_builder_optimizer": self.packet_builder_optimizer.get_stats(),
            "performance_monitor": {
                "current_metrics": self.performance_monitor.get_current_metrics(),
                "performance_summary": self.performance_monitor.get_performance_summary(),
                "recent_alerts": self.performance_monitor.get_alerts(10),
            },
            "fingerprint_cache": self.fingerprint_cache.get_stats(),
            "optimization_settings": {
                "optimization_enabled": self.optimization_enabled,
                "batch_processing_threshold": self.batch_processing_threshold,
                "parallel_processing_threshold": self.parallel_processing_threshold,
            },
        }
