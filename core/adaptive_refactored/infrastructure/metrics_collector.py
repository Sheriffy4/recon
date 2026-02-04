"""
Metrics Collector implementation for the refactored Adaptive Engine.

This component collects and manages performance and success metrics.
"""

import time
import logging
from typing import Dict, Any, List, Union
from collections import defaultdict, deque
from datetime import datetime, timedelta
from ..interfaces import IMetricsCollector
from ..models import CacheType, PerformanceMetrics
from ..config import AnalyticsConfig


logger = logging.getLogger(__name__)


class MetricsCollector(IMetricsCollector):
    """
    Implementation of metrics collection and management.

    Provides comprehensive metrics collection including timing,
    success rates, cache statistics, and performance monitoring.
    Extracted from the original AdaptiveEngine to follow SOLID principles.
    """

    def __init__(self, config: AnalyticsConfig):
        self.config = config
        self._operation_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._success_counts: Dict[str, int] = defaultdict(int)
        self._failure_counts: Dict[str, int] = defaultdict(int)
        self._cache_hits: Dict[CacheType, int] = defaultdict(int)
        self._cache_misses: Dict[CacheType, int] = defaultdict(int)
        self._start_time = time.time()
        self._last_reset = datetime.now()

        # Additional metrics extracted from original AdaptiveEngine
        self._domain_counts: Dict[str, int] = defaultdict(int)
        self._strategy_counts: Dict[str, int] = defaultdict(int)
        self._fingerprint_counts: int = 0
        self._failure_analysis_counts: int = 0
        self._parallel_test_counts: int = 0

        # Closed-loop learning metrics
        self._closed_loop_stats = {
            "iterations_total": 0,
            "intents_generated": 0,
            "strategies_augmented": 0,
            "pattern_matches": 0,
            "knowledge_updates": 0,
        }

        # Adaptive timeout metrics
        self._timeout_stats = {
            "adaptive_timeouts_applied": 0,
            "content_inspection_adjustments": 0,
            "rst_injection_adjustments": 0,
            "network_timeout_adjustments": 0,
            "slow_cdn_adjustments": 0,
            "average_timeout_factor": 1.0,
        }

        if config.enable_metrics:
            logger.info("Metrics collector initialized with metrics enabled")
        else:
            logger.info("Metrics collector initialized with metrics disabled")

    def record_operation_time(self, operation: str, duration: float) -> None:
        """Record timing for an operation."""
        if not self.config.enable_metrics:
            return

        self._operation_times[operation].append({"duration": duration, "timestamp": time.time()})

        logger.debug(f"Recorded operation time: {operation} = {duration:.3f}s")

    def record_success_rate(self, operation: str, success: bool) -> None:
        """Record success/failure for an operation."""
        if not self.config.enable_metrics:
            return

        if success:
            self._success_counts[operation] += 1
        else:
            self._failure_counts[operation] += 1

        logger.debug(
            f"Recorded operation result: {operation} = {'success' if success else 'failure'}"
        )

    def record_cache_hit(self, cache_type: Union[CacheType, str]) -> None:
        """Record cache hit."""
        if not self.config.enable_metrics:
            return

        # Handle both string and enum inputs
        if isinstance(cache_type, str):
            cache_type = CacheType(cache_type)

        self._cache_hits[cache_type] += 1
        logger.debug(f"Recorded cache hit: {cache_type.value}")

    def record_cache_miss(self, cache_type: Union[CacheType, str]) -> None:
        """Record cache miss."""
        if not self.config.enable_metrics:
            return

        # Handle both string and enum inputs
        if isinstance(cache_type, str):
            cache_type = CacheType(cache_type)

        self._cache_misses[cache_type] += 1
        logger.debug(f"Recorded cache miss: {cache_type.value}")

    def record_domain_processed(self, domain: str) -> None:
        """Record that a domain has been processed."""
        if not self.config.enable_metrics:
            return

        self._domain_counts[domain] += 1
        logger.debug(f"Recorded domain processed: {domain}")

    def record_strategy_found(self, strategy_name: str) -> None:
        """Record that a strategy was found/generated."""
        if not self.config.enable_metrics:
            return

        self._strategy_counts[strategy_name] += 1
        logger.debug(f"Recorded strategy found: {strategy_name}")

    def record_fingerprint_created(self) -> None:
        """Record that a fingerprint was created."""
        if not self.config.enable_metrics:
            return

        self._fingerprint_counts += 1
        logger.debug("Recorded fingerprint created")

    def record_failure_analyzed(self) -> None:
        """Record that a failure was analyzed."""
        if not self.config.enable_metrics:
            return

        self._failure_analysis_counts += 1
        logger.debug("Recorded failure analyzed")

    def record_parallel_test(self) -> None:
        """Record that a parallel test was executed."""
        if not self.config.enable_metrics:
            return

        self._parallel_test_counts += 1
        logger.debug("Recorded parallel test executed")

    def record_closed_loop_iteration(self) -> None:
        """Record a closed-loop learning iteration."""
        if not self.config.enable_metrics:
            return

        self._closed_loop_stats["iterations_total"] += 1
        logger.debug("Recorded closed-loop iteration")

    def record_intent_generated(self) -> None:
        """Record that an intent was generated."""
        if not self.config.enable_metrics:
            return

        self._closed_loop_stats["intents_generated"] += 1
        logger.debug("Recorded intent generated")

    def record_strategy_augmented(self) -> None:
        """Record that a strategy was augmented."""
        if not self.config.enable_metrics:
            return

        self._closed_loop_stats["strategies_augmented"] += 1
        logger.debug("Recorded strategy augmented")

    def record_pattern_match(self) -> None:
        """Record that a pattern was matched."""
        if not self.config.enable_metrics:
            return

        self._closed_loop_stats["pattern_matches"] += 1
        logger.debug("Recorded pattern match")

    def record_knowledge_update(self) -> None:
        """Record that knowledge was updated."""
        if not self.config.enable_metrics:
            return

        self._closed_loop_stats["knowledge_updates"] += 1
        logger.debug("Recorded knowledge update")

    def record_adaptive_timeout(self, timeout_type: str, factor: float) -> None:
        """Record an adaptive timeout adjustment."""
        if not self.config.enable_metrics:
            return

        self._timeout_stats["adaptive_timeouts_applied"] += 1

        # Update specific timeout type counter
        if timeout_type == "content_inspection":
            self._timeout_stats["content_inspection_adjustments"] += 1
        elif timeout_type == "rst_injection":
            self._timeout_stats["rst_injection_adjustments"] += 1
        elif timeout_type == "network_timeout":
            self._timeout_stats["network_timeout_adjustments"] += 1
        elif timeout_type == "slow_cdn":
            self._timeout_stats["slow_cdn_adjustments"] += 1

        # Update average timeout factor
        current_avg = self._timeout_stats["average_timeout_factor"]
        applied_count = self._timeout_stats["adaptive_timeouts_applied"]

        if applied_count == 1:
            self._timeout_stats["average_timeout_factor"] = factor
        else:
            # Moving average
            self._timeout_stats["average_timeout_factor"] = (
                current_avg * (applied_count - 1) + factor
            ) / applied_count

        logger.debug(f"Recorded adaptive timeout: {timeout_type} with factor {factor}")

    def record_strategy_test(
        self, domain: str, strategy_name: str, success: bool, duration: float
    ) -> None:
        """Record the result of a strategy test."""
        if not self.config.enable_metrics:
            return

        # Record the test operation
        self.record_operation_time(f"strategy_test_{strategy_name}", duration)
        self.record_success_rate(f"strategy_test_{strategy_name}", success)

        # Record domain and strategy
        self.record_domain_processed(domain)
        if success:
            self.record_strategy_found(strategy_name)

        logger.debug(
            f"Recorded strategy test: {domain} with {strategy_name} = {'success' if success else 'failure'} in {duration:.3f}s"
        )

    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get performance-focused metrics."""
        if not self.config.enable_metrics:
            return PerformanceMetrics()

        # Get overall metrics summary
        summary = self.get_metrics_summary()

        # Extract performance-focused metrics
        cache_hit_rate = summary["summary"]["overall_cache_hit_rate"]
        total_domains_processed = summary["summary"]["domains_processed"]
        total_strategies_found = summary["summary"]["strategies_found"]

        # Calculate average test time from strategy test operations
        strategy_test_times = []
        for operation, stats in summary.get("operation_statistics", {}).items():
            if operation.startswith("strategy_test_"):
                strategy_test_times.append(stats["average_time"])

        average_test_time = 0.0
        if strategy_test_times:
            average_test_time = sum(strategy_test_times) / len(strategy_test_times)

        # Get strategy generation time
        strategy_generation_time = 0.0
        if "strategy_generation" in summary.get("operation_statistics", {}):
            strategy_generation_time = summary["operation_statistics"]["strategy_generation"][
                "average_time"
            ]

        # Get fingerprint creation time
        fingerprint_creation_time = 0.0
        if "fingerprint_creation" in summary.get("operation_statistics", {}):
            fingerprint_creation_time = summary["operation_statistics"]["fingerprint_creation"][
                "average_time"
            ]

        return PerformanceMetrics(
            cache_hit_rate=cache_hit_rate,
            average_test_time=average_test_time,
            strategy_generation_time=strategy_generation_time,
            fingerprint_creation_time=fingerprint_creation_time,
            total_domains_processed=total_domains_processed,
            total_strategies_found=total_strategies_found,
        )

    def get_closed_loop_stats(self) -> Dict[str, Any]:
        """Get closed-loop learning statistics."""
        if not self.config.enable_metrics:
            return {"metrics_enabled": False}

        return self._closed_loop_stats.copy()

    def get_timeout_stats(self) -> Dict[str, Any]:
        """Get adaptive timeout statistics."""
        if not self.config.enable_metrics:
            return {"metrics_enabled": False}

        return self._timeout_stats.copy()

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all collected metrics."""
        if not self.config.enable_metrics:
            return {"metrics_enabled": False}

        current_time = time.time()
        uptime = current_time - self._start_time

        # Calculate operation statistics
        operation_stats = {}
        for operation, times in self._operation_times.items():
            if times:
                durations = [t["duration"] for t in times]
                operation_stats[operation] = {
                    "count": len(durations),
                    "average_time": sum(durations) / len(durations),
                    "min_time": min(durations),
                    "max_time": max(durations),
                    "total_time": sum(durations),
                }

        # Calculate success rates
        success_rates = {}
        for operation in set(self._success_counts.keys()) | set(self._failure_counts.keys()):
            successes = self._success_counts[operation]
            failures = self._failure_counts[operation]
            total = successes + failures

            if total > 0:
                success_rates[operation] = {
                    "success_count": successes,
                    "failure_count": failures,
                    "total_count": total,
                    "success_rate": successes / total,
                    "failure_rate": failures / total,
                }

        # Calculate cache statistics
        cache_stats = {}
        for cache_type in set(self._cache_hits.keys()) | set(self._cache_misses.keys()):
            hits = self._cache_hits[cache_type]
            misses = self._cache_misses[cache_type]
            total = hits + misses

            if total > 0:
                cache_stats[cache_type.value] = {
                    "hits": hits,
                    "misses": misses,
                    "total_requests": total,
                    "hit_rate": hits / total,
                    "miss_rate": misses / total,
                }

        return {
            "metrics_enabled": True,
            "uptime_seconds": uptime,
            "last_reset": self._last_reset.isoformat(),
            "operation_statistics": operation_stats,
            "success_rates": success_rates,
            "cache_statistics": cache_stats,
            "domain_statistics": {
                "unique_domains_processed": len(self._domain_counts),
                "total_domain_operations": sum(self._domain_counts.values()),
                "domain_counts": dict(self._domain_counts),
            },
            "strategy_statistics": {
                "unique_strategies_found": len(self._strategy_counts),
                "total_strategies_found": sum(self._strategy_counts.values()),
                "strategy_counts": dict(self._strategy_counts),
            },
            "fingerprint_statistics": {"total_fingerprints_created": self._fingerprint_counts},
            "failure_analysis_statistics": {
                "total_failures_analyzed": self._failure_analysis_counts
            },
            "parallel_test_statistics": {"total_parallel_tests": self._parallel_test_counts},
            "closed_loop_statistics": self._closed_loop_stats.copy(),
            "timeout_statistics": self._timeout_stats.copy(),
            "summary": {
                "total_operations": sum(len(times) for times in self._operation_times.values()),
                "total_successes": sum(self._success_counts.values()),
                "total_failures": sum(self._failure_counts.values()),
                "total_cache_hits": sum(self._cache_hits.values()),
                "total_cache_misses": sum(self._cache_misses.values()),
                "overall_success_rate": self._calculate_overall_success_rate(),
                "overall_cache_hit_rate": self._calculate_overall_cache_hit_rate(),
                "domains_processed": len(self._domain_counts),
                "strategies_found": sum(self._strategy_counts.values()),
                "fingerprints_created": self._fingerprint_counts,
                "failures_analyzed": self._failure_analysis_counts,
                "parallel_tests_executed": self._parallel_test_counts,
            },
        }

    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate across all operations."""
        total_successes = sum(self._success_counts.values())
        total_failures = sum(self._failure_counts.values())
        total = total_successes + total_failures

        return total_successes / total if total > 0 else 0.0

    def _calculate_overall_cache_hit_rate(self) -> float:
        """Calculate overall cache hit rate across all cache types."""
        total_hits = sum(self._cache_hits.values())
        total_misses = sum(self._cache_misses.values())
        total = total_hits + total_misses

        return total_hits / total if total > 0 else 0.0

    def get_operation_metrics(self, operation: str) -> Dict[str, Any]:
        """Get detailed metrics for a specific operation."""
        if not self.config.enable_metrics:
            return {"metrics_enabled": False}

        metrics = {"operation": operation, "timing": {}, "success_rate": {}}

        # Timing metrics
        if operation in self._operation_times:
            times = self._operation_times[operation]
            if times:
                durations = [t["duration"] for t in times]
                metrics["timing"] = {
                    "count": len(durations),
                    "average": sum(durations) / len(durations),
                    "min": min(durations),
                    "max": max(durations),
                    "total": sum(durations),
                    "recent_average": self._get_recent_average(times, 10),
                }

        # Success rate metrics
        successes = self._success_counts[operation]
        failures = self._failure_counts[operation]
        total = successes + failures

        if total > 0:
            metrics["success_rate"] = {
                "successes": successes,
                "failures": failures,
                "total": total,
                "rate": successes / total,
            }

        return metrics

    def _get_recent_average(self, times: deque, count: int) -> float:
        """Get average of most recent N measurements."""
        if not times:
            return 0.0

        recent_times = list(times)[-count:]
        durations = [t["duration"] for t in recent_times]
        return sum(durations) / len(durations)

    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        self._operation_times.clear()
        self._success_counts.clear()
        self._failure_counts.clear()
        self._cache_hits.clear()
        self._cache_misses.clear()
        self._domain_counts.clear()
        self._strategy_counts.clear()
        self._fingerprint_counts = 0
        self._failure_analysis_counts = 0
        self._parallel_test_counts = 0

        # Reset closed-loop stats
        self._closed_loop_stats = {
            "iterations_total": 0,
            "intents_generated": 0,
            "strategies_augmented": 0,
            "pattern_matches": 0,
            "knowledge_updates": 0,
        }

        # Reset timeout stats
        self._timeout_stats = {
            "adaptive_timeouts_applied": 0,
            "content_inspection_adjustments": 0,
            "rst_injection_adjustments": 0,
            "network_timeout_adjustments": 0,
            "slow_cdn_adjustments": 0,
            "average_timeout_factor": 1.0,
        }

        self._last_reset = datetime.now()

        logger.info("All metrics have been reset")

    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format."""
        metrics = self.get_metrics_summary()

        if format.lower() == "json":
            import json

            return json.dumps(metrics, indent=2, default=str)
        elif format.lower() == "csv":
            return self._export_csv(metrics)
        elif format.lower() == "prometheus":
            return self._export_prometheus(metrics)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_csv(self, metrics: Dict[str, Any]) -> str:
        """Export metrics in CSV format."""
        lines = ["metric_type,metric_name,value,timestamp"]
        timestamp = datetime.now().isoformat()

        # Export operation statistics
        for operation, stats in metrics.get("operation_statistics", {}).items():
            for stat_name, value in stats.items():
                lines.append(f"operation,{operation}_{stat_name},{value},{timestamp}")

        # Export success rates
        for operation, stats in metrics.get("success_rates", {}).items():
            for stat_name, value in stats.items():
                lines.append(f"success_rate,{operation}_{stat_name},{value},{timestamp}")

        # Export cache statistics
        for cache_type, stats in metrics.get("cache_statistics", {}).items():
            for stat_name, value in stats.items():
                lines.append(f"cache,{cache_type}_{stat_name},{value},{timestamp}")

        return "\n".join(lines)

    def _export_prometheus(self, metrics: Dict[str, Any]) -> str:
        """Export metrics in Prometheus format."""
        lines = []

        # Export operation timing metrics
        for operation, stats in metrics.get("operation_statistics", {}).items():
            safe_operation = operation.replace("-", "_").replace(".", "_")
            lines.append(
                f"# HELP adaptive_engine_operation_duration_seconds Duration of {operation} operations"
            )
            lines.append(f"# TYPE adaptive_engine_operation_duration_seconds histogram")
            lines.append(
                f'adaptive_engine_operation_average_duration_seconds{{operation="{operation}"}} {stats.get("average_time", 0)}'
            )
            lines.append(
                f'adaptive_engine_operation_total_count{{operation="{operation}"}} {stats.get("count", 0)}'
            )

        # Export success rates
        for operation, stats in metrics.get("success_rates", {}).items():
            lines.append(
                f"# HELP adaptive_engine_operation_success_rate Success rate of {operation} operations"
            )
            lines.append(f"# TYPE adaptive_engine_operation_success_rate gauge")
            lines.append(
                f'adaptive_engine_operation_success_rate{{operation="{operation}"}} {stats.get("success_rate", 0)}'
            )

        # Export cache hit rates
        for cache_type, stats in metrics.get("cache_statistics", {}).items():
            lines.append(f"# HELP adaptive_engine_cache_hit_rate Cache hit rate for {cache_type}")
            lines.append(f"# TYPE adaptive_engine_cache_hit_rate gauge")
            lines.append(
                f'adaptive_engine_cache_hit_rate{{cache_type="{cache_type}"}} {stats.get("hit_rate", 0)}'
            )

        return "\n".join(lines)
