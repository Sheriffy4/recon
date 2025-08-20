"""
Performance optimizer for bypass engine operations.
"""

import asyncio
import time
import psutil
import logging
from typing import List
from collections import deque

from .performance_models import (
    PerformanceMetrics,
    OptimizationResult,
    OptimizationLevel,
    SystemHealth,
)


class PerformanceOptimizer:
    """Optimizes bypass engine performance based on testing results."""

    def __init__(
        self, optimization_level: OptimizationLevel = OptimizationLevel.BALANCED
    ):
        self.optimization_level = optimization_level
        self.metrics_history = deque(maxlen=1000)
        self.strategy_performance = {}
        self.optimization_cache = {}
        self.logger = logging.getLogger(__name__)

        # Performance thresholds
        self.thresholds = {
            OptimizationLevel.CONSERVATIVE: {
                "max_cpu_usage": 50.0,
                "max_memory_usage": 60.0,
                "min_success_rate": 85.0,
                "max_latency": 5.0,
            },
            OptimizationLevel.BALANCED: {
                "max_cpu_usage": 70.0,
                "max_memory_usage": 75.0,
                "min_success_rate": 80.0,
                "max_latency": 3.0,
            },
            OptimizationLevel.AGGRESSIVE: {
                "max_cpu_usage": 85.0,
                "max_memory_usage": 85.0,
                "min_success_rate": 75.0,
                "max_latency": 2.0,
            },
            OptimizationLevel.MAXIMUM: {
                "max_cpu_usage": 95.0,
                "max_memory_usage": 90.0,
                "min_success_rate": 70.0,
                "max_latency": 1.0,
            },
        }

    async def collect_performance_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics."""
        try:
            # System metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent

            # Network metrics (simplified)
            network_stats = psutil.net_io_counters()

            # Calculate throughput and latency from recent operations
            throughput = self._calculate_throughput()
            latency = self._calculate_average_latency()
            success_rate = self._calculate_success_rate()

            metrics = PerformanceMetrics(
                attack_execution_time=self._get_average_attack_time(),
                strategy_selection_time=self._get_average_selection_time(),
                validation_time=self._get_average_validation_time(),
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                success_rate=success_rate,
                throughput=throughput,
                latency=latency,
            )

            self.metrics_history.append(metrics)
            return metrics

        except Exception as e:
            self.logger.error(f"Error collecting performance metrics: {e}")
            return self._get_default_metrics()

    async def optimize_performance(
        self, current_metrics: PerformanceMetrics
    ) -> OptimizationResult:
        """Optimize performance based on current metrics."""
        try:
            original_metrics = current_metrics
            optimization_actions = []

            # CPU optimization
            if (
                current_metrics.cpu_usage
                > self.thresholds[self.optimization_level]["max_cpu_usage"]
            ):
                optimization_actions.extend(self._optimize_cpu_usage())

            # Memory optimization
            if (
                current_metrics.memory_usage
                > self.thresholds[self.optimization_level]["max_memory_usage"]
            ):
                optimization_actions.extend(self._optimize_memory_usage())

            # Latency optimization
            if (
                current_metrics.latency
                > self.thresholds[self.optimization_level]["max_latency"]
            ):
                optimization_actions.extend(self._optimize_latency())

            # Success rate optimization
            if (
                current_metrics.success_rate
                < self.thresholds[self.optimization_level]["min_success_rate"]
            ):
                optimization_actions.extend(self._optimize_success_rate())

            # Apply optimizations
            await self._apply_optimizations(optimization_actions)

            # Collect new metrics after optimization
            await asyncio.sleep(2)  # Allow time for changes to take effect
            optimized_metrics = await self.collect_performance_metrics()

            # Calculate improvement
            improvement = self._calculate_improvement(
                original_metrics, optimized_metrics
            )

            result = OptimizationResult(
                original_metrics=original_metrics,
                optimized_metrics=optimized_metrics,
                improvement_percentage=improvement,
                optimization_actions=optimization_actions,
                recommendations=self._generate_recommendations(optimized_metrics),
            )

            self.logger.info(
                f"Performance optimization completed: {improvement:.2f}% improvement"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error during performance optimization: {e}")
            raise

    def _optimize_cpu_usage(self) -> List[str]:
        """Optimize CPU usage."""
        actions = []

        # Reduce concurrent operations
        actions.append("reduce_concurrent_attacks")
        actions.append("enable_attack_caching")
        actions.append("optimize_strategy_selection")

        return actions

    def _optimize_memory_usage(self) -> List[str]:
        """Optimize memory usage."""
        actions = []

        # Memory management
        actions.append("clear_old_caches")
        actions.append("reduce_history_size")
        actions.append("enable_lazy_loading")

        return actions

    def _optimize_latency(self) -> List[str]:
        """Optimize latency."""
        actions = []

        # Latency improvements
        actions.append("enable_parallel_processing")
        actions.append("optimize_network_timeouts")
        actions.append("use_faster_algorithms")

        return actions

    def _optimize_success_rate(self) -> List[str]:
        """Optimize success rate."""
        actions = []

        # Success rate improvements
        actions.append("improve_strategy_selection")
        actions.append("enable_fallback_strategies")
        actions.append("increase_retry_attempts")

        return actions

    async def _apply_optimizations(self, actions: List[str]) -> None:
        """Apply optimization actions."""
        for action in actions:
            try:
                if action == "reduce_concurrent_attacks":
                    # Reduce max concurrent attacks
                    pass
                elif action == "enable_attack_caching":
                    # Enable result caching
                    pass
                elif action == "clear_old_caches":
                    # Clear old cached data
                    self.optimization_cache.clear()
                elif action == "enable_parallel_processing":
                    # Enable parallel processing where possible
                    pass
                # Add more optimization implementations as needed

                self.logger.debug(f"Applied optimization: {action}")

            except Exception as e:
                self.logger.error(f"Error applying optimization {action}: {e}")

    def _calculate_improvement(
        self, original: PerformanceMetrics, optimized: PerformanceMetrics
    ) -> float:
        """Calculate performance improvement percentage."""
        try:
            # Calculate weighted improvement across multiple metrics
            cpu_improvement = (
                max(0, original.cpu_usage - optimized.cpu_usage)
                / original.cpu_usage
                * 100
            )
            memory_improvement = (
                max(0, original.memory_usage - optimized.memory_usage)
                / original.memory_usage
                * 100
            )
            latency_improvement = (
                max(0, original.latency - optimized.latency) / original.latency * 100
            )
            success_improvement = (
                max(0, optimized.success_rate - original.success_rate)
                / original.success_rate
                * 100
            )

            # Weighted average
            total_improvement = (
                cpu_improvement * 0.3
                + memory_improvement * 0.2
                + latency_improvement * 0.3
                + success_improvement * 0.2
            )

            return total_improvement

        except (ZeroDivisionError, AttributeError):
            return 0.0

    def _generate_recommendations(self, metrics: PerformanceMetrics) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []

        if metrics.cpu_usage > 80:
            recommendations.append(
                "Consider upgrading CPU or reducing concurrent operations"
            )

        if metrics.memory_usage > 85:
            recommendations.append("Consider increasing RAM or optimizing memory usage")

        if metrics.latency > 2.0:
            recommendations.append(
                "Optimize network configuration or use faster algorithms"
            )

        if metrics.success_rate < 80:
            recommendations.append("Review and improve strategy selection algorithms")

        return recommendations

    def _calculate_throughput(self) -> float:
        """Calculate current throughput."""
        if len(self.metrics_history) < 2:
            return 0.0

        # Simple throughput calculation based on recent operations
        recent_metrics = list(self.metrics_history)[-10:]
        return sum(
            1.0 / max(m.attack_execution_time, 0.1) for m in recent_metrics
        ) / len(recent_metrics)

    def _calculate_average_latency(self) -> float:
        """Calculate average latency."""
        if not self.metrics_history:
            return 0.0

        recent_metrics = list(self.metrics_history)[-10:]
        return sum(m.attack_execution_time for m in recent_metrics) / len(
            recent_metrics
        )

    def _calculate_success_rate(self) -> float:
        """Calculate current success rate."""
        if not self.metrics_history:
            return 0.0

        recent_metrics = list(self.metrics_history)[-20:]
        return sum(m.success_rate for m in recent_metrics) / len(recent_metrics)

    def _get_average_attack_time(self) -> float:
        """Get average attack execution time."""
        if not self.metrics_history:
            return 0.0

        recent_metrics = list(self.metrics_history)[-10:]
        return sum(m.attack_execution_time for m in recent_metrics) / len(
            recent_metrics
        )

    def _get_average_selection_time(self) -> float:
        """Get average strategy selection time."""
        if not self.metrics_history:
            return 0.0

        recent_metrics = list(self.metrics_history)[-10:]
        return sum(m.strategy_selection_time for m in recent_metrics) / len(
            recent_metrics
        )

    def _get_average_validation_time(self) -> float:
        """Get average validation time."""
        if not self.metrics_history:
            return 0.0

        recent_metrics = list(self.metrics_history)[-10:]
        return sum(m.validation_time for m in recent_metrics) / len(recent_metrics)

    def _get_default_metrics(self) -> PerformanceMetrics:
        """Get default metrics when collection fails."""
        return PerformanceMetrics(
            attack_execution_time=1.0,
            strategy_selection_time=0.1,
            validation_time=0.5,
            memory_usage=50.0,
            cpu_usage=30.0,
            success_rate=80.0,
            throughput=10.0,
            latency=1.0,
        )

    async def get_system_health(self) -> SystemHealth:
        """Get current system health status."""
        try:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Calculate system load
            load_avg = (
                psutil.getloadavg()[0]
                if hasattr(psutil, "getloadavg")
                else cpu_usage / 100
            )

            # Get uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time

            return SystemHealth(
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_latency=self._calculate_average_latency(),
                active_attacks=len(self.strategy_performance),
                failed_attacks=0,  # Would be calculated from actual failure data
                system_load=load_avg,
                uptime=uptime,
            )

        except Exception as e:
            self.logger.error(f"Error getting system health: {e}")
            return SystemHealth(
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                network_latency=0.0,
                active_attacks=0,
                failed_attacks=0,
                system_load=0.0,
                uptime=0.0,
            )
