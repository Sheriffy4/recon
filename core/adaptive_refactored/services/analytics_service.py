"""
Analytics Service implementation for the refactored Adaptive Engine.

This service manages metrics collection, performance monitoring, and analytics.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from ..interfaces import IAnalyticsService, IMetricsCollector, IPerformanceMonitor
from ..models import Strategy, TestResult, PerformanceMetrics
from ..config import AnalyticsConfig


logger = logging.getLogger(__name__)


class AnalyticsService(IAnalyticsService):
    """
    Implementation of analytics service operations.

    Coordinates metrics collection and performance monitoring
    to provide comprehensive analytics capabilities.
    """

    def __init__(
        self,
        metrics_collector: IMetricsCollector,
        performance_monitor: IPerformanceMonitor,
        config: AnalyticsConfig,
    ):
        self.metrics_collector = metrics_collector
        self.performance_monitor = performance_monitor
        self.config = config

        logger.info("Analytics service initialized")

    def record_strategy_test(self, domain: str, strategy: Strategy, result: TestResult) -> None:
        """Record the result of a strategy test."""
        try:
            if not self.config.enable_metrics:
                return

            # Use the metrics collector's record_strategy_test method
            self.metrics_collector.record_strategy_test(
                domain=domain,
                strategy_name=strategy.name,
                success=result.success,
                duration=result.execution_time,
            )

            logger.debug(f"Recorded test metrics for {domain} with {strategy.name}")

        except Exception as e:
            logger.error(f"Failed to record strategy test metrics: {e}")

    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        try:
            # Delegate to the metrics collector
            return self.metrics_collector.get_performance_metrics()

        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return PerformanceMetrics()

    def _count_unique_domains(self, operation_stats: Dict[str, Any]) -> int:
        """Count unique domains from operation statistics."""
        domains = set()
        for operation in operation_stats.keys():
            if operation.startswith("domain_test_"):
                domain = operation.replace("domain_test_", "")
                domains.add(domain)
        return len(domains)

    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format."""
        try:
            if not self.config.enable_metrics:
                return '{"error": "Metrics collection is disabled"}'

            # Get comprehensive metrics
            metrics_data = {
                "performance_metrics": self.get_performance_metrics().to_dict(),
                "detailed_metrics": self.metrics_collector.get_metrics_summary(),
                "system_performance": self.performance_monitor.get_system_performance(),
                "export_timestamp": self.get_performance_metrics().last_updated,
            }

            if format.lower() == "json":
                import json

                return json.dumps(metrics_data, indent=2, default=str)
            elif format.lower() == "csv":
                return self._export_csv(metrics_data)
            elif format.lower() == "prometheus":
                return self._export_prometheus(metrics_data)
            else:
                raise ValueError(f"Unsupported export format: {format}")

        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
            return f'{{"error": "{str(e)}"}}'

    def _export_csv(self, metrics_data: Dict[str, Any]) -> str:
        """Export metrics in CSV format."""
        lines = ["metric_category,metric_name,value,timestamp"]

        perf_metrics = metrics_data.get("performance_metrics", {})
        timestamp = perf_metrics.get("last_updated", "")

        for key, value in perf_metrics.items():
            if key != "last_updated":
                lines.append(f"performance,{key},{value},{timestamp}")

        return "\n".join(lines)

    def _export_prometheus(self, metrics_data: Dict[str, Any]) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        perf_metrics = metrics_data.get("performance_metrics", {})

        # Export key performance metrics
        metrics_mapping = {
            "cache_hit_rate": "adaptive_engine_cache_hit_rate",
            "average_test_time": "adaptive_engine_average_test_duration_seconds",
            "success_rate": "adaptive_engine_success_rate",
            "memory_usage_mb": "adaptive_engine_memory_usage_mb",
            "cpu_usage_percent": "adaptive_engine_cpu_usage_percent",
            "total_tests_executed": "adaptive_engine_tests_total",
        }

        for metric_key, prometheus_name in metrics_mapping.items():
            value = perf_metrics.get(metric_key, 0)
            lines.append(f'# HELP {prometheus_name} {metric_key.replace("_", " ").title()}')
            lines.append(f"# TYPE {prometheus_name} gauge")
            lines.append(f"{prometheus_name} {value}")

        return "\n".join(lines)

    def reset_metrics(self) -> None:
        """Reset all collected metrics."""
        try:
            self.metrics_collector.reset_metrics()
            logger.info("All analytics metrics have been reset")

        except Exception as e:
            logger.error(f"Failed to reset metrics: {e}")

    def get_domain_analytics(self, domain: str) -> Dict[str, Any]:
        """Get analytics for a specific domain."""
        try:
            metrics_summary = self.metrics_collector.get_metrics_summary()

            # Extract domain-specific data
            domain_operation = f"domain_test_{domain}"
            success_rates = metrics_summary.get("success_rates", {})
            operation_stats = metrics_summary.get("operation_statistics", {})

            domain_success = success_rates.get(domain_operation, {})
            domain_timing = operation_stats.get(domain_operation, {})

            return {
                "domain": domain,
                "test_count": domain_success.get("total_count", 0),
                "success_count": domain_success.get("success_count", 0),
                "failure_count": domain_success.get("failure_count", 0),
                "success_rate": domain_success.get("success_rate", 0.0),
                "average_test_time": domain_timing.get("average_time", 0.0),
                "min_test_time": domain_timing.get("min_time", 0.0),
                "max_test_time": domain_timing.get("max_time", 0.0),
            }

        except Exception as e:
            logger.error(f"Failed to get domain analytics for {domain}: {e}")
            return {"domain": domain, "error": str(e)}

    def get_strategy_analytics(self, strategy_name: str) -> Dict[str, Any]:
        """Get analytics for a specific strategy."""
        try:
            metrics_summary = self.metrics_collector.get_metrics_summary()

            # Extract strategy-specific data
            strategy_operation = f"strategy_{strategy_name}"
            success_rates = metrics_summary.get("success_rates", {})
            operation_stats = metrics_summary.get("operation_statistics", {})

            strategy_success = success_rates.get(strategy_operation, {})
            strategy_timing = operation_stats.get(strategy_operation, {})

            return {
                "strategy_name": strategy_name,
                "test_count": strategy_success.get("total_count", 0),
                "success_count": strategy_success.get("success_count", 0),
                "failure_count": strategy_success.get("failure_count", 0),
                "success_rate": strategy_success.get("success_rate", 0.0),
                "average_test_time": strategy_timing.get("average_time", 0.0),
                "min_test_time": strategy_timing.get("min_time", 0.0),
                "max_test_time": strategy_timing.get("max_time", 0.0),
            }

        except Exception as e:
            logger.error(f"Failed to get strategy analytics for {strategy_name}: {e}")
            return {"strategy_name": strategy_name, "error": str(e)}

    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        try:
            performance_metrics = self.get_performance_metrics()
            system_performance = self.performance_monitor.get_system_performance()
            metrics_summary = self.metrics_collector.get_metrics_summary()

            # Generate alerts if enabled
            alerts = []
            if self.config.enable_performance_alerts:
                alerts = self.performance_monitor.get_performance_alerts()

            return {
                "report_timestamp": performance_metrics.last_updated,
                "performance_summary": {
                    "overall_success_rate": performance_metrics.success_rate,
                    "average_test_time": performance_metrics.average_test_time,
                    "cache_hit_rate": performance_metrics.cache_hit_rate,
                    "total_tests": performance_metrics.total_tests_executed,
                    "uptime_hours": performance_metrics.uptime_seconds / 3600,
                },
                "resource_usage": {
                    "memory_mb": performance_metrics.memory_usage_mb,
                    "cpu_percent": performance_metrics.cpu_usage_percent,
                    "system_memory_percent": system_performance.get("memory", {}).get("percent", 0),
                    "system_cpu_percent": system_performance.get("cpu", {}).get("percent_total", 0),
                },
                "operational_metrics": {
                    "domains_processed": performance_metrics.total_domains_processed,
                    "strategies_found": performance_metrics.total_strategies_found,
                    "strategy_generation_time": performance_metrics.strategy_generation_time,
                    "fingerprint_creation_time": performance_metrics.fingerprint_creation_time,
                },
                "alerts": alerts,
                "recommendations": self._generate_performance_recommendations(
                    performance_metrics, system_performance
                ),
            }

        except Exception as e:
            logger.error(f"Failed to generate performance report: {e}")
            return {"error": str(e)}

    def _generate_performance_recommendations(
        self, perf_metrics: PerformanceMetrics, sys_perf: Dict[str, Any]
    ) -> List[str]:
        """Generate performance recommendations based on metrics."""
        recommendations = []

        # Memory recommendations
        if perf_metrics.memory_usage_mb > 1024:  # > 1GB
            recommendations.append("Consider reducing cache sizes to lower memory usage")

        # CPU recommendations
        if perf_metrics.cpu_usage_percent > 80:
            recommendations.append("High CPU usage detected - consider reducing parallel workers")

        # Success rate recommendations
        if perf_metrics.success_rate < 0.5:
            recommendations.append("Low success rate - review strategy generation algorithms")

        # Test time recommendations
        if perf_metrics.average_test_time > 30:
            recommendations.append("High average test time - consider optimizing test execution")

        # Cache recommendations
        if perf_metrics.cache_hit_rate < 0.3:
            recommendations.append("Low cache hit rate - review caching strategy and TTL settings")

        return recommendations

    def get_closed_loop_analytics(self) -> Dict[str, Any]:
        """Get closed-loop learning analytics."""
        try:
            closed_loop_stats = self.metrics_collector.get_closed_loop_stats()

            if not closed_loop_stats.get("metrics_enabled", True):
                return {"error": "Metrics collection is disabled"}

            # Calculate efficiency metrics
            total_iterations = closed_loop_stats.get("iterations_total", 0)
            intents_generated = closed_loop_stats.get("intents_generated", 0)
            strategies_augmented = closed_loop_stats.get("strategies_augmented", 0)

            efficiency_metrics = {
                "intents_per_iteration": (
                    intents_generated / total_iterations if total_iterations > 0 else 0
                ),
                "augmentation_rate": (
                    strategies_augmented / intents_generated if intents_generated > 0 else 0
                ),
                "pattern_match_rate": (
                    closed_loop_stats.get("pattern_matches", 0) / total_iterations
                    if total_iterations > 0
                    else 0
                ),
            }

            return {
                "closed_loop_statistics": closed_loop_stats,
                "efficiency_metrics": efficiency_metrics,
                "recommendations": self._generate_closed_loop_recommendations(
                    closed_loop_stats, efficiency_metrics
                ),
            }

        except Exception as e:
            logger.error(f"Failed to get closed-loop analytics: {e}")
            return {"error": str(e)}

    def get_timeout_analytics(self) -> Dict[str, Any]:
        """Get adaptive timeout analytics."""
        try:
            timeout_stats = self.metrics_collector.get_timeout_stats()

            if not timeout_stats.get("metrics_enabled", True):
                return {"error": "Metrics collection is disabled"}

            # Calculate timeout efficiency
            total_adjustments = timeout_stats.get("adaptive_timeouts_applied", 0)
            avg_factor = timeout_stats.get("average_timeout_factor", 1.0)

            # Breakdown by adjustment type
            adjustment_breakdown = {
                "content_inspection": timeout_stats.get("content_inspection_adjustments", 0),
                "rst_injection": timeout_stats.get("rst_injection_adjustments", 0),
                "network_timeout": timeout_stats.get("network_timeout_adjustments", 0),
                "slow_cdn": timeout_stats.get("slow_cdn_adjustments", 0),
            }

            # Calculate percentages
            adjustment_percentages = {}
            if total_adjustments > 0:
                for adj_type, count in adjustment_breakdown.items():
                    adjustment_percentages[adj_type] = (count / total_adjustments) * 100

            return {
                "timeout_statistics": timeout_stats,
                "adjustment_breakdown": adjustment_breakdown,
                "adjustment_percentages": adjustment_percentages,
                "efficiency_metrics": {
                    "average_timeout_factor": avg_factor,
                    "total_adjustments": total_adjustments,
                    "most_common_adjustment": (
                        max(adjustment_breakdown.items(), key=lambda x: x[1])[0]
                        if adjustment_breakdown
                        else None
                    ),
                },
                "recommendations": self._generate_timeout_recommendations(
                    timeout_stats, adjustment_breakdown
                ),
            }

        except Exception as e:
            logger.error(f"Failed to get timeout analytics: {e}")
            return {"error": str(e)}

    def _generate_closed_loop_recommendations(
        self, stats: Dict[str, Any], efficiency: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for closed-loop learning."""
        recommendations = []

        # Check iteration efficiency
        if efficiency.get("intents_per_iteration", 0) < 1.0:
            recommendations.append(
                "Low intent generation rate - consider improving pattern recognition"
            )

        # Check augmentation rate
        if efficiency.get("augmentation_rate", 0) < 0.5:
            recommendations.append(
                "Low strategy augmentation rate - review intent-to-strategy conversion logic"
            )

        # Check pattern matching
        if efficiency.get("pattern_match_rate", 0) < 0.3:
            recommendations.append("Low pattern match rate - consider expanding pattern database")

        # Check knowledge updates
        knowledge_updates = stats.get("knowledge_updates", 0)
        total_iterations = stats.get("iterations_total", 0)
        if total_iterations > 0 and (knowledge_updates / total_iterations) < 0.1:
            recommendations.append("Low knowledge update rate - review learning mechanisms")

        return recommendations

    def _generate_timeout_recommendations(
        self, stats: Dict[str, Any], breakdown: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations for timeout adjustments."""
        recommendations = []

        # Check if too many adjustments are being made
        total_adjustments = stats.get("adaptive_timeouts_applied", 0)
        if total_adjustments > 100:  # Arbitrary threshold
            recommendations.append(
                "High number of timeout adjustments - consider reviewing base timeout values"
            )

        # Check average timeout factor
        avg_factor = stats.get("average_timeout_factor", 1.0)
        if avg_factor > 2.0:
            recommendations.append(
                "High average timeout factor - network conditions may be consistently poor"
            )
        elif avg_factor < 1.1:
            recommendations.append(
                "Low average timeout factor - base timeouts may be too conservative"
            )

        # Check most common adjustment type
        if breakdown:
            most_common = max(breakdown.items(), key=lambda x: x[1])
            if most_common[1] > total_adjustments * 0.5:  # More than 50% of one type
                if most_common[0] == "content_inspection":
                    recommendations.append(
                        "Frequent content inspection timeouts - consider optimizing DPI detection"
                    )
                elif most_common[0] == "slow_cdn":
                    recommendations.append(
                        "Frequent slow CDN timeouts - consider CDN-specific optimizations"
                    )
                elif most_common[0] == "network_timeout":
                    recommendations.append(
                        "Frequent network timeouts - review network connectivity"
                    )

        return recommendations

    def get_comprehensive_analytics(self) -> Dict[str, Any]:
        """Get comprehensive analytics combining all metrics."""
        try:
            return {
                "performance_metrics": self.get_performance_metrics().to_dict(),
                "closed_loop_analytics": self.get_closed_loop_analytics(),
                "timeout_analytics": self.get_timeout_analytics(),
                "detailed_metrics": self.metrics_collector.get_metrics_summary(),
                "system_performance": self.performance_monitor.get_system_performance(),
                "performance_report": self.generate_performance_report(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get comprehensive analytics: {e}")
            return {"error": str(e)}

    def export_analytics_data(self) -> Dict[str, Any]:
        """Export analytics data in a structured format."""
        try:
            if not self.config.enable_metrics:
                return {"error": "Metrics collection is disabled"}

            # Get comprehensive analytics data
            performance_metrics = self.get_performance_metrics()
            detailed_metrics = self.metrics_collector.get_metrics_summary()
            system_performance = self.performance_monitor.get_system_performance()

            # Extract operation statistics for the expected format
            operation_stats = detailed_metrics.get("operation_statistics", {})

            return {
                "performance_metrics": performance_metrics.to_dict(),
                "operation_stats": operation_stats,
                "system_performance": system_performance,
                "detailed_metrics": detailed_metrics,
                "export_timestamp": performance_metrics.last_updated,
                "analytics_config": {
                    "metrics_enabled": self.config.enable_metrics,
                    "profiling_enabled": self.config.enable_profiling,
                    "performance_alerts_enabled": getattr(
                        self.config, "enable_performance_alerts", False
                    ),
                },
            }

        except Exception as e:
            logger.error(f"Failed to export analytics data: {e}")
            return {"error": str(e)}

    def reset_analytics(self) -> None:
        """Reset all analytics data and metrics."""
        try:
            # Delegate to the underlying metrics collector
            self.metrics_collector.reset_metrics()
            logger.info("All analytics data has been reset")

        except Exception as e:
            logger.error(f"Failed to reset analytics: {e}")

    def start_performance_monitoring(self, operation_name: str) -> str:
        """Start performance monitoring for an operation."""
        try:
            return self.performance_monitor.start_operation(operation_name)

        except Exception as e:
            logger.error(f"Failed to start performance monitoring for {operation_name}: {e}")
            return ""

    def end_performance_monitoring(self, operation_id: str) -> float:
        """End performance monitoring for an operation and return duration."""
        try:
            return self.performance_monitor.end_operation(operation_id)

        except Exception as e:
            logger.error(f"Failed to end performance monitoring for {operation_id}: {e}")
            return 0.0
