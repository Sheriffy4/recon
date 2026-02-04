"""
Integrated telemetry system for attack execution.

Provides a unified interface for all telemetry components including
execution logging, error logging, metrics collection, performance
monitoring, and metrics export.
"""

import logging
import time
from typing import Any, Dict, Optional
from contextlib import contextmanager

from .execution_logger import AttackExecutionLogger, ExecutionStatus, LogLevel
from .error_logger import AttackErrorLogger
from .metrics_collector import AttackMetricsCollector
from .performance_monitor import PerformanceMonitor
from .metrics_exporter import PrometheusExporter, JSONExporter


class AttackTelemetrySystem:
    """
    Integrated telemetry system for attack execution.

    Provides a single interface for:
    - Execution logging
    - Error logging
    - Metrics collection
    - Performance monitoring
    - Metrics export

    Usage:
        telemetry = AttackTelemetrySystem()

        with telemetry.track_execution("my_attack", params, payload_size):
            # Execute attack
            result = execute_attack()
    """

    def __init__(
        self,
        log_level: LogLevel = LogLevel.INFO,
        structured_logging: bool = True,
        enable_performance_monitoring: bool = True,
        throughput_window_seconds: int = 60,
    ):
        """
        Initialize telemetry system.

        Args:
            log_level: Minimum log level for execution logging
            structured_logging: Use structured JSON logging
            enable_performance_monitoring: Enable performance degradation detection
            throughput_window_seconds: Window for throughput calculation
        """
        self.logger = logging.getLogger("telemetry_system")

        # Initialize components
        self.execution_logger = AttackExecutionLogger(
            log_level=log_level, structured_format=structured_logging
        )

        self.error_logger = AttackErrorLogger(structured_format=structured_logging)

        self.metrics_collector = AttackMetricsCollector(
            throughput_window_seconds=throughput_window_seconds
        )

        self.performance_monitor = None
        if enable_performance_monitoring:
            self.performance_monitor = PerformanceMonitor()

        # Exporters
        self._exporters = {"prometheus": PrometheusExporter(), "json": JSONExporter(pretty=True)}

        self.logger.info("✅ Telemetry system initialized")

    @contextmanager
    def track_execution(
        self,
        attack_name: str,
        attack_type: str,
        parameters: Dict[str, Any],
        payload_size: int,
        connection_id: Optional[str] = None,
    ):
        """
        Context manager for tracking attack execution.

        Automatically logs execution start/end, collects metrics,
        and monitors performance.

        Args:
            attack_name: Name of the attack
            attack_type: Type/category of attack
            parameters: Attack parameters
            payload_size: Size of payload in bytes
            connection_id: Optional connection identifier

        Yields:
            ExecutionContext with result tracking

        Example:
            with telemetry.track_execution("fake", "tcp", params, 1024) as ctx:
                result = execute_attack()
                ctx.set_result(result)
        """
        # Log execution start
        self.execution_logger.log_execution_start(
            attack_type=attack_type,
            attack_name=attack_name,
            parameters=parameters,
            payload_size=payload_size,
            connection_id=connection_id,
        )

        # Track timing
        start_time = time.time()

        # Create execution context
        ctx = ExecutionContext()

        try:
            yield ctx

            # Calculate execution time
            execution_time_ms = (time.time() - start_time) * 1000

            # Determine status
            if ctx.exception:
                status = ExecutionStatus.ERROR
                success = False
                is_error = True
            elif ctx.success:
                status = ExecutionStatus.SUCCESS
                success = True
                is_error = False
            else:
                status = ExecutionStatus.FAILURE
                success = False
                is_error = False

            # Log execution complete
            self.execution_logger.log_execution_complete(
                attack_type=attack_type,
                attack_name=attack_name,
                parameters=parameters,
                execution_time_ms=execution_time_ms,
                status=status,
                segments_generated=ctx.segments_generated,
                payload_size=payload_size,
                connection_id=connection_id,
                error_message=str(ctx.exception) if ctx.exception else None,
                metadata=ctx.metadata,
            )

            # Record metrics
            self.metrics_collector.record_execution(
                attack_name=attack_name,
                success=success,
                execution_time_ms=execution_time_ms,
                segments_generated=ctx.segments_generated,
                payload_size=payload_size,
                is_fallback=ctx.is_fallback,
                is_error=is_error,
            )

            # Monitor performance
            if self.performance_monitor:
                # Calculate throughput
                throughput_pps = (
                    ctx.segments_generated / (execution_time_ms / 1000)
                    if execution_time_ms > 0
                    else 0
                )

                self.performance_monitor.record_execution(
                    attack_name=attack_name,
                    execution_time_ms=execution_time_ms,
                    success=success,
                    throughput_pps=throughput_pps,
                    is_error=is_error,
                )

            # Log error if present
            if ctx.exception:
                self.error_logger.log_error(
                    attack_type=attack_type,
                    attack_name=attack_name,
                    exception=ctx.exception,
                    parameters=parameters,
                    connection_id=connection_id,
                    context=ctx.metadata,
                )

        except Exception as e:
            # Handle unexpected exceptions
            execution_time_ms = (time.time() - start_time) * 1000

            self.execution_logger.log_execution_complete(
                attack_type=attack_type,
                attack_name=attack_name,
                parameters=parameters,
                execution_time_ms=execution_time_ms,
                status=ExecutionStatus.ERROR,
                segments_generated=0,
                payload_size=payload_size,
                connection_id=connection_id,
                error_message=str(e),
            )

            self.error_logger.log_error(
                attack_type=attack_type,
                attack_name=attack_name,
                exception=e,
                parameters=parameters,
                connection_id=connection_id,
            )

            raise

    def export_metrics(self, format: str = "json") -> str:
        """
        Export metrics in specified format.

        Args:
            format: Export format ('prometheus' or 'json')

        Returns:
            Formatted metrics string

        Raises:
            ValueError: If format is not supported
        """
        if format not in self._exporters:
            raise ValueError(
                f"Unsupported format '{format}'. "
                f"Supported formats: {list(self._exporters.keys())}"
            )

        exporter = self._exporters[format]
        snapshot = self.metrics_collector.get_snapshot()

        return exporter.export(snapshot)

    def get_metrics_snapshot(self):
        """
        Get current metrics snapshot.

        Returns:
            MetricsSnapshot with current metrics
        """
        return self.metrics_collector.get_snapshot()

    def get_execution_summary(self) -> Dict[str, Any]:
        """
        Get summary of execution statistics.

        Returns:
            Dictionary with execution summary
        """
        return self.execution_logger.get_summary_stats()

    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get summary of error statistics.

        Returns:
            Dictionary with error summary
        """
        return self.error_logger.get_error_summary()

    def get_performance_baselines(self) -> Dict[str, Any]:
        """
        Get performance baselines for all attacks.

        Returns:
            Dictionary of performance baselines
        """
        if not self.performance_monitor:
            return {}

        baselines = self.performance_monitor.get_all_baselines()
        return {
            name: {
                "avg_execution_time_ms": baseline.avg_execution_time_ms,
                "avg_success_rate": baseline.avg_success_rate,
                "avg_throughput_pps": baseline.avg_throughput_pps,
                "sample_count": baseline.sample_count,
                "last_updated": baseline.last_updated.isoformat(),
            }
            for name, baseline in baselines.items()
        }

    def get_recent_degradations(self, limit: int = 10):
        """
        Get recent performance degradations.

        Args:
            limit: Maximum number of degradations to return

        Returns:
            List of degradation information
        """
        if not self.performance_monitor:
            return []

        degradations = self.performance_monitor.get_recent_degradations(limit=limit)

        return [
            {
                "timestamp": d.timestamp.isoformat(),
                "attack_name": d.attack_name,
                "type": d.degradation_type.value,
                "severity": d.severity.value,
                "current_value": d.current_value,
                "baseline_value": d.baseline_value,
                "degradation_percentage": d.degradation_percentage,
                "diagnostic_info": d.diagnostic_info,
            }
            for d in degradations
        ]

    def reset_all(self):
        """Reset all telemetry data."""
        self.execution_logger.clear_history()
        self.error_logger.clear_history()
        self.metrics_collector.reset_metrics()

        if self.performance_monitor:
            self.performance_monitor.reset_baseline()
            self.performance_monitor.clear_degradations()

        self.logger.info("🔄 All telemetry data reset")


class ExecutionContext:
    """
    Context for tracking execution within track_execution context manager.

    Allows setting result information during execution.
    """

    def __init__(self):
        """Initialize execution context."""
        self.success = False
        self.segments_generated = 0
        self.is_fallback = False
        self.exception: Optional[Exception] = None
        self.metadata: Dict[str, Any] = {}

    def set_success(self, segments_generated: int = 0, is_fallback: bool = False):
        """
        Mark execution as successful.

        Args:
            segments_generated: Number of segments generated
            is_fallback: Whether this was a fallback execution
        """
        self.success = True
        self.segments_generated = segments_generated
        self.is_fallback = is_fallback

    def set_failure(self, exception: Optional[Exception] = None):
        """
        Mark execution as failed.

        Args:
            exception: Optional exception that caused failure
        """
        self.success = False
        self.exception = exception

    def add_metadata(self, key: str, value: Any):
        """
        Add metadata to execution context.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value


# Global telemetry instance
_global_telemetry: Optional[AttackTelemetrySystem] = None


def get_telemetry_system() -> AttackTelemetrySystem:
    """
    Get global telemetry system instance.

    Returns:
        Global telemetry system
    """
    global _global_telemetry

    if _global_telemetry is None:
        _global_telemetry = AttackTelemetrySystem()

    return _global_telemetry


def initialize_telemetry(
    log_level: LogLevel = LogLevel.INFO,
    structured_logging: bool = True,
    enable_performance_monitoring: bool = True,
) -> AttackTelemetrySystem:
    """
    Initialize global telemetry system.

    Args:
        log_level: Minimum log level
        structured_logging: Use structured logging
        enable_performance_monitoring: Enable performance monitoring

    Returns:
        Initialized telemetry system
    """
    global _global_telemetry

    _global_telemetry = AttackTelemetrySystem(
        log_level=log_level,
        structured_logging=structured_logging,
        enable_performance_monitoring=enable_performance_monitoring,
    )

    return _global_telemetry
