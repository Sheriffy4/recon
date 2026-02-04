#!/usr/bin/env python3
"""
Monitoring and Diagnostics System for Advanced DPI Fingerprinting - Task 18 Implementation
Provides detailed logging, metrics collection, health checks, and diagnostic tools.
"""

import logging
import time
import json
import threading
import psutil
import os
import sys
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque
import statistics

try:
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.fingerprint.config import get_config
except ImportError:
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    from core.fingerprint.config import get_config


# Configure structured logging
class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields if present
        if hasattr(record, "fingerprint_target"):
            log_entry["fingerprint_target"] = record.fingerprint_target
        if hasattr(record, "dpi_type"):
            log_entry["dpi_type"] = record.dpi_type
        if hasattr(record, "confidence"):
            log_entry["confidence"] = record.confidence
        if hasattr(record, "duration"):
            log_entry["duration"] = record.duration
        if hasattr(record, "error_type"):
            log_entry["error_type"] = record.error_type

        return json.dumps(log_entry)


@dataclass
class PerformanceMetric:
    """Performance metric data structure."""

    name: str
    value: float
    unit: str
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class HealthCheckResult:
    """Health check result data structure."""

    component: str
    status: str  # 'healthy', 'warning', 'critical'
    message: str
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticReport:
    """Comprehensive diagnostic report."""

    timestamp: float = field(default_factory=time.time)
    system_info: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: List[PerformanceMetric] = field(default_factory=list)
    health_checks: List[HealthCheckResult] = field(default_factory=list)
    recent_errors: List[Dict[str, Any]] = field(default_factory=list)
    fingerprinting_stats: Dict[str, Any] = field(default_factory=dict)


class MetricsCollector:
    """Collects and aggregates performance metrics."""

    def __init__(self, max_history: int = 1000):
        """Initialize metrics collector."""
        self.max_history = max_history
        self.metrics = defaultdict(lambda: deque(maxlen=max_history))
        self.lock = threading.Lock()

    def record_metric(self, name: str, value: float, unit: str = "", tags: Dict[str, str] = None):
        """Record a performance metric."""
        metric = PerformanceMetric(name=name, value=value, unit=unit, tags=tags or {})

        with self.lock:
            self.metrics[name].append(metric)

    def get_metric_stats(self, name: str, time_window: Optional[float] = None) -> Dict[str, float]:
        """Get statistics for a metric within time window."""
        with self.lock:
            if name not in self.metrics:
                return {}

            metrics = list(self.metrics[name])

            # Filter by time window if specified
            if time_window:
                cutoff_time = time.time() - time_window
                metrics = [m for m in metrics if m.timestamp >= cutoff_time]

            if not metrics:
                return {}

            values = [m.value for m in metrics]

            return {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": statistics.mean(values),
                "median": statistics.median(values),
                "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
                "latest": values[-1],
                "time_span": metrics[-1].timestamp - metrics[0].timestamp,
            }

    def get_all_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all metrics."""
        with self.lock:
            return {name: self.get_metric_stats(name) for name in self.metrics.keys()}


class HealthChecker:
    """Performs health checks on system components."""

    def __init__(self):
        """Initialize health checker."""
        self.checks = {}
        self.register_default_checks()

    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]):
        """Register a health check function."""
        self.checks[name] = check_func

    def register_default_checks(self):
        """Register default health checks."""
        self.register_check("system_resources", self._check_system_resources)
        self.register_check("disk_space", self._check_disk_space)
        self.register_check("memory_usage", self._check_memory_usage)
        self.register_check("cache_system", self._check_cache_system)
        self.register_check("ml_model", self._check_ml_model)

    def run_check(self, name: str) -> HealthCheckResult:
        """Run a specific health check."""
        if name not in self.checks:
            return HealthCheckResult(
                component=name,
                status="critical",
                message=f"Health check '{name}' not found",
            )

        try:
            return self.checks[name]()
        except Exception as e:
            return HealthCheckResult(
                component=name,
                status="critical",
                message=f"Health check failed: {str(e)}",
            )

    def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all registered health checks."""
        results = []
        for name in self.checks.keys():
            results.append(self.run_check(name))
        return results

    def _check_system_resources(self) -> HealthCheckResult:
        """Check system resource usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            status = "healthy"
            message = "System resources normal"

            if cpu_percent > 90:
                status = "critical"
                message = f"High CPU usage: {cpu_percent}%"
            elif cpu_percent > 70:
                status = "warning"
                message = f"Elevated CPU usage: {cpu_percent}%"

            if memory.percent > 90:
                status = "critical"
                message = f"High memory usage: {memory.percent}%"
            elif memory.percent > 70 and status == "healthy":
                status = "warning"
                message = f"Elevated memory usage: {memory.percent}%"

            return HealthCheckResult(
                component="system_resources",
                status=status,
                message=message,
                details={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_available": memory.available,
                    "memory_total": memory.total,
                },
            )
        except Exception as e:
            return HealthCheckResult(
                component="system_resources",
                status="critical",
                message=f"Failed to check system resources: {str(e)}",
            )

    def _check_disk_space(self) -> HealthCheckResult:
        """Check disk space availability."""
        try:
            config = get_config()
            cache_dir = Path(config.cache.cache_dir)

            # Get disk usage for cache directory
            if cache_dir.exists():
                disk_usage = psutil.disk_usage(str(cache_dir))
                free_percent = (disk_usage.free / disk_usage.total) * 100

                status = "healthy"
                message = f"Disk space sufficient: {free_percent:.1f}% free"

                if free_percent < 5:
                    status = "critical"
                    message = f"Critical disk space: {free_percent:.1f}% free"
                elif free_percent < 15:
                    status = "warning"
                    message = f"Low disk space: {free_percent:.1f}% free"

                return HealthCheckResult(
                    component="disk_space",
                    status=status,
                    message=message,
                    details={
                        "free_bytes": disk_usage.free,
                        "total_bytes": disk_usage.total,
                        "free_percent": free_percent,
                        "cache_dir": str(cache_dir),
                    },
                )
            else:
                return HealthCheckResult(
                    component="disk_space",
                    status="warning",
                    message=f"Cache directory does not exist: {cache_dir}",
                )
        except Exception as e:
            return HealthCheckResult(
                component="disk_space",
                status="critical",
                message=f"Failed to check disk space: {str(e)}",
            )

    def _check_memory_usage(self) -> HealthCheckResult:
        """Check memory usage specific to fingerprinting."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024

            config = get_config()
            memory_limit = config.performance.memory_limit_mb

            usage_percent = (memory_mb / memory_limit) * 100

            status = "healthy"
            message = f"Memory usage normal: {memory_mb:.1f}MB ({usage_percent:.1f}%)"

            if usage_percent > 90:
                status = "critical"
                message = f"High memory usage: {memory_mb:.1f}MB ({usage_percent:.1f}%)"
            elif usage_percent > 70:
                status = "warning"
                message = f"Elevated memory usage: {memory_mb:.1f}MB ({usage_percent:.1f}%)"

            return HealthCheckResult(
                component="memory_usage",
                status=status,
                message=message,
                details={
                    "memory_mb": memory_mb,
                    "memory_limit_mb": memory_limit,
                    "usage_percent": usage_percent,
                },
            )
        except Exception as e:
            return HealthCheckResult(
                component="memory_usage",
                status="critical",
                message=f"Failed to check memory usage: {str(e)}",
            )

    def _check_cache_system(self) -> HealthCheckResult:
        """Check cache system health."""
        try:
            from core.fingerprint.cache import FingerprintCache

            config = get_config()
            cache = FingerprintCache(cache_dir=config.cache.cache_dir)

            # Test cache operations
            test_fp = DPIFingerprint(
                target="health-check-test.com", dpi_type=DPIType.UNKNOWN, confidence=0.5
            )

            # Test store and retrieve
            cache.store("health-check-test", test_fp)
            retrieved = cache.get("health-check-test")

            if retrieved and retrieved.target == test_fp.target:
                return HealthCheckResult(
                    component="cache_system",
                    status="healthy",
                    message="Cache system operational",
                )
            else:
                return HealthCheckResult(
                    component="cache_system",
                    status="critical",
                    message="Cache store/retrieve test failed",
                )
        except Exception as e:
            return HealthCheckResult(
                component="cache_system",
                status="critical",
                message=f"Cache system check failed: {str(e)}",
            )

    def _check_ml_model(self) -> HealthCheckResult:
        """Check ML model availability and health."""
        try:
            from core.fingerprint.ml_classifier import MLClassifier

            config = get_config()
            if not config.ml.enabled:
                return HealthCheckResult(
                    component="ml_model",
                    status="healthy",
                    message="ML model disabled in configuration",
                )

            classifier = MLClassifier()

            # Test model prediction
            test_metrics = {
                "rst_injection_detected": True,
                "http_header_filtering": False,
                "dns_hijacking_detected": False,
                "content_inspection_depth": 1000,
            }

            prediction = classifier.classify_dpi(test_metrics)

            if prediction and "dpi_type" in prediction:
                return HealthCheckResult(
                    component="ml_model",
                    status="healthy",
                    message="ML model operational",
                    details={"model_available": True, "test_prediction": prediction},
                )
            else:
                return HealthCheckResult(
                    component="ml_model",
                    status="warning",
                    message="ML model prediction failed",
                )
        except Exception as e:
            return HealthCheckResult(
                component="ml_model",
                status="warning",
                message=f"ML model check failed: {str(e)}",
            )


class DiagnosticLogger:
    """Enhanced logging system for fingerprinting operations."""

    def __init__(self, name: str = "fingerprinting"):
        """Initialize diagnostic logger."""
        self.logger = logging.getLogger(name)
        self.setup_logging()

    def setup_logging(self):
        """Setup logging configuration."""
        config = get_config()

        # Set log level
        level = getattr(logging, config.logging.level.value)
        self.logger.setLevel(level)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Console handler
        if config.logging.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            if config.logging.structured_logging:
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(logging.Formatter(config.logging.format))
            self.logger.addHandler(console_handler)

        # File handler
        if config.logging.file_path:
            file_handler = logging.handlers.RotatingFileHandler(
                config.logging.file_path,
                maxBytes=config.logging.max_file_size,
                backupCount=config.logging.backup_count,
            )
            if config.logging.structured_logging:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_handler.setFormatter(logging.Formatter(config.logging.format))
            self.logger.addHandler(file_handler)

    def log_fingerprinting_start(self, target: str):
        """Log start of fingerprinting operation."""
        self.logger.info("Starting fingerprinting operation", extra={"fingerprint_target": target})

    def log_fingerprinting_complete(
        self, target: str, fingerprint: DPIFingerprint, duration: float
    ):
        """Log completion of fingerprinting operation."""
        self.logger.info(
            "Fingerprinting operation completed",
            extra={
                "fingerprint_target": target,
                "dpi_type": fingerprint.dpi_type.value,
                "confidence": fingerprint.confidence,
                "duration": duration,
            },
        )

    def log_fingerprinting_error(self, target: str, error: Exception, duration: float):
        """Log fingerprinting operation error."""
        self.logger.error(
            f"Fingerprinting operation failed: {str(error)}",
            extra={
                "fingerprint_target": target,
                "error_type": type(error).__name__,
                "duration": duration,
            },
            exc_info=True,
        )

    def log_analyzer_result(
        self, analyzer: str, target: str, result: Dict[str, Any], duration: float
    ):
        """Log analyzer result."""
        self.logger.debug(
            f"Analyzer {analyzer} completed",
            extra={
                "analyzer": analyzer,
                "fingerprint_target": target,
                "duration": duration,
                "result_keys": list(result.keys()),
            },
        )

    def log_ml_classification(self, target: str, prediction: Dict[str, Any], duration: float):
        """Log ML classification result."""
        self.logger.info(
            "ML classification completed",
            extra={
                "fingerprint_target": target,
                "dpi_type": prediction.get("dpi_type", "unknown"),
                "confidence": prediction.get("confidence", 0.0),
                "duration": duration,
            },
        )

    def log_cache_operation(self, operation: str, target: str, hit: bool = None):
        """Log cache operation."""
        message = f"Cache {operation}"
        extra = {"cache_operation": operation, "fingerprint_target": target}

        if hit is not None:
            message += f" - {'hit' if hit else 'miss'}"
            extra["cache_hit"] = hit

        self.logger.debug(message, extra=extra)


class DiagnosticSystem:
    """Main diagnostic system coordinating all monitoring components."""

    def __init__(self):
        """Initialize diagnostic system."""
        self.metrics_collector = MetricsCollector()
        self.health_checker = HealthChecker()
        self.logger = DiagnosticLogger()
        self.error_history = deque(maxlen=100)
        self.fingerprinting_stats = {
            "total_fingerprints": 0,
            "successful_fingerprints": 0,
            "failed_fingerprints": 0,
            "average_duration": 0.0,
            "dpi_type_distribution": defaultdict(int),
        }
        self.lock = threading.Lock()

    def record_fingerprinting_operation(
        self,
        target: str,
        success: bool,
        duration: float,
        fingerprint: Optional[DPIFingerprint] = None,
        error: Optional[Exception] = None,
    ):
        """Record a fingerprinting operation for metrics and logging."""

        # Update statistics
        with self.lock:
            self.fingerprinting_stats["total_fingerprints"] += 1

            if success:
                self.fingerprinting_stats["successful_fingerprints"] += 1
                if fingerprint:
                    self.fingerprinting_stats["dpi_type_distribution"][
                        fingerprint.dpi_type.value
                    ] += 1
            else:
                self.fingerprinting_stats["failed_fingerprints"] += 1
                if error:
                    self.error_history.append(
                        {
                            "timestamp": time.time(),
                            "target": target,
                            "error_type": type(error).__name__,
                            "error_message": str(error),
                            "duration": duration,
                        }
                    )

            # Update average duration
            total = self.fingerprinting_stats["total_fingerprints"]
            current_avg = self.fingerprinting_stats["average_duration"]
            self.fingerprinting_stats["average_duration"] = (
                current_avg * (total - 1) + duration
            ) / total

        # Record metrics
        self.metrics_collector.record_metric(
            "fingerprinting_duration",
            duration,
            "seconds",
            {"target": target, "success": str(success)},
        )

        if success and fingerprint:
            self.metrics_collector.record_metric(
                "fingerprinting_confidence",
                fingerprint.confidence,
                "score",
                {"dpi_type": fingerprint.dpi_type.value},
            )

        # Log operation
        if success and fingerprint:
            self.logger.log_fingerprinting_complete(target, fingerprint, duration)
        elif error:
            self.logger.log_fingerprinting_error(target, error, duration)

    def record_analyzer_operation(
        self,
        analyzer: str,
        target: str,
        duration: float,
        success: bool,
        result: Optional[Dict[str, Any]] = None,
    ):
        """Record analyzer operation metrics."""
        self.metrics_collector.record_metric(
            f"analyzer_{analyzer}_duration",
            duration,
            "seconds",
            {"target": target, "success": str(success)},
        )

        if success and result:
            self.logger.log_analyzer_result(analyzer, target, result, duration)

    def record_ml_classification(self, target: str, duration: float, prediction: Dict[str, Any]):
        """Record ML classification metrics."""
        self.metrics_collector.record_metric(
            "ml_classification_duration", duration, "seconds", {"target": target}
        )

        if "confidence" in prediction:
            self.metrics_collector.record_metric(
                "ml_classification_confidence",
                prediction["confidence"],
                "score",
                {"dpi_type": prediction.get("dpi_type", "unknown")},
            )

        self.logger.log_ml_classification(target, prediction, duration)

    def record_cache_operation(
        self, operation: str, target: str, hit: bool = None, duration: float = None
    ):
        """Record cache operation metrics."""
        if duration is not None:
            self.metrics_collector.record_metric(
                f"cache_{operation}_duration", duration, "seconds", {"target": target}
            )

        if hit is not None:
            self.metrics_collector.record_metric("cache_hit_rate", 1.0 if hit else 0.0, "ratio")

        self.logger.log_cache_operation(operation, target, hit)

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        try:
            return {
                "python_version": sys.version,
                "platform": sys.platform,
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": dict(psutil.disk_usage("/")),
                "process_id": os.getpid(),
                "uptime": time.time() - psutil.boot_time(),
            }
        except Exception as e:
            return {"error": f"Failed to get system info: {str(e)}"}

    def generate_diagnostic_report(self) -> DiagnosticReport:
        """Generate comprehensive diagnostic report."""
        return DiagnosticReport(
            system_info=self.get_system_info(),
            performance_metrics=[
                PerformanceMetric(
                    name=name,
                    value=stats.get("latest", 0),
                    unit="",
                    tags={"stats": json.dumps(stats)},
                )
                for name, stats in self.metrics_collector.get_all_metrics().items()
            ],
            health_checks=self.health_checker.run_all_checks(),
            recent_errors=list(self.error_history)[-10:],  # Last 10 errors
            fingerprinting_stats=dict(self.fingerprinting_stats),
        )

    def export_diagnostic_report(self, file_path: str):
        """Export diagnostic report to file."""
        report = self.generate_diagnostic_report()

        with open(file_path, "w") as f:
            json.dump(asdict(report), f, indent=2, default=str)


# Global diagnostic system instance
_diagnostic_system = None


def get_diagnostic_system() -> DiagnosticSystem:
    """Get global diagnostic system instance."""
    global _diagnostic_system

    if _diagnostic_system is None:
        _diagnostic_system = DiagnosticSystem()

    return _diagnostic_system


def setup_logging():
    """Setup logging for the entire fingerprinting system."""
    diagnostic_system = get_diagnostic_system()
    diagnostic_system.logger.setup_logging()


# Decorator for automatic operation monitoring
def monitor_operation(operation_type: str):
    """Decorator to automatically monitor operations."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            diagnostic_system = get_diagnostic_system()

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Record successful operation
                diagnostic_system.metrics_collector.record_metric(
                    f"{operation_type}_duration", duration, "seconds"
                )

                return result
            except Exception:
                duration = time.time() - start_time

                # Record failed operation
                diagnostic_system.metrics_collector.record_metric(
                    f"{operation_type}_error_rate", 1.0, "count"
                )

                raise

        return wrapper

    return decorator


if __name__ == "__main__":
    # CLI interface for diagnostics
    import argparse

    parser = argparse.ArgumentParser(description="Advanced DPI Fingerprinting Diagnostics")
    parser.add_argument("--health-check", action="store_true", help="Run health checks")
    parser.add_argument("--metrics", action="store_true", help="Show performance metrics")
    parser.add_argument("--report", help="Generate diagnostic report to file")
    parser.add_argument("--test-logging", action="store_true", help="Test logging system")

    args = parser.parse_args()

    diagnostic_system = get_diagnostic_system()

    if args.health_check:
        print("Running health checks...")
        results = diagnostic_system.health_checker.run_all_checks()

        for result in results:
            status_icon = {"healthy": "✅", "warning": "⚠️", "critical": "❌"}.get(
                result.status, "❓"
            )
            print(f"{status_icon} {result.component}: {result.message}")

    elif args.metrics:
        print("Performance metrics:")
        metrics = diagnostic_system.metrics_collector.get_all_metrics()

        for name, stats in metrics.items():
            print(f"\n{name}:")
            for key, value in stats.items():
                print(f"  {key}: {value}")

    elif args.report:
        print(f"Generating diagnostic report: {args.report}")
        diagnostic_system.export_diagnostic_report(args.report)
        print("Report generated successfully")

    elif args.test_logging:
        print("Testing logging system...")
        logger = diagnostic_system.logger

        logger.logger.debug("Debug message")
        logger.logger.info("Info message")
        logger.logger.warning("Warning message")
        logger.logger.error("Error message")

        # Test structured logging
        logger.log_fingerprinting_start("test.com")

        test_fp = DPIFingerprint(
            target="test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.85
        )

        logger.log_fingerprinting_complete("test.com", test_fp, 1.5)

        print("Logging test completed")

    else:
        parser.print_help()
