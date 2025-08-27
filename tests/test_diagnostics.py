#!/usr/bin/env python3
"""
Test suite for Monitoring and Diagnostics System - Task 18 Implementation
Tests logging, metrics collection, health checks, and diagnostic tools.
"""

import unittest
import tempfile
import shutil
import json
import time
import threading
import os
import sys
from unittest.mock import Mock, patch

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from core.fingerprint.diagnostics import (
        MetricsCollector,
        HealthChecker,
        DiagnosticLogger,
        DiagnosticSystem,
        PerformanceMetric,
        HealthCheckResult,
        DiagnosticReport,
        get_diagnostic_system,
        setup_logging,
        monitor_operation,
    )
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
except ImportError:
    from recon.core.fingerprint.diagnostics import (
        MetricsCollector,
        HealthChecker,
        DiagnosticLogger,
        DiagnosticSystem,
        HealthCheckResult,
        DiagnosticReport,
        get_diagnostic_system,
        monitor_operation,
    )
    from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.collector = MetricsCollector(max_history=100)

    def test_record_metric(self):
        """Test recording performance metrics."""
        self.collector.record_metric("test_metric", 1.5, "seconds", {"tag": "value"})

        # Verify metric was recorded
        stats = self.collector.get_metric_stats("test_metric")
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["latest"], 1.5)
        self.assertEqual(stats["mean"], 1.5)

    def test_metric_statistics(self):
        """Test metric statistics calculation."""
        # Record multiple metrics
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for value in values:
            self.collector.record_metric("test_stats", value, "units")

        stats = self.collector.get_metric_stats("test_stats")

        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["min"], 1.0)
        self.assertEqual(stats["max"], 5.0)
        self.assertEqual(stats["mean"], 3.0)
        self.assertEqual(stats["median"], 3.0)
        self.assertGreater(stats["std_dev"], 0)

    def test_time_window_filtering(self):
        """Test metric filtering by time window."""
        # Record metrics with different timestamps
        self.collector.record_metric("windowed_metric", 1.0, "units")
        time.sleep(0.1)
        self.collector.record_metric("windowed_metric", 2.0, "units")

        # Get stats for very short time window (should only include recent metric)
        stats = self.collector.get_metric_stats("windowed_metric", time_window=0.05)
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["latest"], 2.0)

        # Get stats for longer time window (should include both)
        stats = self.collector.get_metric_stats("windowed_metric", time_window=1.0)
        self.assertEqual(stats["count"], 2)

    def test_thread_safety(self):
        """Test thread safety of metrics collection."""

        def record_metrics():
            for i in range(50):
                self.collector.record_metric("thread_test", i, "count")

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=record_metrics)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all metrics were recorded
        stats = self.collector.get_metric_stats("thread_test")
        self.assertEqual(stats["count"], 250)  # 5 threads * 50 metrics each

    def test_max_history_limit(self):
        """Test maximum history limit enforcement."""
        collector = MetricsCollector(max_history=10)

        # Record more metrics than the limit
        for i in range(20):
            collector.record_metric("limited_metric", i, "count")

        stats = collector.get_metric_stats("limited_metric")
        self.assertEqual(stats["count"], 10)  # Should be limited to max_history
        self.assertEqual(stats["latest"], 19)  # Should be the most recent value


class TestHealthChecker(unittest.TestCase):
    """Test health checking functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.health_checker = HealthChecker()

    def test_register_custom_check(self):
        """Test registering custom health checks."""

        def custom_check():
            return HealthCheckResult(
                component="custom_test", status="healthy", message="Custom check passed"
            )

        self.health_checker.register_check("custom_test", custom_check)
        result = self.health_checker.run_check("custom_test")

        self.assertEqual(result.component, "custom_test")
        self.assertEqual(result.status, "healthy")
        self.assertEqual(result.message, "Custom check passed")

    def test_run_nonexistent_check(self):
        """Test running non-existent health check."""
        result = self.health_checker.run_check("nonexistent")

        self.assertEqual(result.component, "nonexistent")
        self.assertEqual(result.status, "critical")
        self.assertIn("not found", result.message)

    def test_check_exception_handling(self):
        """Test health check exception handling."""

        def failing_check():
            raise Exception("Test exception")

        self.health_checker.register_check("failing_test", failing_check)
        result = self.health_checker.run_check("failing_test")

        self.assertEqual(result.component, "failing_test")
        self.assertEqual(result.status, "critical")
        self.assertIn("Test exception", result.message)

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    def test_system_resources_check(self, mock_memory, mock_cpu):
        """Test system resources health check."""
        # Mock normal resource usage
        mock_cpu.return_value = 50.0
        mock_memory.return_value = Mock(percent=60.0, available=1000000, total=2000000)

        result = self.health_checker.run_check("system_resources")

        self.assertEqual(result.component, "system_resources")
        self.assertEqual(result.status, "healthy")
        self.assertIn("normal", result.message.lower())

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    def test_system_resources_warning(self, mock_memory, mock_cpu):
        """Test system resources warning condition."""
        # Mock high resource usage
        mock_cpu.return_value = 80.0
        mock_memory.return_value = Mock(percent=75.0, available=500000, total=2000000)

        result = self.health_checker.run_check("system_resources")

        self.assertEqual(result.component, "system_resources")
        self.assertEqual(result.status, "warning")

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    def test_system_resources_critical(self, mock_memory, mock_cpu):
        """Test system resources critical condition."""
        # Mock critical resource usage
        mock_cpu.return_value = 95.0
        mock_memory.return_value = Mock(percent=95.0, available=100000, total=2000000)

        result = self.health_checker.run_check("system_resources")

        self.assertEqual(result.component, "system_resources")
        self.assertEqual(result.status, "critical")

    def test_run_all_checks(self):
        """Test running all health checks."""
        results = self.health_checker.run_all_checks()

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Verify all results are HealthCheckResult objects
        for result in results:
            self.assertIsInstance(result, HealthCheckResult)
            self.assertIn(result.status, ["healthy", "warning", "critical"])


class TestDiagnosticLogger(unittest.TestCase):
    """Test diagnostic logging functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test.log")

        # Mock configuration
        self.mock_config = Mock()
        self.mock_config.logging.level.value = "INFO"
        self.mock_config.logging.console_output = True
        self.mock_config.logging.structured_logging = False
        self.mock_config.logging.format = "%(asctime)s - %(levelname)s - %(message)s"
        self.mock_config.logging.file_path = self.log_file
        self.mock_config.logging.max_file_size = 1024 * 1024
        self.mock_config.logging.backup_count = 3

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("core.fingerprint.diagnostics.get_config")
    def test_logger_initialization(self, mock_get_config):
        """Test diagnostic logger initialization."""
        mock_get_config.return_value = self.mock_config

        logger = DiagnosticLogger("test_logger")

        self.assertIsNotNone(logger.logger)
        self.assertEqual(logger.logger.name, "test_logger")

    @patch("core.fingerprint.diagnostics.get_config")
    def test_fingerprinting_logging(self, mock_get_config):
        """Test fingerprinting operation logging."""
        mock_get_config.return_value = self.mock_config

        logger = DiagnosticLogger("test_logger")

        # Test logging start
        logger.log_fingerprinting_start("test.com")

        # Test logging completion
        fingerprint = DPIFingerprint(
            target="test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.85
        )
        logger.log_fingerprinting_complete("test.com", fingerprint, 1.5)

        # Test logging error
        error = Exception("Test error")
        logger.log_fingerprinting_error("test.com", error, 2.0)

        # Verify log file was created and contains entries
        self.assertTrue(os.path.exists(self.log_file))

        with open(self.log_file, "r") as f:
            log_content = f.read()
            self.assertIn("Starting fingerprinting", log_content)
            self.assertIn("completed", log_content)
            self.assertIn("failed", log_content)

    @patch("core.fingerprint.diagnostics.get_config")
    def test_structured_logging(self, mock_get_config):
        """Test structured logging format."""
        self.mock_config.logging.structured_logging = True
        mock_get_config.return_value = self.mock_config

        logger = DiagnosticLogger("test_logger")

        fingerprint = DPIFingerprint(
            target="structured-test.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.9,
        )

        logger.log_fingerprinting_complete("structured-test.com", fingerprint, 2.5)

        # Verify structured log format
        with open(self.log_file, "r") as f:
            log_content = f.read()

            # Should be valid JSON
            try:
                log_entry = json.loads(log_content.strip())
                self.assertIn("timestamp", log_entry)
                self.assertIn("level", log_entry)
                self.assertIn("fingerprint_target", log_entry)
                self.assertIn("dpi_type", log_entry)
                self.assertIn("confidence", log_entry)
            except json.JSONDecodeError:
                self.fail("Structured log should be valid JSON")


class TestDiagnosticSystem(unittest.TestCase):
    """Test main diagnostic system."""

    def setUp(self):
        """Set up test fixtures."""
        self.diagnostic_system = DiagnosticSystem()

    def test_record_successful_fingerprinting(self):
        """Test recording successful fingerprinting operation."""
        fingerprint = DPIFingerprint(
            target="success-test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.85
        )

        self.diagnostic_system.record_fingerprinting_operation(
            target="success-test.com",
            success=True,
            duration=1.5,
            fingerprint=fingerprint,
        )

        # Verify statistics were updated
        stats = self.diagnostic_system.fingerprinting_stats
        self.assertEqual(stats["total_fingerprints"], 1)
        self.assertEqual(stats["successful_fingerprints"], 1)
        self.assertEqual(stats["failed_fingerprints"], 0)
        self.assertEqual(stats["average_duration"], 1.5)
        self.assertEqual(stats["dpi_type_distribution"]["commercial_dpi"], 1)

    def test_record_failed_fingerprinting(self):
        """Test recording failed fingerprinting operation."""
        error = Exception("Test error")

        self.diagnostic_system.record_fingerprinting_operation(
            target="failure-test.com", success=False, duration=2.0, error=error
        )

        # Verify statistics were updated
        stats = self.diagnostic_system.fingerprinting_stats
        self.assertEqual(stats["total_fingerprints"], 1)
        self.assertEqual(stats["successful_fingerprints"], 0)
        self.assertEqual(stats["failed_fingerprints"], 1)
        self.assertEqual(stats["average_duration"], 2.0)

        # Verify error was recorded
        self.assertEqual(len(self.diagnostic_system.error_history), 1)
        error_record = self.diagnostic_system.error_history[0]
        self.assertEqual(error_record["target"], "failure-test.com")
        self.assertEqual(error_record["error_type"], "Exception")

    def test_record_analyzer_operation(self):
        """Test recording analyzer operation."""
        result = {"metric1": True, "metric2": 1500}

        self.diagnostic_system.record_analyzer_operation(
            analyzer="tcp",
            target="analyzer-test.com",
            duration=0.5,
            success=True,
            result=result,
        )

        # Verify metric was recorded
        metrics = self.diagnostic_system.metrics_collector.get_all_metrics()
        self.assertIn("analyzer_tcp_duration", metrics)

    def test_record_ml_classification(self):
        """Test recording ML classification."""
        prediction = {"dpi_type": "commercial_dpi", "confidence": 0.9}

        self.diagnostic_system.record_ml_classification(
            target="ml-test.com", duration=0.2, prediction=prediction
        )

        # Verify metrics were recorded
        metrics = self.diagnostic_system.metrics_collector.get_all_metrics()
        self.assertIn("ml_classification_duration", metrics)
        self.assertIn("ml_classification_confidence", metrics)

    def test_record_cache_operation(self):
        """Test recording cache operation."""
        self.diagnostic_system.record_cache_operation(
            operation="get", target="cache-test.com", hit=True, duration=0.001
        )

        # Verify metrics were recorded
        metrics = self.diagnostic_system.metrics_collector.get_all_metrics()
        self.assertIn("cache_get_duration", metrics)
        self.assertIn("cache_hit_rate", metrics)

    @patch("psutil.cpu_count")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.boot_time")
    def test_get_system_info(
        self, mock_boot_time, mock_disk_usage, mock_memory, mock_cpu_count
    ):
        """Test system information collection."""
        # Mock system information
        mock_cpu_count.return_value = 4
        mock_memory.return_value = Mock(total=8000000000)
        mock_disk_usage.return_value = Mock(
            total=1000000000, free=500000000, used=500000000
        )
        mock_boot_time.return_value = time.time() - 3600  # 1 hour ago

        system_info = self.diagnostic_system.get_system_info()

        self.assertIn("python_version", system_info)
        self.assertIn("platform", system_info)
        self.assertIn("cpu_count", system_info)
        self.assertIn("memory_total", system_info)
        self.assertIn("process_id", system_info)
        self.assertEqual(system_info["cpu_count"], 4)

    def test_generate_diagnostic_report(self):
        """Test diagnostic report generation."""
        # Record some test data
        fingerprint = DPIFingerprint(
            target="report-test.com", dpi_type=DPIType.ROSKOMNADZOR_TSPU, confidence=0.8
        )

        self.diagnostic_system.record_fingerprinting_operation(
            target="report-test.com",
            success=True,
            duration=1.0,
            fingerprint=fingerprint,
        )

        # Generate report
        report = self.diagnostic_system.generate_diagnostic_report()

        self.assertIsInstance(report, DiagnosticReport)
        self.assertIsInstance(report.system_info, dict)
        self.assertIsInstance(report.performance_metrics, list)
        self.assertIsInstance(report.health_checks, list)
        self.assertIsInstance(report.fingerprinting_stats, dict)

        # Verify fingerprinting stats are included
        self.assertEqual(report.fingerprinting_stats["total_fingerprints"], 1)

    def test_export_diagnostic_report(self):
        """Test diagnostic report export."""
        temp_dir = tempfile.mkdtemp()
        try:
            report_file = os.path.join(temp_dir, "diagnostic_report.json")

            self.diagnostic_system.export_diagnostic_report(report_file)

            # Verify file was created
            self.assertTrue(os.path.exists(report_file))

            # Verify file contains valid JSON
            with open(report_file, "r") as f:
                report_data = json.load(f)
                self.assertIn("timestamp", report_data)
                self.assertIn("system_info", report_data)
                self.assertIn("performance_metrics", report_data)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestGlobalDiagnosticSystem(unittest.TestCase):
    """Test global diagnostic system functionality."""

    def test_get_diagnostic_system_singleton(self):
        """Test that get_diagnostic_system returns singleton."""
        system1 = get_diagnostic_system()
        system2 = get_diagnostic_system()

        self.assertIs(system1, system2)
        self.assertIsInstance(system1, DiagnosticSystem)

    def test_monitor_operation_decorator(self):
        """Test operation monitoring decorator."""

        @monitor_operation("test_operation")
        def test_function():
            time.sleep(0.1)
            return "success"

        result = test_function()

        self.assertEqual(result, "success")

        # Verify metric was recorded
        diagnostic_system = get_diagnostic_system()
        metrics = diagnostic_system.metrics_collector.get_all_metrics()
        self.assertIn("test_operation_duration", metrics)

    def test_monitor_operation_decorator_with_exception(self):
        """Test operation monitoring decorator with exception."""

        @monitor_operation("failing_operation")
        def failing_function():
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            failing_function()

        # Verify error metric was recorded
        diagnostic_system = get_diagnostic_system()
        metrics = diagnostic_system.metrics_collector.get_all_metrics()
        self.assertIn("failing_operation_error_rate", metrics)


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios with diagnostic system."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.diagnostic_system = get_diagnostic_system()

    def test_complete_fingerprinting_workflow_monitoring(self):
        """Test monitoring of complete fingerprinting workflow."""
        # Simulate complete fingerprinting workflow
        target = "integration-test.com"

        # Record analyzer operations
        self.diagnostic_system.record_analyzer_operation(
            analyzer="tcp",
            target=target,
            duration=0.5,
            success=True,
            result={"rst_injection_detected": True},
        )

        self.diagnostic_system.record_analyzer_operation(
            analyzer="http",
            target=target,
            duration=0.8,
            success=True,
            result={"http_header_filtering": True},
        )

        self.diagnostic_system.record_analyzer_operation(
            analyzer="dns",
            target=target,
            duration=0.3,
            success=True,
            result={"dns_hijacking_detected": False},
        )

        # Record ML classification
        prediction = {"dpi_type": "roskomnadzor_tspu", "confidence": 0.85}
        self.diagnostic_system.record_ml_classification(target, 0.2, prediction)

        # Record cache operations
        self.diagnostic_system.record_cache_operation(
            "get", target, hit=False, duration=0.001
        )
        self.diagnostic_system.record_cache_operation("store", target, duration=0.002)

        # Record final fingerprinting result
        fingerprint = DPIFingerprint(
            target=target, dpi_type=DPIType.ROSKOMNADZOR_TSPU, confidence=0.85
        )

        self.diagnostic_system.record_fingerprinting_operation(
            target=target, success=True, duration=2.0, fingerprint=fingerprint
        )

        # Verify all metrics were recorded
        metrics = self.diagnostic_system.metrics_collector.get_all_metrics()

        expected_metrics = [
            "analyzer_tcp_duration",
            "analyzer_http_duration",
            "analyzer_dns_duration",
            "ml_classification_duration",
            "ml_classification_confidence",
            "cache_get_duration",
            "cache_store_duration",
            "cache_hit_rate",
            "fingerprinting_duration",
            "fingerprinting_confidence",
        ]

        for metric in expected_metrics:
            self.assertIn(metric, metrics, f"Missing metric: {metric}")

        # Verify fingerprinting statistics
        stats = self.diagnostic_system.fingerprinting_stats
        self.assertEqual(stats["total_fingerprints"], 1)
        self.assertEqual(stats["successful_fingerprints"], 1)
        self.assertEqual(stats["dpi_type_distribution"]["roskomnadzor_tspu"], 1)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
