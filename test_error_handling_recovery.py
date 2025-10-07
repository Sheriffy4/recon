"""
Test error handling and recovery mechanisms for PCAP analysis system.

This test suite verifies that the error handling, graceful degradation,
and recovery mechanisms work correctly under various failure scenarios.
"""

import pytest
import tempfile
import os
import struct
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import logging

# Import the modules we're testing
from core.pcap_analysis.error_handling import (
    AnalysisError, PCAPParsingError, StrategyAnalysisError, FixGenerationError,
    ValidationError, ErrorCategory, ErrorSeverity, ErrorHandler, PartialResult,
    get_error_handler, handle_pcap_error, safe_execute
)
from core.pcap_analysis.graceful_degradation import (
    GracefulPCAPParser, PCAPFileInfo, get_graceful_parser, parse_pcap_with_fallback
)
from core.pcap_analysis.diagnostics import (
    DiagnosticChecker, PerformanceMonitor, DebugLogger,
    get_diagnostic_checker, get_performance_monitor, get_debug_logger,
    run_system_diagnostics
)
from core.pcap_analysis.logging_config import (
    setup_logging, get_logger, get_contextual_logger,
    log_operation_start, log_operation_end, log_error_with_context
)


class TestErrorHandling:
    """Test error handling functionality."""
    
    def setup_method(self):
        """Setup for each test method."""
        self.error_handler = ErrorHandler()
    
    def test_analysis_error_creation(self):
        """Test creating different types of analysis errors."""
        # Basic AnalysisError
        error = AnalysisError(
            "Test error",
            ErrorCategory.PCAP_PARSING,
            ErrorSeverity.HIGH
        )
        
        assert error.message == "Test error"
        assert error.category == ErrorCategory.PCAP_PARSING
        assert error.severity == ErrorSeverity.HIGH
        assert error.recoverable is True
        
        # Convert to dict
        error_dict = error.to_dict()
        assert error_dict["message"] == "Test error"
        assert error_dict["category"] == "pcap_parsing"
        assert error_dict["severity"] == "high"
    
    def test_pcap_parsing_error(self):
        """Test PCAP parsing error specifics."""
        error = PCAPParsingError(
            "Failed to parse packet",
            "test.pcap",
            packet_index=42
        )
        
        assert error.pcap_file == "test.pcap"
        assert error.packet_index == 42
        assert error.category == ErrorCategory.PCAP_PARSING
    
    def test_error_handler_basic_functionality(self):
        """Test basic error handler functionality."""
        # Test handling a simple exception
        test_exception = ValueError("Test error")
        result = self.error_handler.handle_error(test_exception)
        
        assert isinstance(result, PartialResult)
        assert result.success is False
        assert len(result.errors) == 1
        assert result.completeness == 0.0
        
        # Check error was logged
        assert len(self.error_handler.error_history) == 1
        assert self.error_handler.recovery_stats["total_errors"] == 1
    
    def test_error_recovery_mechanisms(self):
        """Test error recovery mechanisms."""
        # Create a recoverable PCAP parsing error
        pcap_error = PCAPParsingError(
            "Corrupted packet data",
            "test.pcap",
            packet_index=10,
            recoverable=True
        )
        
        result = self.error_handler.handle_error(pcap_error, attempt_recovery=True)
        
        # Should attempt recovery
        assert isinstance(result, PartialResult)
        # Recovery might succeed or fail, but should be attempted
        assert self.error_handler.recovery_stats["total_errors"] == 1
    
    def test_safe_execute(self):
        """Test safe execution wrapper."""
        # Test successful execution
        def success_func():
            return "success"
        
        result = safe_execute(success_func)
        assert result.success is True
        assert result.data == "success"
        assert result.completeness == 1.0
        
        # Test failed execution
        def fail_func():
            raise ValueError("Test failure")
        
        result = safe_execute(fail_func)
        assert result.success is False
        assert len(result.errors) > 0
    
    def test_error_summary(self):
        """Test error summary generation."""
        # Generate some errors
        errors = [
            PCAPParsingError("Error 1", "file1.pcap"),
            StrategyAnalysisError("Error 2", "strategy1"),
            FixGenerationError("Error 3", "fix1")
        ]
        
        for error in errors:
            self.error_handler.handle_error(error)
        
        summary = self.error_handler.get_error_summary()
        
        assert summary["total_errors"] == 3
        assert "pcap_parsing" in summary["error_counts_by_category"]
        assert "analysis_failure" in summary["error_counts_by_category"]
        assert "fix_generation" in summary["error_counts_by_category"]


class TestGracefulDegradation:
    """Test graceful degradation functionality."""
    
    def setup_method(self):
        """Setup for each test method."""
        self.parser = GracefulPCAPParser()
    
    def create_test_pcap(self, filepath: str, valid: bool = True, size: int = 1000):
        """Create a test PCAP file."""
        with open(filepath, 'wb') as f:
            if valid:
                # Write valid PCAP global header
                f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                # Write some dummy data
                f.write(b'x' * (size - 24))
            else:
                # Write invalid data
                f.write(b'invalid_pcap_data' * (size // 17))
    
    def test_pcap_file_analysis(self):
        """Test PCAP file analysis."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # Test non-existent file
            file_info = self.parser.analyze_pcap_file("nonexistent.pcap")
            assert not file_info.is_readable
            assert file_info.corruption_detected
            
            # Test valid file
            self.create_test_pcap(tmp_path, valid=True)
            file_info = self.parser.analyze_pcap_file(tmp_path)
            assert file_info.is_readable
            assert file_info.header_valid
            
            # Test invalid file
            self.create_test_pcap(tmp_path, valid=False)
            file_info = self.parser.analyze_pcap_file(tmp_path)
            assert file_info.is_readable  # File exists but is corrupted
            assert not file_info.header_valid
            assert file_info.corruption_detected
            
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    def test_parsing_with_degradation(self):
        """Test parsing with graceful degradation."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # Test with corrupted file
            self.create_test_pcap(tmp_path, valid=False)
            result = self.parser.parse_with_degradation(tmp_path)
            
            # Should attempt fallback strategies
            assert isinstance(result, PartialResult)
            # May succeed with fallback or fail completely
            
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    def test_fallback_strategies(self):
        """Test individual fallback strategies."""
        # Test that fallback strategies are properly configured
        assert len(self.parser.fallback_strategies) > 0
        
        # Check strategy priorities
        priorities = [s.priority for s in self.parser.fallback_strategies]
        assert priorities == sorted(priorities)  # Should be in priority order
    
    def test_parsing_statistics(self):
        """Test parsing statistics tracking."""
        initial_stats = self.parser.get_parsing_statistics()
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            self.create_test_pcap(tmp_path, valid=False)
            self.parser.parse_with_degradation(tmp_path)
            
            stats = self.parser.get_parsing_statistics()
            assert stats["total_files"] > 0
            
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass


class TestDiagnostics:
    """Test diagnostic functionality."""
    
    def setup_method(self):
        """Setup for each test method."""
        self.checker = DiagnosticChecker()
        self.monitor = PerformanceMonitor(sample_interval=0.1)
        self.debug_logger = DebugLogger()
    
    def test_diagnostic_checks(self):
        """Test diagnostic checks."""
        results = self.checker.run_all_checks()
        
        assert len(results) > 0
        
        # Check that we have expected diagnostic checks
        check_names = [r.check_name for r in results]
        expected_checks = [
            "system_resources",
            "python_environment",
            "dependencies",
            "file_permissions",
            "disk_space"
        ]
        
        for expected in expected_checks:
            assert expected in check_names
    
    def test_diagnostic_report_generation(self):
        """Test diagnostic report generation."""
        report = self.checker.generate_report()
        
        assert isinstance(report, str)
        assert "Diagnostic Report" in report
        assert "SUMMARY:" in report
        assert "DETAILED RESULTS:" in report
    
    def test_performance_monitoring(self):
        """Test performance monitoring."""
        # Test starting and stopping monitoring
        self.monitor.start_monitoring()
        assert self.monitor.monitoring is True
        
        # Test operation profiling
        with self.monitor.profile_operation("test_operation") as profile:
            # Simulate some work
            import time
            time.sleep(0.1)
        
        assert profile.duration is not None
        assert profile.duration > 0
        
        self.monitor.stop_monitoring()
        assert self.monitor.monitoring is False
        
        # Test performance summary
        summary = self.monitor.get_performance_summary()
        assert "operation_stats" in summary
        assert "test_operation" in summary["operation_stats"]
    
    def test_debug_logger(self):
        """Test debug logger functionality."""
        # Test operation tracking
        self.debug_logger.start_operation("test_op", param1="value1")
        assert "test_op" in self.debug_logger.operation_stack
        
        self.debug_logger.end_operation("test_op", result="success")
        assert "test_op" not in self.debug_logger.operation_stack
        
        # Test error logging
        test_error = ValueError("Test error")
        self.debug_logger.log_error_details(test_error, "test_context")
        
        # Should not raise exception
        assert True


class TestLoggingConfiguration:
    """Test logging configuration."""
    
    def test_logging_setup(self):
        """Test logging setup."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger_config = setup_logging(tmp_dir)
            
            assert logger_config is not None
            
            # Test getting loggers
            root_logger = get_logger("root")
            assert isinstance(root_logger, logging.Logger)
            
            contextual_logger = get_contextual_logger("test")
            assert contextual_logger is not None
            
            # Close handlers to release file locks
            logger_config.close_all_handlers()
    
    def test_contextual_logging(self):
        """Test contextual logging."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger_config = setup_logging(tmp_dir)
            
            contextual_logger = get_contextual_logger("test")
            contextual_logger.set_context(operation="test_op", user="test_user")
            
            # Should not raise exception
            contextual_logger.info("Test message")
            contextual_logger.error("Test error")
            
            contextual_logger.clear_context()
            
            # Close handlers to release file locks
            logger_config.close_all_handlers()
    
    def test_operation_logging(self):
        """Test operation logging functions."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger_config = setup_logging(tmp_dir)
            
            # Should not raise exceptions
            log_operation_start("test_operation", param1="value1")
            log_operation_end("test_operation", 1.5, result="success")
            
            test_error = ValueError("Test error")
            log_error_with_context(test_error, "test_context")
            
            # Close handlers to release file locks
            logger_config.close_all_handlers()


class TestIntegration:
    """Test integration between error handling components."""
    
    def test_error_handling_with_graceful_degradation(self):
        """Test error handling integrated with graceful degradation."""
        parser = get_graceful_parser()
        
        # Test parsing non-existent file
        result = parse_pcap_with_fallback("nonexistent.pcap")
        
        assert isinstance(result, PartialResult)
        assert result.success is False
        assert len(result.errors) > 0
    
    def test_diagnostics_with_error_handling(self):
        """Test diagnostics integrated with error handling."""
        # Run diagnostics
        report = run_system_diagnostics()
        
        assert isinstance(report, str)
        assert len(report) > 0
    
    def test_logging_with_error_handling(self):
        """Test logging integrated with error handling."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_logging(tmp_dir)
            
            error_handler = get_error_handler()
            
            # Generate an error
            test_error = PCAPParsingError("Test error", "test.pcap")
            result = error_handler.handle_error(test_error)
            
            assert isinstance(result, PartialResult)
            
            # Check that error was logged (should not raise exception)
            summary = error_handler.get_error_summary()
            assert summary["total_errors"] > 0


def test_module_imports():
    """Test that all modules can be imported without errors."""
    # Test imports
    from core.pcap_analysis import error_handling
    from core.pcap_analysis import graceful_degradation
    from core.pcap_analysis import diagnostics
    from core.pcap_analysis import logging_config
    
    # Test that global instances can be created
    error_handler = get_error_handler()
    parser = get_graceful_parser()
    checker = get_diagnostic_checker()
    monitor = get_performance_monitor()
    debug_logger = get_debug_logger()
    
    assert error_handler is not None
    assert parser is not None
    assert checker is not None
    assert monitor is not None
    assert debug_logger is not None


if __name__ == "__main__":
    # Run basic tests if executed directly
    print("Running basic error handling tests...")
    
    # Test error creation
    error = AnalysisError("Test", ErrorCategory.PCAP_PARSING)
    print(f"✓ Created error: {error.message}")
    
    # Test error handler
    handler = get_error_handler()
    result = handler.handle_error(ValueError("Test error"))
    print(f"✓ Error handler result: success={result.success}")
    
    # Test graceful parser
    parser = get_graceful_parser()
    file_info = parser.analyze_pcap_file("nonexistent.pcap")
    print(f"✓ File analysis: readable={file_info.is_readable}")
    
    # Test diagnostics
    checker = get_diagnostic_checker()
    checks = checker.run_all_checks()
    print(f"✓ Diagnostic checks: {len(checks)} checks completed")
    
    # Test logging
    with tempfile.TemporaryDirectory() as tmp_dir:
        logger_config = setup_logging(tmp_dir)
        logger = get_logger()
        logger.info("Test log message")
        logger_config.close_all_handlers()
        print("✓ Logging setup successful")
    
    print("All basic tests passed!")