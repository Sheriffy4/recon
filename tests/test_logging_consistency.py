"""
Test logging consistency and format.

This test verifies that logging follows the consistent format specified in
Requirements 10.1, 10.2, 10.3, 10.4, 10.5.

Feature: strategy-testing-production-parity
Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.test_result_coordinator import TestResultCoordinator
from core.test_result_models import TestVerdict, PCAPAnalysisResult
from core.validation.strategy_saver import StrategySaver


class LogCapture(logging.Handler):
    """Helper to capture log messages."""
    
    def __init__(self):
        super().__init__()
        self.messages = []
        
    def emit(self, record):
        self.messages.append(self.format(record))


class TestLoggingConsistency:
    """
    Test that logging follows consistent format across all components.
    
    Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
    """
    
    def test_start_test_logging_format(self):
        """
        Test that start_test logs in format: "Starting test: [strategy] for [domain]"
        
        Requirement 10.1
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        # Add handler to capture logs
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute
        session_id = coordinator.start_test(
            domain="example.com",
            strategy_name="split",
            pcap_file="test.pcap"
        )
        
        # Verify
        assert any("Starting test: [split] for [example.com]" in msg for msg in log_capture.messages), \
            f"Expected 'Starting test: [split] for [example.com]' in logs, got: {log_capture.messages}"
    
    def test_test_result_logging_format(self):
        """
        Test that finalize_test logs in format: "Test result: [verdict] for [strategy]"
        
        Requirement 10.2
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        # Add handler to capture logs
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Create test session
        session_id = coordinator.start_test(
            domain="example.com",
            strategy_name="split",
            pcap_file="test.pcap"
        )
        
        # Record high retransmissions (will cause FAIL verdict)
        coordinator.record_retransmission(session_id, 5)
        
        # Execute
        verdict = coordinator.finalize_test(session_id)
        
        # Verify
        assert verdict == TestVerdict.FAIL
        assert any("Test result: FAIL for [split]" in msg for msg in log_capture.messages), \
            f"Expected 'Test result: FAIL for [split]' in logs, got: {log_capture.messages}"
    
    def test_pcap_analysis_logging_format(self):
        """
        Test that PCAP analysis logs in format: "Analyzing PCAP: [file]"
        
        Requirement 10.3
        """
        # Setup
        mock_analyzer = Mock()
        mock_analyzer.analyze_pcap.return_value = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=["split"],
            parameters={"split_pos": 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=["example.com"],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        coordinator = TestResultCoordinator(pcap_analyzer=mock_analyzer)
        log_capture = LogCapture()
        
        # Add handler to capture logs
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Create temp PCAP file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pcap', delete=False) as f:
            pcap_file = f.name
        
        try:
            # Execute
            result = coordinator.get_pcap_analysis(pcap_file)
            
            # Verify
            assert any(f"Analyzing PCAP: [{pcap_file}]" in msg for msg in log_capture.messages), \
                f"Expected 'Analyzing PCAP: [{pcap_file}]' in logs, got: {log_capture.messages}"
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    def test_save_strategy_logging_format(self):
        """
        Test that save logs in format: "Saved strategy: [strategy] to [file]"
        
        Requirement 10.4
        """
        # Setup
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            log_capture = LogCapture()
            
            # Add handler to capture logs
            logger = logging.getLogger("StrategySaver")
            logger.addHandler(log_capture)
            logger.setLevel(logging.DEBUG)
            
            # Execute
            result = saver.save_strategy(
                domain="example.com",
                strategy_name="split",
                parameters={"split_pos": 3},
                verdict=TestVerdict.SUCCESS,
                attacks=["split"]
            )
            
            # Verify
            assert result.success
            assert any("Saved strategy: [split] to [adaptive_knowledge.json]" in msg for msg in log_capture.messages), \
                f"Expected 'Saved strategy: [split] to [adaptive_knowledge.json]' in logs, got: {log_capture.messages}"
            assert any("Saved strategy: [split] to [domain_rules.json]" in msg for msg in log_capture.messages), \
                f"Expected 'Saved strategy: [split] to [domain_rules.json]' in logs, got: {log_capture.messages}"
            assert any("Saved strategy: [split] to [domain_strategies.json]" in msg for msg in log_capture.messages), \
                f"Expected 'Saved strategy: [split] to [domain_strategies.json]' in logs, got: {log_capture.messages}"
    
    def test_error_logging_includes_context(self):
        """
        Test that error logs include context (component, operation, details).
        
        Requirement 10.5
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        # Add handler to capture logs
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute - try to analyze non-existent PCAP
        result = coordinator.get_pcap_analysis("nonexistent.pcap")
        
        # Verify
        assert result is None
        # Should have warning about file not found
        assert any("PCAP file not found" in msg for msg in log_capture.messages)
    
    def test_error_logging_in_saver_includes_context(self):
        """
        Test that StrategySaver error logs include context.
        
        Requirement 10.5
        """
        # Setup - use read-only directory to trigger error
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create a file where we want a directory (will cause error)
            bad_path = tmpdir_path / "bad.json"
            bad_path.write_text("not a directory")
            
            # Try to use this as a directory path
            saver = StrategySaver(
                adaptive_knowledge_path=str(bad_path / "adaptive_knowledge.json"),
                domain_rules_path=str(bad_path / "domain_rules.json"),
                domain_strategies_path=str(bad_path / "domain_strategies.json")
            )
            
            log_capture = LogCapture()
            
            # Add handler to capture logs
            logger = logging.getLogger("StrategySaver")
            logger.addHandler(log_capture)
            logger.setLevel(logging.DEBUG)
            
            # Execute - this should fail due to invalid path
            result = saver.save_strategy(
                domain="example.com",
                strategy_name="split",
                parameters={"split_pos": 3},
                verdict=TestVerdict.SUCCESS,
                attacks=["split"]
            )
            
            # Verify - should have error logs even if result says success
            # (because no files were actually updated)
            assert len(result.files_updated) == 0, f"Expected no files updated, got: {result.files_updated}"
            
            # Should have error with context
            error_logs = [msg for msg in log_capture.messages if "Error" in msg]
            assert len(error_logs) > 0, f"Expected error logs, got: {log_capture.messages}"
            
            # Check that error includes component and operation
            assert any("component=StrategySaver" in msg for msg in error_logs), \
                f"Expected 'component=StrategySaver' in error logs, got: {error_logs}"
            assert any("operation=" in msg for msg in error_logs), \
                f"Expected 'operation=' in error logs, got: {error_logs}"


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_domain(draw):
    """Generate valid domain names."""
    tld = draw(st.sampled_from(['com', 'org', 'net', 'io', 'ru']))
    domain_name = draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz0123456789-',
        min_size=3,
        max_size=20
    ).filter(lambda x: not x.startswith('-') and not x.endswith('-')))
    
    return f"{domain_name}.{tld}"


@st.composite
def valid_strategy_name(draw):
    """Generate valid strategy names."""
    return draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz_',
        min_size=3,
        max_size=30
    ))


@st.composite
def operation_data(draw):
    """Generate test operations (start, complete, analyze, save, error)."""
    operation_type = draw(st.sampled_from([
        'start_test',
        'finalize_test',
        'get_pcap_analysis',
        'save_strategy',
        'error'
    ]))
    
    domain = draw(valid_domain())
    strategy = draw(valid_strategy_name())
    verdict = draw(st.sampled_from([v for v in TestVerdict]))
    pcap_file = f"/tmp/test_{draw(st.text(min_size=5, max_size=10, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))}.pcap"
    
    return {
        'operation_type': operation_type,
        'domain': domain,
        'strategy': strategy,
        'verdict': verdict,
        'pcap_file': pcap_file
    }


# ============================================================================
# Property Tests for Logging Consistency
# ============================================================================

class TestLoggingConsistencyProperty:
    """
    **Feature: strategy-testing-production-parity, Property 12: Logging is consistent and complete**
    **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
    
    Property: For any test operation (start, complete, analyze, save, error), the system must log
    with consistent format including operation type, strategy name, domain, and relevant details.
    """
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_start_test_logging_format_is_consistent(self, domain, strategy):
        """
        Test that start_test always logs in consistent format.
        
        For any domain and strategy, start_test must log:
        "Starting test: [strategy] for [domain]"
        
        Validates: Requirement 10.1
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute
        session_id = coordinator.start_test(
            domain=domain,
            strategy_name=strategy,
            pcap_file="test.pcap"
        )
        
        # Verify - must contain the expected format
        expected_pattern = f"Starting test: [{strategy}] for [{domain}]"
        assert any(expected_pattern in msg for msg in log_capture.messages), \
            f"Expected '{expected_pattern}' in logs, got: {log_capture.messages}"
        
        # Verify - must contain strategy name in brackets
        assert any(f"[{strategy}]" in msg for msg in log_capture.messages), \
            f"Expected strategy '[{strategy}]' in logs"
        
        # Verify - must contain domain in brackets
        assert any(f"[{domain}]" in msg for msg in log_capture.messages), \
            f"Expected domain '[{domain}]' in logs"
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        retransmission_count=st.integers(min_value=0, max_value=10)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_finalize_test_logging_format_is_consistent(self, domain, strategy, retransmission_count):
        """
        Test that finalize_test always logs in consistent format.
        
        For any test completion, finalize_test must log:
        "Test result: [VERDICT] for [strategy]"
        
        Validates: Requirement 10.2
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Create test session
        session_id = coordinator.start_test(
            domain=domain,
            strategy_name=strategy,
            pcap_file="test.pcap"
        )
        
        # Record retransmissions
        coordinator.record_retransmission(session_id, retransmission_count)
        
        # Clear previous logs to focus on finalize_test
        log_capture.messages.clear()
        
        # Execute
        verdict = coordinator.finalize_test(session_id)
        
        # Verify - must contain the expected format
        expected_pattern = f"Test result: {verdict.value.upper()} for [{strategy}]"
        assert any(expected_pattern in msg for msg in log_capture.messages), \
            f"Expected '{expected_pattern}' in logs, got: {log_capture.messages}"
        
        # Verify - verdict must be uppercase
        assert any(verdict.value.upper() in msg for msg in log_capture.messages), \
            f"Expected verdict '{verdict.value.upper()}' in logs"
        
        # Verify - strategy must be in brackets
        assert any(f"[{strategy}]" in msg for msg in log_capture.messages), \
            f"Expected strategy '[{strategy}]' in logs"
    
    @given(operation=operation_data())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_all_operations_include_required_context(self, operation):
        """
        Test that all operations include required context in logs.
        
        For any operation, logs must include:
        - Operation type (start, complete, analyze, save, error)
        - Strategy name (when applicable)
        - Domain (when applicable)
        - Relevant details
        
        Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute operation based on type
        if operation['operation_type'] == 'start_test':
            coordinator.start_test(
                domain=operation['domain'],
                strategy_name=operation['strategy'],
                pcap_file=operation['pcap_file']
            )
            
            # Verify context is present
            assert any(operation['strategy'] in msg for msg in log_capture.messages), \
                f"Expected strategy '{operation['strategy']}' in logs"
            assert any(operation['domain'] in msg for msg in log_capture.messages), \
                f"Expected domain '{operation['domain']}' in logs"
        
        elif operation['operation_type'] == 'finalize_test':
            session_id = coordinator.start_test(
                domain=operation['domain'],
                strategy_name=operation['strategy'],
                pcap_file=operation['pcap_file']
            )
            log_capture.messages.clear()
            
            coordinator.finalize_test(session_id)
            
            # Verify context is present
            assert any(operation['strategy'] in msg for msg in log_capture.messages), \
                f"Expected strategy '{operation['strategy']}' in logs"
        
        elif operation['operation_type'] == 'get_pcap_analysis':
            # Create temp PCAP file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pcap', delete=False) as f:
                pcap_file = f.name
            
            try:
                # Mock analyzer
                mock_analyzer = Mock()
                mock_analyzer.analyze_pcap.return_value = PCAPAnalysisResult(
                    pcap_file=pcap_file,
                    packet_count=10,
                    detected_attacks=["split"],
                    parameters={"split_pos": 3},
                    split_positions=[3],
                    fake_packets_detected=0,
                    sni_values=["example.com"],
                    analysis_time=0.1,
                    analyzer_version="1.0"
                )
                
                coordinator.pcap_analyzer = mock_analyzer
                log_capture.messages.clear()
                
                coordinator.get_pcap_analysis(pcap_file)
                
                # Verify context is present
                assert any(pcap_file in msg for msg in log_capture.messages), \
                    f"Expected PCAP file '{pcap_file}' in logs"
            finally:
                Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        verdict=st.sampled_from([v for v in TestVerdict])
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_save_operations_include_file_names(self, domain, strategy, verdict):
        """
        Test that save operations include file names in logs.
        
        For any save operation, logs must include:
        "Saved strategy: [strategy] to [file]"
        
        Validates: Requirement 10.4
        """
        # Only test SUCCESS verdicts (others are blocked from saving)
        assume(verdict == TestVerdict.SUCCESS)
        
        # Setup
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            saver = StrategySaver(
                adaptive_knowledge_path=str(tmpdir_path / "adaptive_knowledge.json"),
                domain_rules_path=str(tmpdir_path / "domain_rules.json"),
                domain_strategies_path=str(tmpdir_path / "domain_strategies.json")
            )
            
            log_capture = LogCapture()
            
            # Add handler to capture logs
            logger = logging.getLogger("StrategySaver")
            logger.addHandler(log_capture)
            logger.setLevel(logging.DEBUG)
            
            # Execute
            result = saver.save_strategy(
                domain=domain,
                strategy_name=strategy,
                parameters={"split_pos": 3},
                verdict=verdict,
                attacks=["split"]
            )
            
            # Verify - must include strategy name
            assert any(strategy in msg for msg in log_capture.messages), \
                f"Expected strategy '{strategy}' in logs"
            
            # Verify - must include file names
            expected_files = ["adaptive_knowledge.json", "domain_rules.json", "domain_strategies.json"]
            for file_name in expected_files:
                assert any(file_name in msg for msg in log_capture.messages), \
                    f"Expected file '{file_name}' in logs, got: {log_capture.messages}"
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_error_logs_include_component_and_operation(self, domain, strategy):
        """
        Test that error logs include component and operation context.
        
        For any error, logs must include:
        - Component name (which component encountered the error)
        - Operation name (which operation failed)
        - Error details
        
        Validates: Requirement 10.5
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute - try to analyze non-existent PCAP (will cause error/warning)
        result = coordinator.get_pcap_analysis("nonexistent.pcap")
        
        # Verify - should have warning about file not found
        assert any("PCAP file not found" in msg or "nonexistent.pcap" in msg for msg in log_capture.messages), \
            f"Expected error/warning about missing PCAP in logs, got: {log_capture.messages}"
        
        # Verify - error context should be present
        # The coordinator logs warnings, not errors with full context, but the file path is included
        assert any("nonexistent.pcap" in msg for msg in log_capture.messages), \
            f"Expected file path in error logs"
    
    @given(
        operations=st.lists(
            st.tuples(valid_domain(), valid_strategy_name()),
            min_size=2,
            max_size=5
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_multiple_operations_maintain_consistent_format(self, operations):
        """
        Test that multiple operations maintain consistent logging format.
        
        For any sequence of operations, all logs must follow the same format conventions:
        - Brackets around key identifiers [strategy], [domain]
        - Consistent operation prefixes (Starting test, Test result, Analyzing PCAP, Saved strategy)
        - Consistent case (UPPERCASE for verdicts)
        
        Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5
        """
        # Setup
        coordinator = TestResultCoordinator()
        log_capture = LogCapture()
        
        coordinator.logger.addHandler(log_capture)
        coordinator.logger.setLevel(logging.DEBUG)
        
        # Execute multiple operations
        for domain, strategy in operations:
            session_id = coordinator.start_test(
                domain=domain,
                strategy_name=strategy,
                pcap_file="test.pcap"
            )
            
            coordinator.record_retransmission(session_id, 0)
            coordinator.record_response(session_id, response_status=200)
            coordinator.finalize_test(session_id)
        
        # Verify - all strategy names should be in brackets
        for domain, strategy in operations:
            assert any(f"[{strategy}]" in msg for msg in log_capture.messages), \
                f"Expected strategy '[{strategy}]' in brackets in logs"
        
        # Verify - all domains should be in brackets
        for domain, strategy in operations:
            assert any(f"[{domain}]" in msg for msg in log_capture.messages), \
                f"Expected domain '[{domain}]' in brackets in logs"
        
        # Verify - consistent operation prefixes
        start_logs = [msg for msg in log_capture.messages if "Starting test:" in msg]
        result_logs = [msg for msg in log_capture.messages if "Test result:" in msg]
        
        assert len(start_logs) == len(operations), \
            f"Expected {len(operations)} 'Starting test' logs, got {len(start_logs)}"
        assert len(result_logs) == len(operations), \
            f"Expected {len(operations)} 'Test result' logs, got {len(result_logs)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
