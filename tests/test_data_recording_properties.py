"""
Property-based tests for test data recording and validation.

Feature: strategy-testing-production-parity, Property 11: Test data is recorded and validated
Validates: Requirements 9.1, 9.2, 9.3, 9.5

For any test execution, raw test data (packets sent, responses received, retransmissions)
must be recorded, then analyzed by validator to produce a verdict and validation report.
"""

import time
import tempfile
from pathlib import Path
from typing import Optional
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.test_result_coordinator import TestResultCoordinator
from core.test_result_models import (
    TestVerdict,
    TestSession,
    PCAPAnalysisResult,
    ValidationResult
)


# ============================================================================
# Mock Components for Testing
# ============================================================================

class MockPCAPAnalyzer:
    """Mock PCAP analyzer for testing."""
    
    def __init__(self, should_fail: bool = False, detected_attacks: Optional[list] = None):
        self.should_fail = should_fail
        self.detected_attacks = detected_attacks or ['split']
        self.analyze_count = 0
    
    def analyze_pcap(self, pcap_file: str) -> PCAPAnalysisResult:
        """Mock PCAP analysis."""
        self.analyze_count += 1
        
        if self.should_fail:
            raise Exception("PCAP analysis failed")
        
        return PCAPAnalysisResult(
            pcap_file=pcap_file,
            packet_count=10,
            detected_attacks=self.detected_attacks,
            parameters={'split_pos': 3} if 'split' in self.detected_attacks else {},
            analysis_time=0.1
        )


class MockStrategyValidator:
    """Mock strategy validator for testing."""
    
    def __init__(self, is_valid: bool = True, strategy_match: bool = True, 
                 all_attacks_applied: bool = True):
        self.is_valid = is_valid
        self.strategy_match = strategy_match
        self.all_attacks_applied = all_attacks_applied
        self.validate_count = 0
    
    def validate(self, strategy_name: str, pcap_analysis: PCAPAnalysisResult) -> ValidationResult:
        """Mock validation."""
        self.validate_count += 1
        
        return ValidationResult(
            is_valid=self.is_valid,
            all_attacks_applied=self.all_attacks_applied,
            declared_strategy=strategy_name,
            applied_strategy=strategy_name if self.strategy_match else "different_strategy",
            strategy_match=self.strategy_match,
            parameters_extracted=True,
            parameter_count=len(pcap_analysis.parameters)
        )


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
def execution_data_strategy(draw):
    """Generate test execution data (retransmissions, responses, etc.)."""
    # Generate timeout first
    timeout = draw(st.booleans())
    
    # If timeout, then no response
    if timeout:
        return {
            'retransmission_count': draw(st.integers(min_value=0, max_value=10)),
            'response_received': False,
            'response_status': None,
            'timeout': True
        }
    
    # Otherwise, generate response data
    response_received = draw(st.booleans())
    response_status = draw(st.one_of(
        st.none(),
        st.integers(min_value=200, max_value=599)
    )) if response_received else None
    
    return {
        'retransmission_count': draw(st.integers(min_value=0, max_value=10)),
        'response_received': response_received,
        'response_status': response_status,
        'timeout': False
    }


# ============================================================================
# Property Tests for Test Data Recording
# ============================================================================

class TestDataRecordingProperty:
    """
    **Feature: strategy-testing-production-parity, Property 11: Test data is recorded and validated**
    **Validates: Requirements 9.1, 9.2, 9.3, 9.5**
    
    Property: For any test execution, raw test data (packets sent, responses received, 
    retransmissions) must be recorded, then analyzed by validator to produce a verdict 
    and validation report.
    """
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        execution_data=execution_data_strategy()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_raw_test_data_is_recorded(self, domain, strategy, execution_data):
        """
        Test that raw test data is recorded during execution.
        
        For any test execution, the coordinator must record:
        - Retransmission count
        - Response status
        - Timeout status
        
        Validates: Requirements 9.1
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
        
        try:
            # Create coordinator with mock components
            coordinator = TestResultCoordinator(
                pcap_analyzer=MockPCAPAnalyzer(),
                strategy_validator=MockStrategyValidator()
            )
            
            # Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            
            # Record test data
            coordinator.record_retransmission(session_id, execution_data['retransmission_count'])
            coordinator.record_response(
                session_id,
                response_status=execution_data['response_status'],
                timeout=execution_data['timeout']
            )
            
            # Verify data was recorded
            session = coordinator.get_session(session_id)
            assert session is not None, "Session should exist"
            assert session.retransmission_count == execution_data['retransmission_count'], \
                "Retransmission count should be recorded"
            assert session.response_status == execution_data['response_status'], \
                "Response status should be recorded"
            assert session.timeout == execution_data['timeout'], \
                "Timeout status should be recorded"
            
            # Verify response_received is set correctly
            if execution_data['timeout']:
                assert not session.response_received, \
                    "Response should not be marked as received if timeout occurred"
            elif execution_data['response_status'] is not None:
                assert session.response_received, \
                    "Response should be marked as received if status is set"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        execution_data=execution_data_strategy()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validator_analyzes_recorded_data(self, domain, strategy, execution_data):
        """
        Test that validator analyzes the recorded test data.
        
        For any test execution, after data is recorded, the validator
        must analyze it to produce a verdict.
        
        Validates: Requirements 9.2
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator with mock components
            mock_analyzer = MockPCAPAnalyzer()
            mock_validator = MockStrategyValidator()
            coordinator = TestResultCoordinator(
                pcap_analyzer=mock_analyzer,
                strategy_validator=mock_validator
            )
            
            # Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            
            # Record test data
            coordinator.record_retransmission(session_id, execution_data['retransmission_count'])
            coordinator.record_response(
                session_id,
                response_status=execution_data['response_status'],
                timeout=execution_data['timeout']
            )
            
            # Finalize test (triggers validation)
            verdict = coordinator.finalize_test(session_id)
            
            # Verify verdict was determined
            assert verdict is not None, "Verdict should be determined"
            assert isinstance(verdict, TestVerdict), "Verdict should be a TestVerdict enum"
            
            # Verify session has verdict
            session = coordinator.get_session(session_id)
            assert session.verdict is not None, "Session should have verdict"
            assert session.verdict == verdict, "Session verdict should match returned verdict"
            assert session.verdict_reason, "Session should have verdict reason"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        execution_data=execution_data_strategy()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validation_report_is_generated(self, domain, strategy, execution_data):
        """
        Test that a validation report is generated after analysis.
        
        For any test execution, after validation, a validation report
        must be generated with the final verdict.
        
        Validates: Requirements 9.3
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator with mock components
            coordinator = TestResultCoordinator(
                pcap_analyzer=MockPCAPAnalyzer(),
                strategy_validator=MockStrategyValidator()
            )
            
            # Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            
            # Record test data
            coordinator.record_retransmission(session_id, execution_data['retransmission_count'])
            coordinator.record_response(
                session_id,
                response_status=execution_data['response_status'],
                timeout=execution_data['timeout']
            )
            
            # Finalize test
            verdict = coordinator.finalize_test(session_id)
            
            # Verify validation report exists
            session = coordinator.get_session(session_id)
            
            # If PCAP was analyzed and validator was called, validation_result should exist
            # (unless retransmissions >= 3 or timeout, which skip validation)
            if execution_data['retransmission_count'] < 3 and not execution_data['timeout']:
                # PCAP should have been analyzed
                assert session.pcap_analysis is not None, \
                    "PCAP analysis should be performed for non-failed tests"
                
                # Validation should have been performed
                assert session.validation_result is not None, \
                    "Validation result should exist for non-failed tests"
                
                # Validation result should have required fields
                assert hasattr(session.validation_result, 'is_valid'), \
                    "Validation result should have is_valid field"
                assert hasattr(session.validation_result, 'declared_strategy'), \
                    "Validation result should have declared_strategy field"
                assert hasattr(session.validation_result, 'applied_strategy'), \
                    "Validation result should have applied_strategy field"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        retransmission_count=st.integers(min_value=0, max_value=10)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_complete_workflow_from_recording_to_verdict(self, domain, strategy, retransmission_count):
        """
        Test the complete workflow from data recording to verdict determination.
        
        For any test execution, the complete workflow should be:
        1. Start test (create session)
        2. Record raw data (retransmissions, responses)
        3. Finalize test (analyze PCAP, validate, determine verdict)
        4. Produce final verdict and report
        
        Validates: Requirements 9.1, 9.2, 9.3, 9.5
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator with mock components
            coordinator = TestResultCoordinator(
                pcap_analyzer=MockPCAPAnalyzer(),
                strategy_validator=MockStrategyValidator()
            )
            
            # Step 1: Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            session = coordinator.get_session(session_id)
            
            assert session is not None, "Session should be created"
            assert session.domain == domain, "Domain should be recorded"
            assert session.strategy_name == strategy, "Strategy should be recorded"
            assert session.verdict is None, "Verdict should not be set yet"
            
            # Step 2: Record raw data
            coordinator.record_retransmission(session_id, retransmission_count)
            coordinator.record_response(session_id, response_status=200, timeout=False)
            
            session = coordinator.get_session(session_id)
            assert session.retransmission_count == retransmission_count, \
                "Retransmission count should be recorded"
            assert session.response_received, "Response should be recorded"
            
            # Step 3: Finalize test
            verdict = coordinator.finalize_test(session_id)
            
            # Step 4: Verify final verdict and report
            session = coordinator.get_session(session_id)
            
            assert session.verdict is not None, "Verdict should be set"
            assert session.verdict == verdict, "Session verdict should match returned verdict"
            assert session.verdict_reason, "Verdict reason should be provided"
            assert session.end_time is not None, "End time should be set"
            
            # Verify verdict matches expected outcome based on retransmissions
            if retransmission_count >= 3:
                assert verdict == TestVerdict.FAIL, \
                    f"High retransmissions ({retransmission_count}) should result in FAIL"
            elif retransmission_count == 0:
                # With response and no retransmissions, should be SUCCESS
                assert verdict == TestVerdict.SUCCESS, \
                    "Zero retransmissions with response should result in SUCCESS"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_session_tracks_all_test_metadata(self, domain, strategy):
        """
        Test that session tracks all required test metadata.
        
        For any test execution, the session should track:
        - Session ID
        - Domain
        - Strategy name
        - PCAP file
        - Start time
        - End time (after finalization)
        
        Validates: Requirements 9.1, 9.5
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator
            coordinator = TestResultCoordinator(
                pcap_analyzer=MockPCAPAnalyzer(),
                strategy_validator=MockStrategyValidator()
            )
            
            # Start test
            start_time_before = time.time()
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            start_time_after = time.time()
            
            # Verify session metadata
            session = coordinator.get_session(session_id)
            
            assert session.session_id == session_id, "Session ID should match"
            assert session.domain == domain, "Domain should be recorded"
            assert session.strategy_name == strategy, "Strategy name should be recorded"
            assert session.pcap_file == pcap_file, "PCAP file should be recorded"
            assert start_time_before <= session.start_time <= start_time_after, \
                "Start time should be recorded"
            assert session.end_time is None, "End time should not be set yet"
            
            # Record data and finalize
            coordinator.record_retransmission(session_id, 0)
            coordinator.record_response(session_id, response_status=200)
            
            end_time_before = time.time()
            coordinator.finalize_test(session_id)
            end_time_after = time.time()
            
            # Verify end time is set
            session = coordinator.get_session(session_id)
            assert session.end_time is not None, "End time should be set after finalization"
            assert end_time_before <= session.end_time <= end_time_after, \
                "End time should be recorded correctly"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name(),
        retransmission_count=st.integers(min_value=0, max_value=2)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_pcap_analysis_is_performed_during_validation(self, domain, strategy, retransmission_count):
        """
        Test that PCAP analysis is performed during validation phase.
        
        For any test execution with low retransmissions, PCAP analysis
        should be performed as part of the validation process.
        
        Validates: Requirements 9.2
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator with mock analyzer
            mock_analyzer = MockPCAPAnalyzer()
            coordinator = TestResultCoordinator(
                pcap_analyzer=mock_analyzer,
                strategy_validator=MockStrategyValidator()
            )
            
            # Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            
            # Record data (low retransmissions to trigger validation)
            coordinator.record_retransmission(session_id, retransmission_count)
            coordinator.record_response(session_id, response_status=200)
            
            # Verify analyzer hasn't been called yet
            assert mock_analyzer.analyze_count == 0, \
                "PCAP analyzer should not be called before finalization"
            
            # Finalize test
            coordinator.finalize_test(session_id)
            
            # Verify analyzer was called during finalization
            assert mock_analyzer.analyze_count == 1, \
                "PCAP analyzer should be called exactly once during finalization"
            
            # Verify PCAP analysis result is stored in session
            session = coordinator.get_session(session_id)
            assert session.pcap_analysis is not None, \
                "PCAP analysis result should be stored in session"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)
    
    @given(
        domain=valid_domain(),
        strategy=valid_strategy_name()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validation_is_performed_after_pcap_analysis(self, domain, strategy):
        """
        Test that strategy validation is performed after PCAP analysis.
        
        For any test execution, validation should occur after PCAP analysis
        and use the PCAP results.
        
        Validates: Requirements 9.2, 9.3
        """
        # Create temporary PCAP file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            pcap_file = f.name
            # Write minimal PCAP data
            f.write(b'\x00' * 100)
        
        try:
            # Create coordinator with mock components
            mock_analyzer = MockPCAPAnalyzer()
            mock_validator = MockStrategyValidator()
            coordinator = TestResultCoordinator(
                pcap_analyzer=mock_analyzer,
                strategy_validator=mock_validator
            )
            
            # Start test
            session_id = coordinator.start_test(domain, strategy, pcap_file)
            
            # Record data (low retransmissions to trigger validation)
            coordinator.record_retransmission(session_id, 0)
            coordinator.record_response(session_id, response_status=200)
            
            # Verify neither component has been called yet
            assert mock_analyzer.analyze_count == 0, \
                "PCAP analyzer should not be called before finalization"
            assert mock_validator.validate_count == 0, \
                "Validator should not be called before finalization"
            
            # Finalize test
            coordinator.finalize_test(session_id)
            
            # Verify both components were called
            assert mock_analyzer.analyze_count == 1, \
                "PCAP analyzer should be called during finalization"
            assert mock_validator.validate_count == 1, \
                "Validator should be called during finalization"
            
            # Verify validation result is stored in session
            session = coordinator.get_session(session_id)
            assert session.validation_result is not None, \
                "Validation result should be stored in session"
        
        finally:
            # Cleanup
            Path(pcap_file).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
