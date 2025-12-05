"""
Property-based tests for save blocking logic.

Feature: strategy-testing-production-parity, Property 2: Failed tests are never saved
Validates: Requirements 1.4, 1.5, 9.4

For any test session with verdict != SUCCESS, the strategy must not be saved
to any storage location.
"""

import time
import tempfile
from pathlib import Path
from unittest.mock import Mock
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
def session_with_specific_verdict(draw, verdict: TestVerdict):
    """Generate a TestSession with a specific verdict."""
    domain = draw(valid_domain())
    strategy = draw(valid_strategy_name())
    session_id = draw(st.text(min_size=10, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))
    
    session = TestSession(
        session_id=session_id,
        domain=domain,
        strategy_name=strategy,
        pcap_file=f"/tmp/test_{session_id}.pcap",
        start_time=time.time(),
        verdict=verdict
    )
    
    # Set appropriate evidence based on verdict
    if verdict == TestVerdict.FAIL:
        session.retransmission_count = draw(st.integers(min_value=3, max_value=10))
    elif verdict == TestVerdict.SUCCESS:
        session.retransmission_count = 0
        session.response_received = True
        session.response_status = 200
    elif verdict == TestVerdict.PARTIAL_SUCCESS:
        session.retransmission_count = draw(st.integers(min_value=0, max_value=2))
        session.response_received = True
    elif verdict == TestVerdict.MISMATCH:
        session.retransmission_count = draw(st.integers(min_value=0, max_value=2))
        session.response_received = True
    elif verdict == TestVerdict.INCONCLUSIVE:
        session.retransmission_count = draw(st.integers(min_value=0, max_value=2))
    
    return session


@st.composite
def failed_test_session(draw):
    """Generate a TestSession with a non-SUCCESS verdict."""
    verdict = draw(st.sampled_from([
        TestVerdict.FAIL,
        TestVerdict.PARTIAL_SUCCESS,
        TestVerdict.MISMATCH,
        TestVerdict.INCONCLUSIVE
    ]))
    
    return draw(session_with_specific_verdict(verdict=verdict))


@st.composite
def successful_test_session(draw):
    """Generate a TestSession with SUCCESS verdict."""
    return draw(session_with_specific_verdict(verdict=TestVerdict.SUCCESS))


# ============================================================================
# Property Tests for Save Blocking
# ============================================================================

class TestSaveBlockingProperty:
    """
    **Feature: strategy-testing-production-parity, Property 2: Failed tests are never saved**
    **Validates: Requirements 1.4, 1.5, 9.4**
    
    Property: For any test session with verdict != SUCCESS, the strategy must not be saved
    to any storage location (adaptive_knowledge.json, domain_rules.json, domain_strategies.json).
    """
    
    @given(session=failed_test_session())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_failed_tests_are_blocked_from_saving(self, session):
        """
        Test that failed tests are blocked from saving.
        
        For any test session with verdict != SUCCESS, should_save_strategy()
        must return False.
        
        Validates: Requirements 1.4, 1.5, 9.4
        """
        # Ensure verdict is not SUCCESS
        assume(session.verdict != TestVerdict.SUCCESS)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with verdict {session.verdict} should not be saved, but should_save returned True"
    
    @given(session=successful_test_session())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_successful_tests_are_approved_for_saving(self, session):
        """
        Test that successful tests are approved for saving.
        
        For any test session with verdict == SUCCESS, should_save_strategy()
        must return True.
        
        Validates: Requirements 1.4, 9.4
        """
        # Ensure verdict is SUCCESS
        assume(session.verdict == TestVerdict.SUCCESS)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert should_save, \
            f"Strategy with verdict SUCCESS should be saved, but should_save returned False"
    
    @given(
        verdict=st.sampled_from([
            TestVerdict.FAIL,
            TestVerdict.PARTIAL_SUCCESS,
            TestVerdict.MISMATCH,
            TestVerdict.INCONCLUSIVE
        ])
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_all_non_success_verdicts_block_saving(self, verdict):
        """
        Test that all non-SUCCESS verdicts block saving.
        
        For any verdict that is not SUCCESS (FAIL, PARTIAL_SUCCESS, MISMATCH, INCONCLUSIVE),
        should_save_strategy() must return False.
        
        Validates: Requirements 1.4, 1.5, 9.4
        """
        # Create a test session with the given verdict
        session = TestSession(
            session_id="test_session",
            domain="example.com",
            strategy_name="test_strategy",
            pcap_file="/tmp/test.pcap",
            start_time=time.time(),
            verdict=verdict
        )
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with verdict {verdict} should not be saved, but should_save returned True"
    
    @given(session=failed_test_session())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_save_blocking_is_consistent(self, session):
        """
        Test that save blocking is consistent across multiple calls.
        
        For any failed test session, multiple calls to should_save_strategy()
        should always return False.
        
        Validates: Requirements 1.4, 9.4
        """
        # Ensure verdict is not SUCCESS
        assume(session.verdict != TestVerdict.SUCCESS)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Call should_save_strategy multiple times
        results = []
        for i in range(5):
            should_save = coordinator.should_save_strategy(session.session_id)
            results.append(should_save)
        
        # All results should be False
        assert all(not result for result in results), \
            f"All calls to should_save_strategy for failed test should return False, got {results}"
    
    @given(
        fail_session=failed_test_session(),
        success_session=successful_test_session()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_save_approval_is_session_specific(self, fail_session, success_session):
        """
        Test that save approval is session-specific.
        
        For any two sessions with different verdicts, should_save_strategy()
        should return different results based on each session's verdict.
        
        Validates: Requirements 9.4
        """
        # Ensure sessions have different verdicts
        assume(fail_session.verdict != TestVerdict.SUCCESS)
        assume(success_session.verdict == TestVerdict.SUCCESS)
        assume(fail_session.session_id != success_session.session_id)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add both sessions to coordinator
        coordinator.test_sessions[fail_session.session_id] = fail_session
        coordinator.test_sessions[success_session.session_id] = success_session
        
        # Check save approval for both sessions
        should_save_fail = coordinator.should_save_strategy(fail_session.session_id)
        should_save_success = coordinator.should_save_strategy(success_session.session_id)
        
        assert not should_save_fail, \
            f"Failed session should not be approved for saving"
        assert should_save_success, \
            f"Successful session should be approved for saving"
    
    @given(session=failed_test_session())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_unknown_session_returns_false(self, session):
        """
        Test that unknown session IDs return False.
        
        For any session ID that doesn't exist in the coordinator,
        should_save_strategy() should return False (safe default).
        
        Validates: Requirements 9.4
        """
        # Create coordinator without adding the session
        coordinator = TestResultCoordinator()
        
        # Try to check save approval for non-existent session
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Unknown session should not be approved for saving, but should_save returned True"
    
    @given(
        retransmission_count=st.integers(min_value=3, max_value=10)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_high_retransmissions_block_saving(self, retransmission_count):
        """
        Test that high retransmissions block saving.
        
        For any test session with retransmissions >= 3, the verdict should be FAIL
        and the strategy should not be saved.
        
        Validates: Requirements 1.2, 1.4
        """
        # Create a test session with high retransmissions
        session = TestSession(
            session_id="test_session",
            domain="example.com",
            strategy_name="test_strategy",
            pcap_file="/tmp/test.pcap",
            start_time=time.time(),
            retransmission_count=retransmission_count,
            verdict=TestVerdict.FAIL  # High retransmissions should result in FAIL
        )
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with {retransmission_count} retransmissions should not be saved, " \
            f"but should_save returned True"
    
    @given(session=session_with_specific_verdict(verdict=TestVerdict.PARTIAL_SUCCESS))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_partial_success_blocks_saving(self, session):
        """
        Test that PARTIAL_SUCCESS verdict blocks saving.
        
        For any test session with PARTIAL_SUCCESS verdict (incomplete strategy),
        the strategy should not be saved.
        
        Validates: Requirements 1.5, 9.4
        """
        # Ensure verdict is PARTIAL_SUCCESS
        assume(session.verdict == TestVerdict.PARTIAL_SUCCESS)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with PARTIAL_SUCCESS verdict should not be saved, but should_save returned True"
    
    @given(session=session_with_specific_verdict(verdict=TestVerdict.MISMATCH))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_blocks_saving(self, session):
        """
        Test that MISMATCH verdict blocks saving.
        
        For any test session with MISMATCH verdict (declared != applied),
        the strategy should not be saved.
        
        Validates: Requirements 1.5, 9.4
        """
        # Ensure verdict is MISMATCH
        assume(session.verdict == TestVerdict.MISMATCH)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with MISMATCH verdict should not be saved, but should_save returned True"
    
    @given(session=session_with_specific_verdict(verdict=TestVerdict.INCONCLUSIVE))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_inconclusive_blocks_saving(self, session):
        """
        Test that INCONCLUSIVE verdict blocks saving.
        
        For any test session with INCONCLUSIVE verdict (cannot determine),
        the strategy should not be saved.
        
        Validates: Requirements 1.5, 9.4
        """
        # Ensure verdict is INCONCLUSIVE
        assume(session.verdict == TestVerdict.INCONCLUSIVE)
        
        # Create coordinator
        coordinator = TestResultCoordinator()
        
        # Add session to coordinator
        coordinator.test_sessions[session.session_id] = session
        
        # Check if strategy should be saved
        should_save = coordinator.should_save_strategy(session.session_id)
        
        assert not should_save, \
            f"Strategy with INCONCLUSIVE verdict should not be saved, but should_save returned True"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
