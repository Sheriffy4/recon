"""
Property-based tests for TestVerdict determination logic.

Feature: strategy-testing-production-parity, Property 1: Test verdict matches retransmission count
Validates: Requirements 1.1, 1.2, 8.1, 8.2, 8.5

For any test session, the verdict must accurately reflect the actual connection outcome
based on retransmissions and other evidence.
"""

import time
from typing import Optional
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

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
def session_with_retransmissions(draw):
    """Generate a TestSession with varying retransmission counts."""
    domain = draw(valid_domain())
    strategy = draw(valid_strategy_name())
    session_id = draw(st.text(min_size=10, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))
    
    # Generate retransmission count (0-10)
    retransmission_count = draw(st.integers(min_value=0, max_value=10))
    
    # Generate response status
    response_received = draw(st.booleans())
    response_status = draw(st.one_of(
        st.none(),
        st.integers(min_value=200, max_value=599)
    )) if response_received else None
    
    # Generate timeout status
    timeout = draw(st.booleans())
    
    # If we have retransmissions >= 3, we likely timed out or got no response
    if retransmission_count >= 3:
        # High retransmissions usually mean timeout or no response
        timeout = draw(st.booleans())
        if timeout:
            response_received = False
            response_status = None
    
    session = TestSession(
        session_id=session_id,
        domain=domain,
        strategy_name=strategy,
        pcap_file=f"/tmp/test_{session_id}.pcap",
        start_time=time.time(),
        retransmission_count=retransmission_count,
        response_received=response_received,
        response_status=response_status,
        timeout=timeout
    )
    
    return session


@st.composite
def session_with_pcap_analysis(draw):
    """Generate a TestSession with PCAP analysis results."""
    session = draw(session_with_retransmissions())
    
    # Generate PCAP analysis result
    detected_attacks = draw(st.lists(
        st.sampled_from(['split', 'fake', 'disorder', 'multisplit']),
        min_size=0,
        max_size=4,
        unique=True
    ))
    
    pcap_analysis = PCAPAnalysisResult(
        pcap_file=session.pcap_file,
        packet_count=draw(st.integers(min_value=1, max_value=100)),
        detected_attacks=detected_attacks,
        parameters={'split_pos': draw(st.integers(min_value=1, max_value=10))} if detected_attacks else {},
        analysis_time=draw(st.floats(min_value=0.1, max_value=5.0, allow_nan=False, allow_infinity=False))
    )
    
    session.pcap_analysis = pcap_analysis
    
    return session


@st.composite
def session_with_validation(draw):
    """Generate a TestSession with validation results."""
    session = draw(session_with_pcap_analysis())
    
    # Generate validation result
    all_attacks_applied = draw(st.booleans())
    strategy_match = draw(st.booleans())
    
    validation = ValidationResult(
        is_valid=all_attacks_applied and strategy_match,
        all_attacks_applied=all_attacks_applied,
        declared_strategy=session.strategy_name,
        applied_strategy=session.strategy_name if strategy_match else draw(valid_strategy_name()),
        strategy_match=strategy_match,
        parameters_extracted=draw(st.booleans()),
        parameter_count=draw(st.integers(min_value=0, max_value=10))
    )
    
    session.validation_result = validation
    
    return session


# ============================================================================
# Helper Functions for Verdict Determination
# ============================================================================

def determine_verdict(session: TestSession) -> TestVerdict:
    """
    Determine the verdict for a test session based on evidence.
    
    This implements the decision logic from the design document:
    1. If retransmissions >= 3: FAIL
    2. If timeout or no response: FAIL
    3. If no PCAP: INCONCLUSIVE
    4. If incomplete strategy: PARTIAL_SUCCESS
    5. If declared != applied strategy: MISMATCH
    6. If all checks pass: SUCCESS
    
    Requirements: 1.1, 1.2, 8.1, 8.2, 8.5
    """
    # Priority 1: Retransmissions >= 3 → FAIL
    if session.retransmission_count >= 3:
        return TestVerdict.FAIL
    
    # Priority 2: Timeout or no response → FAIL
    # This must come before PCAP check because timeout is a clear failure
    if session.timeout or (not session.response_received and session.retransmission_count > 0):
        return TestVerdict.FAIL
    
    # Priority 3: No PCAP → INCONCLUSIVE (unless already failed above)
    if session.pcap_analysis is None:
        return TestVerdict.INCONCLUSIVE
    
    # Priority 4: Incomplete strategy → PARTIAL_SUCCESS
    if session.validation_result is not None:
        if not session.validation_result.all_attacks_applied:
            return TestVerdict.PARTIAL_SUCCESS
        
        # Priority 5: Strategy mismatch → MISMATCH
        if not session.validation_result.strategy_match:
            return TestVerdict.MISMATCH
    
    # Priority 6: All checks pass → SUCCESS
    # Must have: no retransmissions, PCAP exists, response received
    if session.retransmission_count == 0 and session.response_received:
        return TestVerdict.SUCCESS
    
    # Default to INCONCLUSIVE if we can't determine
    return TestVerdict.INCONCLUSIVE


# ============================================================================
# Property Tests for Verdict Determination
# ============================================================================

class TestVerdictDeterminationProperty:
    """
    **Feature: strategy-testing-production-parity, Property 1: Test verdict matches retransmission count**
    **Validates: Requirements 1.1, 1.2, 8.1, 8.2, 8.5**
    
    Property: For any test session, if retransmissions >= 3, then the verdict must be FAIL;
    if retransmissions == 0 and response received, then verdict must be SUCCESS.
    """
    
    @given(session=session_with_retransmissions())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_high_retransmissions_always_fail(self, session):
        """
        Test that retransmissions >= 3 always results in FAIL verdict.
        
        For any test session with retransmissions >= 3, the verdict
        must be FAIL regardless of other indicators.
        
        Validates: Requirements 1.2, 8.2
        """
        # Only test sessions with high retransmissions
        assume(session.retransmission_count >= 3)
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.FAIL, \
            f"Session with {session.retransmission_count} retransmissions should have FAIL verdict, got {verdict}"
    
    @given(session=session_with_pcap_analysis())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_zero_retransmissions_with_response_is_success(self, session):
        """
        Test that zero retransmissions with response results in SUCCESS verdict.
        
        For any test session with retransmissions == 0 and response received,
        the verdict must be SUCCESS (assuming PCAP and validation are good).
        
        Validates: Requirements 1.1, 1.3, 8.3
        """
        # Only test sessions with zero retransmissions and response
        assume(session.retransmission_count == 0)
        assume(session.response_received)
        assume(not session.timeout)  # Can't have both response and timeout
        assume(session.pcap_analysis is not None)
        
        # Add validation result indicating success
        session.validation_result = ValidationResult(
            is_valid=True,
            all_attacks_applied=True,
            declared_strategy=session.strategy_name,
            applied_strategy=session.strategy_name,
            strategy_match=True,
            parameters_extracted=True,
            parameter_count=1
        )
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.SUCCESS, \
            f"Session with 0 retransmissions and response should have SUCCESS verdict, got {verdict}"
    
    @given(session=session_with_retransmissions())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_timeout_results_in_fail(self, session):
        """
        Test that timeout results in FAIL verdict.
        
        For any test session that times out, the verdict must be FAIL.
        
        Validates: Requirements 8.4
        """
        # Only test sessions with timeout
        assume(session.timeout)
        assume(session.retransmission_count < 3)  # Test timeout specifically, not retransmissions
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.FAIL, \
            f"Session with timeout should have FAIL verdict, got {verdict}"
    
    @given(session=session_with_retransmissions())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_no_pcap_results_in_inconclusive(self, session):
        """
        Test that missing PCAP results in INCONCLUSIVE verdict.
        
        For any test session without PCAP analysis, the verdict must be INCONCLUSIVE
        (unless retransmissions >= 3 or timeout, which take priority).
        
        Validates: Requirements 6.1
        """
        # Only test sessions without PCAP, low retransmissions, and no timeout
        assume(session.pcap_analysis is None)
        assume(session.retransmission_count < 3)
        assume(not session.timeout)
        # Also exclude cases where we have retransmissions but no response (that's a FAIL)
        assume(session.retransmission_count == 0 or session.response_received)
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.INCONCLUSIVE, \
            f"Session without PCAP should have INCONCLUSIVE verdict, got {verdict}"
    
    @given(session=session_with_validation())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_incomplete_strategy_results_in_partial_success(self, session):
        """
        Test that incomplete strategy application results in PARTIAL_SUCCESS verdict.
        
        For any test session where not all attacks were applied, the verdict
        must be PARTIAL_SUCCESS (unless retransmissions >= 3 or timeout).
        
        Validates: Requirements 2.5, 7.4
        """
        # Only test sessions with incomplete strategy, low retransmissions, and no timeout
        assume(session.retransmission_count < 3)
        assume(not session.timeout)
        assume(session.pcap_analysis is not None)
        assume(session.validation_result is not None)
        assume(not session.validation_result.all_attacks_applied)
        # Must have response to avoid FAIL verdict
        assume(session.response_received or session.retransmission_count == 0)
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.PARTIAL_SUCCESS, \
            f"Session with incomplete strategy should have PARTIAL_SUCCESS verdict, got {verdict}"
    
    @given(session=session_with_validation())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_strategy_mismatch_results_in_mismatch_verdict(self, session):
        """
        Test that strategy mismatch results in MISMATCH verdict.
        
        For any test session where declared strategy != applied strategy,
        the verdict must be MISMATCH (unless retransmissions >= 3, timeout, or incomplete).
        
        Validates: Requirements 2.2, 2.3
        """
        # Only test sessions with strategy mismatch, low retransmissions, and no timeout
        assume(session.retransmission_count < 3)
        assume(not session.timeout)
        assume(session.pcap_analysis is not None)
        assume(session.validation_result is not None)
        assume(session.validation_result.all_attacks_applied)  # Complete, but mismatched
        assume(not session.validation_result.strategy_match)
        # Must have response to avoid FAIL verdict
        assume(session.response_received or session.retransmission_count == 0)
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.MISMATCH, \
            f"Session with strategy mismatch should have MISMATCH verdict, got {verdict}"
    
    @given(session=session_with_retransmissions())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_retransmissions_take_priority_over_other_indicators(self, session):
        """
        Test that retransmissions >= 3 takes priority over all other indicators.
        
        For any test session with retransmissions >= 3, the verdict must be FAIL
        even if PCAP shows success, validation passes, etc.
        
        Validates: Requirements 8.5
        """
        # Only test sessions with high retransmissions
        assume(session.retransmission_count >= 3)
        
        # Add positive indicators that should be overridden
        session.response_received = True
        session.response_status = 200
        session.pcap_analysis = PCAPAnalysisResult(
            pcap_file=session.pcap_file,
            packet_count=10,
            detected_attacks=['split', 'fake'],
            parameters={'split_pos': 3}
        )
        session.validation_result = ValidationResult(
            is_valid=True,
            all_attacks_applied=True,
            declared_strategy=session.strategy_name,
            applied_strategy=session.strategy_name,
            strategy_match=True,
            parameters_extracted=True,
            parameter_count=2
        )
        
        verdict = determine_verdict(session)
        
        assert verdict == TestVerdict.FAIL, \
            f"Session with {session.retransmission_count} retransmissions should have FAIL verdict " \
            f"regardless of other indicators, got {verdict}"
    
    @given(
        retransmission_count=st.integers(min_value=0, max_value=10),
        response_received=st.booleans(),
        has_pcap=st.booleans()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_verdict_is_deterministic(self, retransmission_count, response_received, has_pcap):
        """
        Test that verdict determination is deterministic.
        
        For any given set of inputs, the verdict should always be the same.
        
        Validates: Requirements 1.1, 8.1
        """
        # Create two identical sessions
        session1 = TestSession(
            session_id="test1",
            domain="example.com",
            strategy_name="test_strategy",
            pcap_file="/tmp/test.pcap",
            start_time=time.time(),
            retransmission_count=retransmission_count,
            response_received=response_received,
            timeout=not response_received
        )
        
        session2 = TestSession(
            session_id="test2",
            domain="example.com",
            strategy_name="test_strategy",
            pcap_file="/tmp/test.pcap",
            start_time=time.time(),
            retransmission_count=retransmission_count,
            response_received=response_received,
            timeout=not response_received
        )
        
        if has_pcap:
            pcap1 = PCAPAnalysisResult(
                pcap_file="/tmp/test.pcap",
                packet_count=10,
                detected_attacks=['split'],
                parameters={'split_pos': 3}
            )
            pcap2 = PCAPAnalysisResult(
                pcap_file="/tmp/test.pcap",
                packet_count=10,
                detected_attacks=['split'],
                parameters={'split_pos': 3}
            )
            session1.pcap_analysis = pcap1
            session2.pcap_analysis = pcap2
            
            # Add validation
            val1 = ValidationResult(
                is_valid=True,
                all_attacks_applied=True,
                declared_strategy="test_strategy",
                applied_strategy="test_strategy",
                strategy_match=True,
                parameters_extracted=True,
                parameter_count=1
            )
            val2 = ValidationResult(
                is_valid=True,
                all_attacks_applied=True,
                declared_strategy="test_strategy",
                applied_strategy="test_strategy",
                strategy_match=True,
                parameters_extracted=True,
                parameter_count=1
            )
            session1.validation_result = val1
            session2.validation_result = val2
        
        verdict1 = determine_verdict(session1)
        verdict2 = determine_verdict(session2)
        
        assert verdict1 == verdict2, \
            f"Identical sessions should produce identical verdicts, got {verdict1} and {verdict2}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
