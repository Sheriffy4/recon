"""
Property-based tests for StrategyEvaluator.

Feature: auto-strategy-discovery
Tests correctness properties for strategy evaluation logic.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.connection_metrics import ConnectionMetrics, BlockType
from core.strategy_evaluator import StrategyEvaluator, EvaluationResult


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def connection_metrics_for_evaluation(draw):
    """Generate ConnectionMetrics suitable for evaluation testing."""
    # Тайминги (неотрицательные)
    connect_time_ms = draw(st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False))
    tls_time_ms = draw(st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False))
    ttfb_ms = draw(st.floats(min_value=0.0, max_value=30000.0, allow_nan=False, allow_infinity=False))
    total_time_ms = draw(st.floats(min_value=0.0, max_value=30000.0, allow_nan=False, allow_infinity=False))
    
    # Результат
    http_status = draw(st.one_of(st.none(), st.integers(min_value=100, max_value=599)))
    bytes_received = draw(st.integers(min_value=0, max_value=1000000))
    tls_completed = draw(st.booleans())
    
    # Ошибки
    error = draw(st.one_of(st.none(), st.text(min_size=1, max_size=100)))
    rst_received = draw(st.booleans())
    rst_timing_ms = draw(st.one_of(
        st.none(),
        st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False)
    ))
    timeout = draw(st.booleans())
    
    # Классификация
    block_type = draw(st.sampled_from(list(BlockType)))
    
    return ConnectionMetrics(
        connect_time_ms=connect_time_ms,
        tls_time_ms=tls_time_ms,
        ttfb_ms=ttfb_ms,
        total_time_ms=total_time_ms,
        http_status=http_status,
        bytes_received=bytes_received,
        tls_completed=tls_completed,
        error=error,
        rst_received=rst_received,
        rst_timing_ms=rst_timing_ms,
        timeout=timeout,
        block_type=block_type
    )


# ============================================================================
# Property Tests for StrategyEvaluator Consistency (Property 2)
# ============================================================================

class TestStrategyEvaluatorConsistency:
    """
    **Feature: auto-strategy-discovery, Property 2: StrategyEvaluator consistency**
    **Validates: Requirements 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    
    Property: For any ConnectionMetrics input, StrategyEvaluator.evaluate() SHALL return:
    - success=False with block_type=PASSIVE_DROP when timeout=True (Req 3.2)
    - success=False with block_type=ACTIVE_RST when rst_received=True and rst_timing_ms < 100 (Req 3.3)
    - success=True when http_status is in range 200-499 (Req 3.4)
    - success=True with block_type=HTTP_BLOCK when http_status is 403 or 451 (Req 3.5)
    - success=True when bytes_received > 0 and http_status is None (Req 3.6)
    - success=True with confidence=0.8 when tls_completed=True (Req 3.7)
    """
    
    @given(
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        ttfb_ms=st.floats(min_value=0.0, max_value=30000.0, allow_nan=False, allow_infinity=False),
        total_time_ms=st.floats(min_value=0.0, max_value=30000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_timeout_returns_passive_drop(self, connect_time_ms, tls_time_ms, ttfb_ms, total_time_ms):
        """
        Test Requirement 3.2: Timeout -> success=False, block_type=PASSIVE_DROP
        
        For any ConnectionMetrics with timeout=True, StrategyEvaluator.evaluate()
        should return success=False and block_type=PASSIVE_DROP.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            ttfb_ms=ttfb_ms,
            total_time_ms=total_time_ms,
            timeout=True
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is False, \
            "Timeout should result in failure"
        assert result.block_type == BlockType.PASSIVE_DROP, \
            f"Timeout should be classified as PASSIVE_DROP, got {result.block_type}"
        assert result.confidence == 1.0, \
            "Timeout detection should have confidence 1.0"
    
    @given(
        rst_timing_ms=st.floats(min_value=0.0, max_value=99.9, allow_nan=False, allow_infinity=False),
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_early_rst_returns_active_rst(self, rst_timing_ms, connect_time_ms, tls_time_ms):
        """
        Test Requirement 3.3: RST < 100ms -> success=False, block_type=ACTIVE_RST
        
        For any ConnectionMetrics with rst_received=True and rst_timing_ms < 100,
        StrategyEvaluator.evaluate() should return success=False and block_type=ACTIVE_RST.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            rst_received=True,
            rst_timing_ms=rst_timing_ms,
            timeout=False  # Ensure timeout doesn't override
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is False, \
            f"RST at {rst_timing_ms}ms should result in failure"
        assert result.block_type == BlockType.ACTIVE_RST, \
            f"Early RST should be classified as ACTIVE_RST, got {result.block_type}"
        assert result.confidence == 1.0, \
            "Early RST detection should have confidence 1.0"
    
    @given(
        http_status=st.integers(min_value=200, max_value=499).filter(lambda x: x not in [403, 451]),
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        bytes_received=st.integers(min_value=0, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_http_2xx_4xx_returns_success(self, http_status, connect_time_ms, bytes_received):
        """
        Test Requirement 3.4: HTTP 200-499 (except 403/451) -> success=True
        
        For any ConnectionMetrics with http_status in range 200-499 (excluding 403/451),
        StrategyEvaluator.evaluate() should return success=True.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            http_status=http_status,
            bytes_received=bytes_received,
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            f"HTTP {http_status} should result in success (DPI bypassed)"
        assert result.block_type == BlockType.NONE, \
            f"Successful HTTP response should have block_type=NONE, got {result.block_type}"
        assert result.confidence == 1.0, \
            "HTTP status detection should have confidence 1.0"
    
    @given(
        http_status=st.sampled_from([403, 451]),
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tls_completed=st.booleans()
    )
    @settings(max_examples=100)
    def test_http_403_451_returns_success_with_http_block(self, http_status, connect_time_ms, tls_completed):
        """
        Test Requirement 3.5: HTTP 403/451 -> success=True, block_type=HTTP_BLOCK
        
        For any ConnectionMetrics with http_status=403 or 451,
        StrategyEvaluator.evaluate() should return success=True with block_type=HTTP_BLOCK
        (DPI bypassed, but server-level block).
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            http_status=http_status,
            tls_completed=tls_completed,
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            f"HTTP {http_status} should result in success (DPI bypassed, server blocked)"
        assert result.block_type == BlockType.HTTP_BLOCK, \
            f"HTTP {http_status} should have block_type=HTTP_BLOCK, got {result.block_type}"
        assert result.confidence == 1.0, \
            "HTTP 403/451 detection should have confidence 1.0"
    
    @given(
        bytes_received=st.integers(min_value=1, max_value=1000000),
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_bytes_received_without_http_status_returns_success(self, bytes_received, connect_time_ms, tls_time_ms):
        """
        Test Requirement 3.6: bytes_received > 0 without HTTP status -> success=True
        
        For any ConnectionMetrics with bytes_received > 0 and http_status=None,
        StrategyEvaluator.evaluate() should return success=True.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            bytes_received=bytes_received,
            http_status=None,  # No HTTP status
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            f"Receiving {bytes_received} bytes should result in success"
        assert result.block_type == BlockType.NONE, \
            f"Bytes received should have block_type=NONE, got {result.block_type}"
        assert result.confidence == 0.9, \
            "Bytes received without HTTP status should have confidence 0.9"
    
    @given(
        connect_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_tls_completed_returns_success_with_confidence_08(self, connect_time_ms, tls_time_ms):
        """
        Test Requirement 3.7: tls_completed=True -> success=True, confidence=0.8
        
        For any ConnectionMetrics with tls_completed=True (and no other success indicators),
        StrategyEvaluator.evaluate() should return success=True with confidence=0.8.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            tls_completed=True,
            bytes_received=0,  # No bytes
            http_status=None,  # No HTTP status
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            "TLS completion should result in success"
        assert result.block_type == BlockType.NONE, \
            f"TLS completion should have block_type=NONE, got {result.block_type}"
        assert result.confidence == 0.8, \
            f"TLS completion should have confidence 0.8, got {result.confidence}"


# ============================================================================
# Property Tests for Evaluation Priority
# ============================================================================

class TestStrategyEvaluatorPriority:
    """
    Tests for evaluation priority order.
    
    These tests verify that StrategyEvaluator applies evaluation rules
    in the correct priority order (timeout > RST > HTTP status > bytes > TLS).
    """
    
    @given(
        http_status=st.integers(min_value=200, max_value=499),
        bytes_received=st.integers(min_value=1, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_timeout_overrides_success_indicators(self, http_status, bytes_received):
        """
        Test that timeout takes priority over success indicators.
        
        Even if HTTP status and bytes indicate success, timeout should
        result in failure with PASSIVE_DROP.
        """
        metrics = ConnectionMetrics(
            http_status=http_status,
            bytes_received=bytes_received,
            tls_completed=True,
            timeout=True  # Timeout overrides everything
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is False, \
            "Timeout should override success indicators"
        assert result.block_type == BlockType.PASSIVE_DROP, \
            "Timeout should result in PASSIVE_DROP"
    
    @given(
        rst_timing_ms=st.floats(min_value=0.0, max_value=99.9, allow_nan=False, allow_infinity=False),
        http_status=st.integers(min_value=200, max_value=499),
        bytes_received=st.integers(min_value=1, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_early_rst_overrides_success_indicators(self, rst_timing_ms, http_status, bytes_received):
        """
        Test that early RST takes priority over success indicators.
        
        Even if HTTP status and bytes indicate success, early RST should
        result in failure with ACTIVE_RST.
        """
        metrics = ConnectionMetrics(
            rst_received=True,
            rst_timing_ms=rst_timing_ms,
            http_status=http_status,
            bytes_received=bytes_received,
            tls_completed=True,
            timeout=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is False, \
            "Early RST should override success indicators"
        assert result.block_type == BlockType.ACTIVE_RST, \
            "Early RST should result in ACTIVE_RST"
    
    @given(
        http_status=st.sampled_from([403, 451]),
        bytes_received=st.integers(min_value=1, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_http_403_451_takes_priority_over_bytes(self, http_status, bytes_received):
        """
        Test that HTTP 403/451 takes priority over bytes received.
        
        When both HTTP 403/451 and bytes are present, the result should
        be HTTP_BLOCK (not NONE).
        """
        metrics = ConnectionMetrics(
            http_status=http_status,
            bytes_received=bytes_received,
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            "HTTP 403/451 should still indicate DPI bypass success"
        assert result.block_type == BlockType.HTTP_BLOCK, \
            f"HTTP {http_status} should result in HTTP_BLOCK, not NONE"
    
    @given(
        http_status=st.integers(min_value=200, max_value=499).filter(lambda x: x not in [403, 451]),
        bytes_received=st.integers(min_value=1, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_http_status_takes_priority_over_bytes(self, http_status, bytes_received):
        """
        Test that HTTP status takes priority over bytes received.
        
        When both HTTP status and bytes are present, the evaluation should
        use HTTP status (confidence 1.0) rather than bytes (confidence 0.9).
        """
        metrics = ConnectionMetrics(
            http_status=http_status,
            bytes_received=bytes_received,
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            "HTTP status should indicate success"
        assert result.confidence == 1.0, \
            "HTTP status should have higher confidence (1.0) than bytes alone (0.9)"
    
    @given(
        bytes_received=st.integers(min_value=1, max_value=1000000)
    )
    @settings(max_examples=100)
    def test_bytes_takes_priority_over_tls(self, bytes_received):
        """
        Test that bytes received takes priority over TLS completion.
        
        When both bytes and TLS completion are present, the evaluation should
        use bytes (confidence 0.9) rather than TLS alone (confidence 0.8).
        """
        metrics = ConnectionMetrics(
            bytes_received=bytes_received,
            tls_completed=True,
            http_status=None,
            timeout=False,
            rst_received=False
        )
        
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.success is True, \
            "Bytes received should indicate success"
        assert result.confidence == 0.9, \
            "Bytes should have higher confidence (0.9) than TLS alone (0.8)"


# ============================================================================
# Property Tests for EvaluationResult Structure
# ============================================================================

class TestEvaluationResultStructure:
    """
    Tests for EvaluationResult dataclass structure.
    
    These tests verify that EvaluationResult always contains the required fields.
    """
    
    @given(metrics=connection_metrics_for_evaluation())
    @settings(max_examples=100)
    def test_evaluation_result_has_all_fields(self, metrics):
        """
        Test that EvaluationResult always contains all required fields.
        
        For any ConnectionMetrics input, the resulting EvaluationResult should
        have success, block_type, reason, and confidence fields.
        """
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert hasattr(result, 'success'), "Result should have 'success' field"
        assert hasattr(result, 'block_type'), "Result should have 'block_type' field"
        assert hasattr(result, 'reason'), "Result should have 'reason' field"
        assert hasattr(result, 'confidence'), "Result should have 'confidence' field"
        
        assert isinstance(result.success, bool), "success should be boolean"
        assert isinstance(result.block_type, BlockType), "block_type should be BlockType enum"
        assert isinstance(result.reason, str), "reason should be string"
        assert isinstance(result.confidence, float), "confidence should be float"
    
    @given(metrics=connection_metrics_for_evaluation())
    @settings(max_examples=100)
    def test_confidence_is_in_valid_range(self, metrics):
        """
        Test that confidence is always in range 0.0-1.0.
        
        For any ConnectionMetrics input, the resulting EvaluationResult should
        have confidence in the range [0.0, 1.0].
        """
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert 0.0 <= result.confidence <= 1.0, \
            f"Confidence should be in range [0.0, 1.0], got {result.confidence}"
    
    @given(metrics=connection_metrics_for_evaluation())
    @settings(max_examples=100)
    def test_reason_is_non_empty(self, metrics):
        """
        Test that reason is always a non-empty string.
        
        For any ConnectionMetrics input, the resulting EvaluationResult should
        have a non-empty reason string explaining the evaluation.
        """
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert len(result.reason) > 0, \
            "Reason should be non-empty string"
    
    @given(metrics=connection_metrics_for_evaluation())
    @settings(max_examples=100)
    def test_block_type_is_valid_enum(self, metrics):
        """
        Test that block_type is always a valid BlockType enum value.
        
        For any ConnectionMetrics input, the resulting EvaluationResult should
        have a valid BlockType enum value.
        """
        evaluator = StrategyEvaluator()
        result = evaluator.evaluate(metrics)
        
        assert result.block_type in list(BlockType), \
            f"block_type should be valid BlockType enum, got {result.block_type}"
