"""
Property-based tests for ConnectionMetrics.

Feature: auto-strategy-discovery
Tests correctness properties for connection metrics collection and evaluation.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.connection_metrics import ConnectionMetrics, BlockType


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_connection_metrics(draw):
    """Generate valid ConnectionMetrics with random values."""
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
# Property Tests for ConnectionMetrics Completeness (Property 1)
# ============================================================================

class TestConnectionMetricsCompleteness:
    """
    **Feature: auto-strategy-discovery, Property 1: ConnectionMetrics completeness**
    **Validates: Requirements 2.1, 2.2, 2.3, 2.8**
    
    Property: For any strategy test execution, the resulting ConnectionMetrics object
    SHALL contain all timing fields (connect_time_ms, tls_time_ms, ttfb_ms, total_time_ms)
    with non-negative values, and block_type SHALL be set to a valid BlockType enum value.
    """
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_all_timing_fields_are_non_negative(self, metrics):
        """
        Test that all timing fields have non-negative values.
        
        For any ConnectionMetrics object, all timing fields should be >= 0.
        """
        assert metrics.connect_time_ms >= 0.0, \
            f"connect_time_ms should be non-negative, got {metrics.connect_time_ms}"
        assert metrics.tls_time_ms >= 0.0, \
            f"tls_time_ms should be non-negative, got {metrics.tls_time_ms}"
        assert metrics.ttfb_ms >= 0.0, \
            f"ttfb_ms should be non-negative, got {metrics.ttfb_ms}"
        assert metrics.total_time_ms >= 0.0, \
            f"total_time_ms should be non-negative, got {metrics.total_time_ms}"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_block_type_is_valid_enum(self, metrics):
        """
        Test that block_type is always a valid BlockType enum value.
        
        For any ConnectionMetrics object, block_type should be one of the
        defined BlockType enum values.
        """
        assert isinstance(metrics.block_type, BlockType), \
            f"block_type should be BlockType enum, got {type(metrics.block_type)}"
        assert metrics.block_type in list(BlockType), \
            f"block_type should be valid BlockType value, got {metrics.block_type}"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_all_required_fields_are_present(self, metrics):
        """
        Test that all required fields are present in ConnectionMetrics.
        
        For any ConnectionMetrics object, all fields defined in the spec
        should be accessible.
        """
        # Тайминги
        assert hasattr(metrics, 'connect_time_ms'), "Should have connect_time_ms field"
        assert hasattr(metrics, 'tls_time_ms'), "Should have tls_time_ms field"
        assert hasattr(metrics, 'ttfb_ms'), "Should have ttfb_ms field"
        assert hasattr(metrics, 'total_time_ms'), "Should have total_time_ms field"
        
        # Результат
        assert hasattr(metrics, 'http_status'), "Should have http_status field"
        assert hasattr(metrics, 'bytes_received'), "Should have bytes_received field"
        assert hasattr(metrics, 'tls_completed'), "Should have tls_completed field"
        
        # Ошибки
        assert hasattr(metrics, 'error'), "Should have error field"
        assert hasattr(metrics, 'rst_received'), "Should have rst_received field"
        assert hasattr(metrics, 'rst_timing_ms'), "Should have rst_timing_ms field"
        assert hasattr(metrics, 'timeout'), "Should have timeout field"
        
        # Классификация
        assert hasattr(metrics, 'block_type'), "Should have block_type field"
        
        # Мета
        assert hasattr(metrics, 'timestamp'), "Should have timestamp field"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_bytes_received_is_non_negative(self, metrics):
        """
        Test that bytes_received is always non-negative.
        
        For any ConnectionMetrics object, bytes_received should be >= 0.
        """
        assert metrics.bytes_received >= 0, \
            f"bytes_received should be non-negative, got {metrics.bytes_received}"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_http_status_is_valid_when_present(self, metrics):
        """
        Test that http_status is in valid range when present.
        
        For any ConnectionMetrics object with http_status set, the value
        should be in the valid HTTP status code range (100-599).
        """
        if metrics.http_status is not None:
            assert 100 <= metrics.http_status <= 599, \
                f"http_status should be in range 100-599, got {metrics.http_status}"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_rst_timing_is_non_negative_when_present(self, metrics):
        """
        Test that rst_timing_ms is non-negative when present.
        
        For any ConnectionMetrics object with rst_timing_ms set, the value
        should be >= 0.
        """
        if metrics.rst_timing_ms is not None:
            assert metrics.rst_timing_ms >= 0.0, \
                f"rst_timing_ms should be non-negative, got {metrics.rst_timing_ms}"
    
    @given(metrics=valid_connection_metrics())
    @settings(max_examples=100)
    def test_timestamp_is_present(self, metrics):
        """
        Test that timestamp is always present and positive.
        
        For any ConnectionMetrics object, timestamp should be set to a
        positive value (Unix timestamp).
        """
        assert metrics.timestamp > 0, \
            f"timestamp should be positive, got {metrics.timestamp}"


# ============================================================================
# Property Tests for is_success() Method
# ============================================================================

class TestConnectionMetricsIsSuccess:
    """
    Tests for the is_success() method of ConnectionMetrics.
    
    These tests verify that the success detection logic correctly identifies
    successful connections that bypassed DPI.
    """
    
    @given(
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        ttfb_ms=st.floats(min_value=0.0, max_value=10000.0, allow_nan=False, allow_infinity=False),
        total_time_ms=st.floats(min_value=0.0, max_value=15000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_timeout_always_means_failure(self, connect_time_ms, tls_time_ms, ttfb_ms, total_time_ms):
        """
        Test that timeout always results in failure.
        
        For any ConnectionMetrics with timeout=True, is_success() should return False.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            ttfb_ms=ttfb_ms,
            total_time_ms=total_time_ms,
            timeout=True
        )
        
        assert metrics.is_success() is False, \
            "Connection with timeout should not be successful"
    
    @given(
        rst_timing_ms=st.floats(min_value=0.0, max_value=99.9, allow_nan=False, allow_infinity=False),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_early_rst_means_failure(self, rst_timing_ms, connect_time_ms):
        """
        Test that RST within 100ms results in failure.
        
        For any ConnectionMetrics with rst_received=True and rst_timing_ms < 100,
        is_success() should return False.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            rst_received=True,
            rst_timing_ms=rst_timing_ms
        )
        
        assert metrics.is_success() is False, \
            f"Connection with RST at {rst_timing_ms}ms should not be successful"
    
    @given(
        http_status=st.integers(min_value=200, max_value=499),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_http_2xx_4xx_means_success(self, http_status, connect_time_ms):
        """
        Test that HTTP status 200-499 results in success.
        
        For any ConnectionMetrics with http_status in range 200-499,
        is_success() should return True (DPI was bypassed).
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            http_status=http_status
        )
        
        assert metrics.is_success() is True, \
            f"Connection with HTTP {http_status} should be successful"
    
    @given(
        bytes_received=st.integers(min_value=1, max_value=100000),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_bytes_received_means_success(self, bytes_received, connect_time_ms):
        """
        Test that receiving bytes results in success.
        
        For any ConnectionMetrics with bytes_received > 0, is_success()
        should return True (data was received, DPI was bypassed).
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            bytes_received=bytes_received
        )
        
        assert metrics.is_success() is True, \
            f"Connection with {bytes_received} bytes received should be successful"
    
    @given(
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_tls_completed_means_success(self, connect_time_ms, tls_time_ms):
        """
        Test that completed TLS handshake results in success.
        
        For any ConnectionMetrics with tls_completed=True, is_success()
        should return True (TLS handshake completed, DPI was bypassed).
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            tls_completed=True
        )
        
        assert metrics.is_success() is True, \
            "Connection with completed TLS should be successful"
    
    def test_no_data_no_tls_means_failure(self):
        """
        Test that no data and no TLS completion results in failure.
        
        For ConnectionMetrics with no timeout, no RST, but also no data,
        no HTTP status, and no TLS completion, is_success() should return False.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            bytes_received=0,
            tls_completed=False,
            http_status=None,
            timeout=False,
            rst_received=False
        )
        
        assert metrics.is_success() is False, \
            "Connection with no data should not be successful"


# ============================================================================
# Property Tests for detect_block_type() Method
# ============================================================================

class TestConnectionMetricsDetectBlockType:
    """
    Tests for the detect_block_type() method of ConnectionMetrics.
    
    These tests verify that block type detection correctly classifies
    different types of DPI blocking.
    """
    
    @given(
        rst_timing_ms=st.floats(min_value=0.0, max_value=99.9, allow_nan=False, allow_infinity=False),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_early_rst_detected_as_active_rst(self, rst_timing_ms, connect_time_ms):
        """
        Test that early RST is classified as ACTIVE_RST.
        
        For any ConnectionMetrics with rst_received=True and rst_timing_ms < 100,
        detect_block_type() should return BlockType.ACTIVE_RST.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            rst_received=True,
            rst_timing_ms=rst_timing_ms
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.ACTIVE_RST, \
            f"RST at {rst_timing_ms}ms should be classified as ACTIVE_RST, got {block_type}"
    
    @given(
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_timeout_with_no_connect_detected_as_ip_block(self, connect_time_ms, tls_time_ms):
        """
        Test that timeout with no TCP connection is classified as IP_BLOCK.
        
        For any ConnectionMetrics with timeout=True and connect_time_ms=0,
        detect_block_type() should return BlockType.IP_BLOCK.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=0.0,
            tls_time_ms=tls_time_ms,
            timeout=True
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.IP_BLOCK, \
            f"Timeout with no connection should be classified as IP_BLOCK, got {block_type}"
    
    @given(
        connect_time_ms=st.floats(min_value=0.1, max_value=5000.0, allow_nan=False, allow_infinity=False),
        tls_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_timeout_after_connect_detected_as_passive_drop(self, connect_time_ms, tls_time_ms):
        """
        Test that timeout after TCP connection is classified as PASSIVE_DROP.
        
        For any ConnectionMetrics with timeout=True and connect_time_ms > 0,
        detect_block_type() should return BlockType.PASSIVE_DROP.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            tls_time_ms=tls_time_ms,
            timeout=True
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.PASSIVE_DROP, \
            f"Timeout after connection should be classified as PASSIVE_DROP, got {block_type}"
    
    @given(
        http_status=st.sampled_from([403, 451]),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_http_403_451_detected_as_http_block(self, http_status, connect_time_ms):
        """
        Test that HTTP 403/451 is classified as HTTP_BLOCK.
        
        For any ConnectionMetrics with http_status=403 or 451,
        detect_block_type() should return BlockType.HTTP_BLOCK.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            http_status=http_status,
            tls_completed=True
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.HTTP_BLOCK, \
            f"HTTP {http_status} should be classified as HTTP_BLOCK, got {block_type}"
    
    @given(
        http_status=st.integers(min_value=200, max_value=499).filter(lambda x: x not in [403, 451]),
        bytes_received=st.integers(min_value=1, max_value=100000),
        connect_time_ms=st.floats(min_value=0.0, max_value=5000.0, allow_nan=False, allow_infinity=False)
    )
    @settings(max_examples=100)
    def test_successful_connection_detected_as_none(self, http_status, bytes_received, connect_time_ms):
        """
        Test that successful connection is classified as NONE.
        
        For any ConnectionMetrics with successful indicators (HTTP 2xx-4xx except 403/451,
        or bytes received), detect_block_type() should return BlockType.NONE.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=connect_time_ms,
            http_status=http_status,
            bytes_received=bytes_received
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.NONE, \
            f"Successful connection should be classified as NONE, got {block_type}"
    
    def test_no_indicators_detected_as_unknown(self):
        """
        Test that connection with no clear indicators is classified as UNKNOWN.
        
        For ConnectionMetrics with no timeout, no RST, no data, and no HTTP status,
        detect_block_type() should return BlockType.UNKNOWN.
        """
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            bytes_received=0,
            tls_completed=False,
            http_status=None,
            timeout=False,
            rst_received=False
        )
        
        block_type = metrics.detect_block_type()
        assert block_type == BlockType.UNKNOWN, \
            f"Connection with no indicators should be classified as UNKNOWN, got {block_type}"
