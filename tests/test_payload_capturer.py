"""
Property-based tests for PayloadCapturer.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 6: Capture Produces Valid TLS**
"""

import asyncio
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.payload.capturer import (
    PayloadCapturer,
    CaptureResult,
    CaptureError,
    CaptureTimeoutError,
    CaptureNetworkError,
)
from core.payload.validator import PayloadValidator
from core.payload.types import PayloadType


class TestCaptureProducesValidTLS:
    """
    Property-based tests for capture validation.
    
    **Feature: fake-payload-generation, Property 6: Capture Produces Valid TLS**
    **Validates: Requirements 2.2, 2.5**
    
    Property: For any successful ClientHello capture, the captured bytes
    MUST pass TLS ClientHello validation.
    """
    
    # Well-known domains that should be accessible for testing
    # These are major sites that are unlikely to block connections
    KNOWN_DOMAINS = [
        "www.google.com",
        "www.cloudflare.com",
        "www.microsoft.com",
    ]
    
    @pytest.mark.asyncio
    @given(domain_idx=st.integers(min_value=0, max_value=2))
    @settings(
        max_examples=3,
        deadline=30000,  # 30 second deadline per test
        suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    async def test_successful_capture_produces_valid_tls(self, domain_idx):
        """
        **Feature: fake-payload-generation, Property 6: Capture Produces Valid TLS**
        **Validates: Requirements 2.2, 2.5**
        
        Property: If capture_clienthello() returns success=True, then the
        captured payload MUST pass TLS ClientHello validation.
        
        This test uses real network connections to verify that captured
        ClientHello packets are structurally valid.
        """
        # Create instances inside test to avoid fixture issues with hypothesis
        capturer = PayloadCapturer(max_retries=1, backoff_base=0.1)
        validator = PayloadValidator()
        
        domain = self.KNOWN_DOMAINS[domain_idx]
        
        result = await capturer.capture_clienthello(domain, timeout=15.0)
        
        # If capture succeeded, payload must be valid TLS
        if result.success:
            assert result.payload is not None, "Successful capture must have payload"
            
            validation = validator.validate_tls_clienthello(result.payload)
            
            # Property: successful capture produces valid TLS
            assert validation.valid, (
                f"Captured ClientHello from {domain} failed validation: "
                f"{validation.errors}"
            )
            assert validation.payload_type == PayloadType.TLS
            
            # Additional structural checks from Property 1
            assert len(result.payload) >= 6, "Valid TLS must have at least 6 bytes"
            assert result.payload[0] == 0x16, "Must start with 0x16 (Handshake)"
            assert result.payload[1] == 0x03, "Must have 0x03 at byte 1 (TLS version)"
            assert result.payload[5] == 0x01, "Must have 0x01 at byte 5 (ClientHello)"
    
    @pytest.mark.asyncio
    async def test_capture_result_consistency(self):
        """
        **Feature: fake-payload-generation, Property 6: Capture Produces Valid TLS**
        **Validates: Requirements 2.2, 2.5**
        
        Property: CaptureResult fields must be consistent:
        - If success=True, payload must not be None
        - If success=False, error should explain why
        """
        capturer = PayloadCapturer(max_retries=1, backoff_base=0.1)
        
        # Test with a known good domain
        result = await capturer.capture_clienthello("www.google.com", timeout=15.0)
        
        if result.success:
            assert result.payload is not None
            assert result.error is None
            assert len(result.payload) > 0
        else:
            # If failed, should have error message
            assert result.error is not None or result.payload is None
    
    @pytest.mark.asyncio
    async def test_capture_domain_normalization(self):
        """
        **Feature: fake-payload-generation, Property 6: Capture Produces Valid TLS**
        **Validates: Requirements 2.2, 2.5**
        
        Property: Domain normalization should not affect capture validity.
        Various domain formats should produce valid TLS if successful.
        """
        capturer = PayloadCapturer(max_retries=1, backoff_base=0.1)
        validator = PayloadValidator()
        
        # Test domain with https:// prefix
        result = await capturer.capture_clienthello(
            "https://www.google.com", timeout=15.0
        )
        
        if result.success:
            validation = validator.validate_tls_clienthello(result.payload)
            assert validation.valid, "Captured payload must be valid TLS"
    
    @pytest.mark.asyncio
    async def test_retry_logic_respects_max_retries(self):
        """
        Test that retry logic respects max_retries setting.
        
        **Validates: Requirements 2.3**
        """
        capturer = PayloadCapturer(max_retries=2, backoff_base=0.1)
        
        # Use an invalid domain that will fail
        result = await capturer.capture_clienthello(
            "invalid.domain.that.does.not.exist.example",
            timeout=2.0
        )
        
        assert not result.success
        assert result.attempts <= capturer.max_retries
        assert result.error is not None


class TestCaptureResultDataclass:
    """Tests for CaptureResult dataclass behavior."""
    
    @given(
        success=st.booleans(),
        domain=st.text(min_size=1, max_size=50).filter(lambda x: x.strip()),
        attempts=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=50)
    def test_capture_result_fields(self, success, domain, attempts):
        """
        Property: CaptureResult should correctly store all fields.
        """
        payload = b"\x16\x03\x01\x00\x05\x01" if success else None
        error = None if success else "Test error"
        
        result = CaptureResult(
            success=success,
            payload=payload,
            domain=domain,
            error=error,
            attempts=attempts
        )
        
        assert result.success == success
        assert result.domain == domain
        assert result.attempts == attempts
        
        if success:
            assert result.payload is not None
        else:
            assert result.error is not None or result.payload is None


class TestHTTPCapture:
    """Tests for HTTP request capture."""
    
    # Strategy for generating valid domain names
    @staticmethod
    def domain_strategy():
        """Generate valid domain names."""
        return st.from_regex(
            r'[a-z][a-z0-9]{1,10}\.[a-z]{2,4}',
            fullmatch=True
        )
    
    @pytest.mark.asyncio
    @given(
        domain=st.sampled_from([
            "example.com",
            "test.org",
            "google.com",
            "cloudflare.com",
        ]),
        path=st.sampled_from(["/", "/index.html", "/api/test", "/path/to/resource"])
    )
    @settings(
        max_examples=20,
        suppress_health_check=[
            HealthCheck.function_scoped_fixture,
            HealthCheck.filter_too_much
        ]
    )
    async def test_http_capture_produces_valid_http(self, domain, path):
        """
        Property: HTTP capture should produce valid HTTP request format.
        """
        capturer = PayloadCapturer()
        validator = PayloadValidator()
        
        result = await capturer.capture_http_request(domain, path=path)
        
        if result.success:
            assert result.payload is not None
            
            validation = validator.validate_http_request(result.payload)
            assert validation.valid, f"HTTP request invalid: {validation.errors}"
            assert validation.payload_type == PayloadType.HTTP
            
            # Check that domain is in Host header
            assert domain.encode() in result.payload


class TestCapturerConfiguration:
    """Tests for PayloadCapturer configuration."""
    
    @given(
        max_retries=st.integers(min_value=1, max_value=10),
        backoff_base=st.floats(min_value=0.1, max_value=5.0)
    )
    @settings(max_examples=20)
    def test_capturer_configuration(self, max_retries, backoff_base):
        """
        Property: PayloadCapturer should accept valid configuration.
        """
        capturer = PayloadCapturer(
            max_retries=max_retries,
            backoff_base=backoff_base
        )
        
        assert capturer.max_retries == max_retries
        assert capturer.backoff_base == backoff_base
    
    @given(attempt=st.integers(min_value=0, max_value=5))
    @settings(max_examples=20)
    def test_exponential_backoff_calculation(self, attempt):
        """
        Property: Backoff should follow exponential formula.
        """
        base = 1.0
        capturer = PayloadCapturer(backoff_base=base)
        
        expected = base * (2 ** attempt)
        actual = capturer._calculate_backoff(attempt)
        
        assert actual == expected, f"Backoff for attempt {attempt} should be {expected}"
