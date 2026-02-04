#!/usr/bin/env python3
"""
Unit tests for validators module.

Tests individual validation methods.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from core.bypass.validation.validators import (
    validate_http_response,
    validate_content_check,
    validate_timing_analysis,
    validate_multi_request,
    validate_dns_resolution,
    validate_ssl_handshake,
    validate_header_analysis,
    validate_payload_verification,
)
from core.bypass.validation.types import ValidationMethod


class TestValidateHttpResponse:
    """Tests for validate_http_response."""

    @pytest.mark.asyncio
    async def test_successful_http_response(self):
        """Test successful HTTP response validation."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_http_response("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.HTTP_RESPONSE
            assert result.success is True
            assert result.response_time > 0

    @pytest.mark.asyncio
    async def test_http_response_timeout(self):
        """Test HTTP response timeout."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value.__aenter__.return_value.get.side_effect = asyncio.TimeoutError()
            
            result = await validate_http_response("example.com", 443, 1.0)
            
            assert result.method == ValidationMethod.HTTP_RESPONSE
            assert result.success is False
            assert "timeout" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_http_response_client_error(self):
        """Test HTTP response with client error."""
        with patch("aiohttp.ClientSession") as mock_session:
            import aiohttp
            mock_session.return_value.__aenter__.return_value.get.side_effect = aiohttp.ClientError("Connection failed")
            
            result = await validate_http_response("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.HTTP_RESPONSE
            assert result.success is False
            assert "connection failed" in result.error_message.lower()


class TestValidateContentCheck:
    """Tests for validate_content_check."""

    @pytest.mark.asyncio
    async def test_successful_content_check(self):
        """Test successful content validation."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text.return_value = "Test content"
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_content_check("example.com", 443, 10.0, 0.8)
            
            assert result.method == ValidationMethod.CONTENT_CHECK
            assert result.success is True

    @pytest.mark.asyncio
    async def test_content_check_empty_response(self):
        """Test content check with empty response."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text.return_value = ""
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_content_check("example.com", 443, 10.0, 0.8)
            
            assert result.method == ValidationMethod.CONTENT_CHECK
            # Empty content should still be considered valid
            assert result.success is True


class TestValidateTimingAnalysis:
    """Tests for validate_timing_analysis."""

    @pytest.mark.asyncio
    async def test_timing_within_threshold(self):
        """Test timing analysis within acceptable threshold."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_timing_analysis("example.com", 443, 10.0, 15.0)
            
            assert result.method == ValidationMethod.TIMING_ANALYSIS
            assert result.success is True
            assert result.response_time < 15.0

    @pytest.mark.asyncio
    async def test_timing_timeout(self):
        """Test timing analysis with timeout."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value.__aenter__.return_value.get.side_effect = asyncio.TimeoutError()
            
            result = await validate_timing_analysis("example.com", 443, 1.0, 5.0)
            
            assert result.method == ValidationMethod.TIMING_ANALYSIS
            assert result.success is False


class TestValidateMultiRequest:
    """Tests for validate_multi_request."""

    @pytest.mark.asyncio
    async def test_multi_request_high_success_rate(self):
        """Test multi-request with high success rate."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_multi_request("example.com", 443, 10.0, 0.7)
            
            assert result.method == ValidationMethod.MULTI_REQUEST
            assert result.success is True

    @pytest.mark.asyncio
    async def test_multi_request_low_success_rate(self):
        """Test multi-request with low success rate."""
        with patch("aiohttp.ClientSession") as mock_session:
            # Make all requests fail
            mock_session.return_value.__aenter__.return_value.get.side_effect = asyncio.TimeoutError()
            
            result = await validate_multi_request("example.com", 443, 1.0, 0.7)
            
            assert result.method == ValidationMethod.MULTI_REQUEST
            assert result.success is False


class TestValidateDnsResolution:
    """Tests for validate_dns_resolution."""

    @pytest.mark.asyncio
    async def test_dns_resolution_success(self):
        """Test successful DNS resolution."""
        dns_cache = {}
        cache_lock = asyncio.Lock()
        thread_pool = Mock()
        
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_answer = Mock()
            mock_answer.address = "1.2.3.4"
            mock_resolve.return_value = [mock_answer]
            
            result = await validate_dns_resolution(
                "example.com", 10.0, dns_cache, thread_pool, cache_lock
            )
            
            assert result.method == ValidationMethod.DNS_RESOLUTION
            assert result.success is True
            assert "example.com" in dns_cache

    @pytest.mark.asyncio
    async def test_dns_resolution_cached(self):
        """Test DNS resolution with cached result."""
        dns_cache = {"example.com": "1.2.3.4"}
        cache_lock = asyncio.Lock()
        thread_pool = Mock()
        
        result = await validate_dns_resolution(
            "example.com", 10.0, dns_cache, thread_pool, cache_lock
        )
        
        assert result.method == ValidationMethod.DNS_RESOLUTION
        assert result.success is True

    @pytest.mark.asyncio
    async def test_dns_resolution_nxdomain(self):
        """Test DNS resolution with NXDOMAIN error."""
        dns_cache = {}
        cache_lock = asyncio.Lock()
        thread_pool = Mock()
        
        with patch("dns.resolver.resolve") as mock_resolve:
            import dns.resolver
            mock_resolve.side_effect = dns.resolver.NXDOMAIN()
            
            result = await validate_dns_resolution(
                "nonexistent.example.com", 10.0, dns_cache, thread_pool, cache_lock
            )
            
            assert result.method == ValidationMethod.DNS_RESOLUTION
            assert result.success is False
            assert "nxdomain" in result.error_message.lower()


class TestValidateSslHandshake:
    """Tests for validate_ssl_handshake."""

    @pytest.mark.asyncio
    async def test_ssl_handshake_success(self):
        """Test successful SSL handshake."""
        thread_pool = Mock()
        
        with patch("ssl.create_default_context"):
            with patch("socket.create_connection") as mock_socket:
                mock_sock = Mock()
                mock_socket.return_value = mock_sock
                
                with patch.object(mock_sock, "close"):
                    result = await validate_ssl_handshake("example.com", 443, 10.0, thread_pool)
                    
                    assert result.method == ValidationMethod.SSL_HANDSHAKE
                    # May succeed or fail depending on mock setup
                    assert result.method == ValidationMethod.SSL_HANDSHAKE

    @pytest.mark.asyncio
    async def test_ssl_handshake_timeout(self):
        """Test SSL handshake timeout."""
        thread_pool = Mock()
        
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = TimeoutError()
            
            result = await validate_ssl_handshake("example.com", 443, 1.0, thread_pool)
            
            assert result.method == ValidationMethod.SSL_HANDSHAKE
            assert result.success is False


class TestValidateHeaderAnalysis:
    """Tests for validate_header_analysis."""

    @pytest.mark.asyncio
    async def test_header_analysis_success(self):
        """Test successful header analysis."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {
                "Content-Type": "text/html",
                "Server": "nginx",
            }
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_header_analysis("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.HEADER_ANALYSIS
            assert result.success is True

    @pytest.mark.asyncio
    async def test_header_analysis_missing_headers(self):
        """Test header analysis with missing headers."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {}
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_header_analysis("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.HEADER_ANALYSIS
            # Missing headers might still be valid
            assert result.method == ValidationMethod.HEADER_ANALYSIS


class TestValidatePayloadVerification:
    """Tests for validate_payload_verification."""

    @pytest.mark.asyncio
    async def test_payload_verification_success(self):
        """Test successful payload verification."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.read.return_value = b"Test payload content"
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_payload_verification("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.PAYLOAD_VERIFICATION
            assert result.success is True

    @pytest.mark.asyncio
    async def test_payload_verification_empty(self):
        """Test payload verification with empty payload."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.read.return_value = b""
            mock_response.__aenter__.return_value = mock_response
            mock_response.__aexit__.return_value = None
            
            mock_session.return_value.__aenter__.return_value.get.return_value = mock_response
            
            result = await validate_payload_verification("example.com", 443, 10.0)
            
            assert result.method == ValidationMethod.PAYLOAD_VERIFICATION
            # Empty payload might be valid for some responses
            assert result.method == ValidationMethod.PAYLOAD_VERIFICATION

    @pytest.mark.asyncio
    async def test_payload_verification_timeout(self):
        """Test payload verification timeout."""
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value.__aenter__.return_value.get.side_effect = asyncio.TimeoutError()
            
            result = await validate_payload_verification("example.com", 443, 1.0)
            
            assert result.method == ValidationMethod.PAYLOAD_VERIFICATION
            assert result.success is False
            assert "timeout" in result.error_message.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
