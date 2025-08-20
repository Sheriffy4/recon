# recon/core/fingerprint/test_http_analyzer.py
"""
Comprehensive tests for HTTP Behavior Analyzer - Task 5 Implementation
Tests HTTP-specific DPI detection including header filtering, content inspection,
user agent filtering, host header manipulation, redirect injection, and response modification.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import AsyncMock, patch

from ..core.fingerprint.http_analyzer import (
    HTTPAnalyzer,
    HTTPAnalysisResult,
    HTTPRequest,
    HTTPBlockingMethod,
)
from ..core.fingerprint.advanced_models import NetworkAnalysisError


class TestHTTPAnalyzer:
    """Test suite for HTTPAnalyzer class"""

    @pytest.fixture
    def analyzer(self):
        """Create HTTPAnalyzer instance for testing"""
        return HTTPAnalyzer(timeout=5.0, max_attempts=3)

    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response"""
        response = AsyncMock()
        response_context = AsyncMock()
        response_context.status = 200
        response_context.headers = {"Content-Type": "text/html", "Server": "nginx"}
        response_context.text = AsyncMock(
            return_value="<html><body>Test content</body></html>"
        )
        response.__aenter__ = AsyncMock(return_value=response_context)
        response.__aexit__ = AsyncMock(return_value=None)
        return response

    @pytest.fixture
    def mock_session(self, mock_response):
        """Create mock aiohttp session"""
        session = AsyncMock()
        session.get = AsyncMock(return_value=mock_response)
        session.post = AsyncMock(return_value=mock_response)
        session.put = AsyncMock(return_value=mock_response)
        session.delete = AsyncMock(return_value=mock_response)
        session.head = AsyncMock(return_value=mock_response)
        session.options = AsyncMock(return_value=mock_response)
        session.patch = AsyncMock(return_value=mock_response)
        session.request = AsyncMock(return_value=mock_response)
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)
        return session

    def test_init(self, analyzer):
        """Test HTTPAnalyzer initialization"""
        assert analyzer.timeout == 5.0
        assert analyzer.max_attempts == 3
        assert len(analyzer.test_user_agents) > 0
        assert len(analyzer.test_headers) > 0
        assert len(analyzer.test_content_keywords) > 0
        assert len(analyzer.test_methods) > 0
        assert len(analyzer.test_content_types) > 0

    @pytest.mark.asyncio
    async def test_analyze_http_behavior_success(self, analyzer):
        """Test successful HTTP behavior analysis"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Create mock response
            mock_response = AsyncMock()
            response_context = AsyncMock()
            response_context.status = 200
            response_context.headers = {"Content-Type": "text/html"}
            response_context.text = AsyncMock(return_value="<html>Test</html>")
            mock_response.__aenter__ = AsyncMock(return_value=response_context)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            # Configure session
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.put = AsyncMock(return_value=mock_response)
            mock_session.delete = AsyncMock(return_value=mock_response)
            mock_session.head = AsyncMock(return_value=mock_response)
            mock_session.options = AsyncMock(return_value=mock_response)
            mock_session.patch = AsyncMock(return_value=mock_response)
            mock_session.request = AsyncMock(return_value=mock_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyzer.analyze_http_behavior("example.com", 443)

            assert isinstance(result, dict)
            assert result["target"] == "example.com"
            assert "timestamp" in result
            assert "reliability_score" in result
            assert isinstance(result["http_header_filtering"], bool)
            assert isinstance(result["user_agent_filtering"], bool)
            assert isinstance(result["content_inspection_depth"], int)

    @pytest.mark.asyncio
    async def test_analyze_http_behavior_network_error(self, analyzer):
        """Test HTTP analysis with network errors"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            # Create error response that raises error in context manager
            mock_response = AsyncMock()
            mock_response.__aenter__ = AsyncMock(
                side_effect=aiohttp.ClientError("Network error")
            )
            mock_response.__aexit__ = AsyncMock(return_value=None)

            # Configure session to return error response
            mock_session = AsyncMock()
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session

            with pytest.raises(NetworkAnalysisError):
                await analyzer.analyze_http_behavior("unreachable.com", 443)

    @pytest.mark.asyncio
    async def test_make_request_success(self, analyzer):
        """Test successful HTTP request"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Create successful response
            mock_response = AsyncMock()
            response_context = AsyncMock()
            response_context.status = 200
            response_context.headers = {"Content-Type": "text/html"}
            response_context.text = AsyncMock(return_value="<html>Test</html>")
            mock_response.__aenter__ = AsyncMock(return_value=response_context)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            request = await analyzer._make_request(
                "https://example.com", "GET", {"User-Agent": "test-agent"}
            )

            assert isinstance(request, HTTPRequest)
            assert request.success == True
            assert request.status_code == 200
            assert request.method == "GET"
            assert request.url == "https://example.com"

    @pytest.mark.asyncio
    async def test_make_request_timeout(self, analyzer):
        """Test HTTP request timeout"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session.get = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            request = await analyzer._make_request(
                "https://example.com", "GET", {"User-Agent": "test-agent"}
            )

            assert request.success == False
            assert request.blocking_method == HTTPBlockingMethod.TIMEOUT
            assert "timeout" in request.error_message.lower()

    @pytest.mark.asyncio
    async def test_make_request_connection_reset(self, analyzer):
        """Test HTTP request connection reset"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            # Use a specific aiohttp exception
            mock_session.get = AsyncMock(
                side_effect=aiohttp.ClientError("Connection reset by peer")
            )
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            request = await analyzer._make_request(
                "https://example.com", "GET", {"User-Agent": "test-agent"}
            )

            assert request.success == False
            assert "Connection reset" in request.error_message

    @pytest.mark.asyncio
    async def test_header_filtering_detection(self, analyzer):
        """Test header filtering detection"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Mock responses: success for normal headers, failure for suspicious ones
            async def mock_get_side_effect(*args, **kwargs):
                headers = kwargs.get("headers", {})
                response = AsyncMock()
                response_context = AsyncMock()

                # Block requests with suspicious headers
                if any(
                    header in headers for header in ["X-Forwarded-For", "X-Real-IP"]
                ):
                    raise aiohttp.ClientError("Connection reset by peer")

                response_context.status = 200
                response_context.headers = {"Content-Type": "text/html"}
                response_context.text = AsyncMock(return_value="<html>Test</html>")
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            mock_session.get = AsyncMock(side_effect=mock_get_side_effect)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = HTTPAnalysisResult(target="example.com")
            await analyzer._analyze_header_filtering(result, "https://example.com")

            assert result.http_header_filtering == True
            assert len(result.filtered_headers) > 0
            assert (
                "X-Forwarded-For" in result.filtered_headers
                or "X-Real-IP" in result.filtered_headers
            )

    @pytest.mark.asyncio
    async def test_user_agent_filtering_detection(self, analyzer):
        """Test user agent filtering detection"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Mock responses: block suspicious user agents
            async def mock_get_side_effect(*args, **kwargs):
                headers = kwargs.get("headers", {})
                user_agent = headers.get("User-Agent", "")
                response = AsyncMock()
                response_context = AsyncMock()

                # Block suspicious user agents
                if any(
                    agent in user_agent for agent in ["curl", "wget", "python-requests"]
                ):
                    raise aiohttp.ClientError("Connection reset by peer")

                response_context.status = 200
                response_context.headers = {"Content-Type": "text/html"}
                response_context.text = AsyncMock(return_value="<html>Test</html>")
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            mock_session.get = AsyncMock(side_effect=mock_get_side_effect)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = HTTPAnalysisResult(target="example.com")
            await analyzer._analyze_user_agent_filtering(result, "https://example.com")

            assert result.user_agent_filtering == True
            assert len(result.blocked_user_agents) > 0

    @pytest.mark.asyncio
    async def test_http_method_restrictions(self, analyzer):
        """Test HTTP method restrictions detection"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Mock responses: block certain methods
            async def mock_request_behavior(method, *args, **kwargs):
                response = AsyncMock()
                response_context = AsyncMock()

                # Block TRACE and DELETE methods
                if method.upper() in ["TRACE", "DELETE"]:
                    response_context.status = 405
                    response_context.headers = {"Content-Type": "text/html"}
                    response_context.text = AsyncMock(return_value="Method not allowed")
                    response.__aenter__ = AsyncMock(return_value=response_context)
                    response.__aexit__ = AsyncMock(return_value=None)
                    return response

                # Allow other methods
                response_context.status = 200
                response_context.headers = {"Content-Type": "text/html"}
                response_context.text = AsyncMock(return_value="<html>Test</html>")
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            # Set up method mocks
            for method in ["get", "post", "put", "delete", "head", "options", "patch"]:
                setattr(
                    mock_session,
                    method,
                    AsyncMock(
                        side_effect=lambda *args, **kwargs: mock_request_behavior(
                            method, *args, **kwargs
                        )
                    ),
                )

            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = HTTPAnalysisResult(target="example.com")
            await analyzer._analyze_http_method_restrictions(
                result, "https://example.com"
            )

            assert result.method_based_blocking == True
            assert len(result.http_method_restrictions) > 0
            assert (
                "TRACE" in result.http_method_restrictions
                or "DELETE" in result.http_method_restrictions
            )

    @pytest.mark.asyncio
    async def test_comprehensive_dpi_analysis(self, analyzer):
        """Test comprehensive DPI analysis with multiple blocking methods"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Complex mock that simulates various DPI behaviors
            async def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get("headers", {})
                data = kwargs.get("data", "")

                # Create response object
                response = AsyncMock()
                response_context = AsyncMock()
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)

                # Header-based blocking
                if "X-Forwarded-For" in headers:
                    raise aiohttp.ClientError("Connection reset by peer")

                # User agent blocking
                user_agent = headers.get("User-Agent", "")
                if "curl" in user_agent or "wget" in user_agent:
                    raise aiohttp.ClientError("Connection reset by peer")

                # Method blocking
                if method.upper() in ["TRACE", "DELETE"]:
                    response_context.status = 405
                    response_context.headers = {"Content-Type": "text/html"}
                    response_context.text = AsyncMock(return_value="Method not allowed")
                    return response

                # Content-based blocking
                if "vpn" in str(data) or "proxy" in str(data):
                    response_context.status = 200
                    response_context.headers = {
                        "Content-Type": "text/html",
                        "X-Blocked-By": "Content-Filter",
                    }
                    response_context.text = AsyncMock(
                        return_value="<html>This content is blocked</html>"
                    )
                    return response

                # Redirect injection for certain paths
                if "/blocked" in url:
                    response_context.status = 302
                    response_context.headers = {
                        "Location": "https://warning.gov/blocked",
                        "Content-Type": "text/html",
                    }
                    response_context.text = AsyncMock(
                        return_value="<html>Redirecting...</html>"
                    )
                    return response

                # Normal response
                response_context.status = 200
                response_context.headers = {"Content-Type": "text/html"}
                response_context.text = AsyncMock(
                    return_value="<html><body>Normal content</body></html>"
                )
                return response

            # Set up all method mocks
            mock_session.get = AsyncMock(side_effect=mock_request_behavior)
            mock_session.post = AsyncMock(side_effect=mock_request_behavior)
            mock_session.put = AsyncMock(side_effect=mock_request_behavior)
            mock_session.delete = AsyncMock(side_effect=mock_request_behavior)
            mock_session.head = AsyncMock(side_effect=mock_request_behavior)
            mock_session.options = AsyncMock(side_effect=mock_request_behavior)
            mock_session.patch = AsyncMock(side_effect=mock_request_behavior)
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyzer.analyze_http_behavior("blocked-site.com", 443)

            # Verify comprehensive analysis results
            assert result["target"] == "blocked-site.com"
            assert result["http_header_filtering"] == True
            assert result["user_agent_filtering"] == True
            assert result["method_based_blocking"] == True
            assert result["redirect_injection"] == True
            assert result["http_response_modification"] == True
            assert result["reliability_score"] > 0.0

            # Check specific detections
            assert len(result["filtered_headers"]) > 0
            assert len(result["blocked_user_agents"]) > 0
            assert len(result["http_method_restrictions"]) > 0
            assert len(result["redirect_patterns"]) > 0

    @pytest.mark.asyncio
    async def test_no_blocking_scenario(self, analyzer):
        """Test analysis when no blocking is detected"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Create normal response
            mock_response = AsyncMock()
            response_context = AsyncMock()
            response_context.status = 200
            response_context.headers = {"Content-Type": "text/html", "Server": "nginx"}
            response_context.text = AsyncMock(
                return_value="<html><body>Normal content</body></html>"
            )
            mock_response.__aenter__ = AsyncMock(return_value=response_context)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.put = AsyncMock(return_value=mock_response)
            mock_session.delete = AsyncMock(return_value=mock_response)
            mock_session.head = AsyncMock(return_value=mock_response)
            mock_session.options = AsyncMock(return_value=mock_response)
            mock_session.patch = AsyncMock(return_value=mock_response)
            mock_session.request = AsyncMock(return_value=mock_response)

            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyzer.analyze_http_behavior("normal-site.com", 443)

            # Verify no blocking detected
            assert result["target"] == "normal-site.com"
            assert result["http_header_filtering"] == False
            assert result["user_agent_filtering"] == False
            assert result["method_based_blocking"] == False
            assert result["redirect_injection"] == False
            assert result["http_response_modification"] == False
            assert result["content_based_blocking"] == False

            # Should have high reliability score with all successful requests
            assert result["reliability_score"] > 0.7

    @pytest.mark.asyncio
    async def test_bytewise_packet_processing(self, analyzer):
        """Test bytewise packet processing functionality"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Simulate raw packet data
            raw_packet = (
                b"GET / HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: test-agent\r\n"
                b"Accept: */*\r\n\r\n"
            )

            # Mock response with raw packet handling
            async def mock_response_with_raw_packets(*args, **kwargs):
                response = AsyncMock()
                response_context = AsyncMock()

                # Test if bytewise processing is enabled
                if (
                    hasattr(analyzer, "use_bytewise_processing")
                    and analyzer.use_bytewise_processing
                ):
                    # Simulate packet segmentation
                    response_context.raw_packets = [
                        raw_packet[:10],
                        raw_packet[10:20],
                        raw_packet[20:],
                    ]
                    response_context.content_type = "application/octet-stream"
                else:
                    raise ValueError("Bytewise processing not enabled")

                response_context.status = 200
                response_context.headers = {"Content-Type": "text/html"}
                response_context.text = AsyncMock(return_value="<html>Test</html>")
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            mock_session.get = AsyncMock(side_effect=mock_response_with_raw_packets)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            # Test packet analysis with bytewise processing
            result = await analyzer.analyze_packet_stream("example.com", 443)

            assert result["packet_processing_method"] == "bytewise"
            assert result["segmentation_detected"] == True
            assert result["packet_reassembly_success"] == True

    @pytest.mark.asyncio
    async def test_packet_modification_detection(self, analyzer):
        """Test detection of packet modifications"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Original packet
            original_packet = (
                b"GET / HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: test-agent\r\n"
                b"Accept: */*\r\n\r\n"
            )

            # Modified packet (simulating DPI modification)
            modified_packet = (
                b"GET / HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: modified-agent\r\n"  # Modified field
                b"Accept: */*\r\n"
                b"X-Injected: true\r\n\r\n"  # Injected field
            )

            async def mock_modified_response(*args, **kwargs):
                response = AsyncMock()
                response_context = AsyncMock()
                response_context.raw_packets = [modified_packet]
                response_context.original_packets = [original_packet]
                response_context.status = 200
                response_context.headers = {"Content-Type": "application/octet-stream"}
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            mock_session.get = AsyncMock(side_effect=mock_modified_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyzer.analyze_packet_modifications("example.com", 443)

            assert result["packet_modified"] == True
            assert result["modifications_detected"] == {
                "header_injection": True,
                "user_agent_modified": True,
            }
            assert result["original_size"] == len(original_packet)
            assert result["modified_size"] == len(modified_packet)

    @pytest.mark.asyncio
    async def test_packet_fragmentation_handling(self, analyzer):
        """Test handling of fragmented packets"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()

            # Test packet with intentional fragmentation
            packet_fragments = [
                b"GET / HTT",
                b"P/1.1\r\nHost:",
                b" example.com\r\n",
                b"User-Agent: test",
                b"-agent\r\n\r\n",
            ]

            async def mock_fragmented_response(*args, **kwargs):
                response = AsyncMock()
                response_context = AsyncMock()
                response_context.raw_packets = packet_fragments
                response_context.status = 200
                response_context.headers = {"Content-Type": "application/octet-stream"}
                response.__aenter__ = AsyncMock(return_value=response_context)
                response.__aexit__ = AsyncMock(return_value=None)
                return response

            mock_session.get = AsyncMock(side_effect=mock_fragmented_response)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyzer.analyze_fragmentation_handling("example.com", 443)

            assert result["fragmentation_handled"] == True
            assert result["fragments_count"] == len(packet_fragments)
            assert result["reassembly_successful"] == True
            assert result["total_size"] == sum(len(f) for f in packet_fragments)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
