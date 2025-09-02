"""
Integration tests for HTTP Analyzer - Task 5 Implementation
Tests HTTP analyzer integration with various HTTP blocking scenarios and real-world DPI behaviors.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import AsyncMock, MagicMock, patch
from recon.тесты.http_analyzer import HTTPAnalyzer
from recon.тесты.advanced_models import NetworkAnalysisError


class TestHTTPAnalyzerIntegration:
    """Integration tests for HTTP analyzer with realistic DPI scenarios"""

    @pytest.fixture
    def analyzer(self):
        """Create HTTPAnalyzer instance for integration testing"""
        return HTTPAnalyzer(timeout=3.0, max_attempts=2)

    @pytest.mark.asyncio
    async def test_roskomnadzor_tspu_simulation(self, analyzer):
        """Test simulation of Roskomnadzor TSPU DPI behavior"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get("headers", {})
                data = kwargs.get("data", "")
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                user_agent = headers.get("User-Agent", "")
                if any(
                    (
                        agent in user_agent.lower()
                        for agent in ["curl", "wget", "python", "bot"]
                    )
                ):
                    raise Exception("Connection reset by peer")
                if any(
                    (
                        header in headers
                        for header in ["X-Forwarded-For", "X-Real-IP", "Via"]
                    )
                ):
                    raise Exception("Connection reset by peer")
                if any(
                    (
                        keyword in str(data).lower()
                        for keyword in ["vpn", "proxy", "tor", "обход"]
                    )
                ):
                    mock_response.status = 200
                    mock_response.headers = {"Content-Type": "text/html"}
                    mock_response.text = AsyncMock(
                        return_value="\n                    <html><head><title>Доступ ограничен</title></head>\n                    <body><h1>Доступ к информационному ресурсу ограничен</h1>\n                    <p>Доступ ограничен в соответствии с законодательством Российской Федерации</p>\n                    </body></html>\n                    "
                    )
                    return mock_response
                if method.upper() in ["TRACE", "CONNECT"]:
                    mock_response.status = 405
                    mock_response.headers = {"Content-Type": "text/html"}
                    mock_response.text = AsyncMock(return_value="Method Not Allowed")
                    return mock_response
                mock_response.status = 200
                mock_response.headers = {"Content-Type": "text/html", "Server": "nginx"}
                mock_response.text = AsyncMock(
                    return_value="<html><body>Normal content</body></html>"
                )
                return mock_response

            mock_session.get = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "GET", url, *args, **kwargs
                )
            )
            mock_session.post = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "POST", url, *args, **kwargs
                )
            )
            mock_session.put = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PUT", url, *args, **kwargs
                )
            )
            mock_session.delete = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "DELETE", url, *args, **kwargs
                )
            )
            mock_session.head = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "HEAD", url, *args, **kwargs
                )
            )
            mock_session.options = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "OPTIONS", url, *args, **kwargs
                )
            )
            mock_session.patch = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PATCH", url, *args, **kwargs
                )
            )
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            result = await analyzer.analyze_http_behavior("blocked-site.ru", 443)
            assert result["target"] == "blocked-site.ru"
            assert result["user_agent_filtering"] == True
            assert result["http_header_filtering"] == True
            assert result["content_based_blocking"] == True
            assert result["method_based_blocking"] == True
            assert len(result["blocked_user_agents"]) > 0
            assert len(result["filtered_headers"]) > 0
            assert result["reliability_score"] > 0.5

    @pytest.mark.asyncio
    async def test_commercial_dpi_simulation(self, analyzer):
        """Test simulation of commercial DPI system behavior"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get("headers", {})
                data = kwargs.get("data", "")
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                if any(
                    (
                        keyword in str(data).lower()
                        for keyword in ["torrent", "p2p", "streaming"]
                    )
                ):
                    mock_response.status = 302
                    mock_response.headers = {
                        "Location": "https://warning.isp.com/blocked?reason=content",
                        "Content-Type": "text/html",
                    }
                    mock_response.text = AsyncMock(
                        return_value="<html>Redirecting to warning page</html>"
                    )
                    return mock_response
                if headers.get("Transfer-Encoding", "").lower() == "chunked":
                    mock_response.status = 400
                    mock_response.headers = {"Content-Type": "text/html"}
                    mock_response.text = AsyncMock(
                        return_value="Bad Request - Transfer encoding not supported"
                    )
                    return mock_response
                if headers.get("Connection", "").lower() == "keep-alive":
                    mock_response.status = 200
                    mock_response.headers = {
                        "Content-Type": "text/html",
                        "Connection": "close",
                    }
                    mock_response.text = AsyncMock(
                        return_value="<html>Content with forced close</html>"
                    )
                    return mock_response
                mock_response.status = 200
                mock_response.headers = {
                    "Content-Type": "text/html",
                    "Server": "Apache",
                }
                mock_response.text = AsyncMock(
                    return_value="<html><body>Normal content</body></html>"
                )
                return mock_response

            mock_session.get = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "GET", url, *args, **kwargs
                )
            )
            mock_session.post = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "POST", url, *args, **kwargs
                )
            )
            mock_session.put = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PUT", url, *args, **kwargs
                )
            )
            mock_session.delete = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "DELETE", url, *args, **kwargs
                )
            )
            mock_session.head = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "HEAD", url, *args, **kwargs
                )
            )
            mock_session.options = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "OPTIONS", url, *args, **kwargs
                )
            )
            mock_session.patch = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PATCH", url, *args, **kwargs
                )
            )
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            result = await analyzer.analyze_http_behavior("corporate-site.com", 443)
            assert result["target"] == "corporate-site.com"
            assert result["redirect_injection"] == True
            assert result["transfer_encoding_filtering"] == True
            assert result["keep_alive_manipulation"] == True
            assert len(result["redirect_patterns"]) > 0
            assert result["reliability_score"] > 0.5

    @pytest.mark.asyncio
    async def test_firewall_based_blocking(self, analyzer):
        """Test simulation of firewall-based blocking"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get("headers", {})
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                if method.upper() not in ["GET", "POST"]:
                    raise aiohttp.ClientConnectorError(
                        connection_key=None, os_error=OSError(111, "Connection refused")
                    )
                suspicious_headers = [
                    "X-Forwarded-For",
                    "X-Real-IP",
                    "Via",
                    "Proxy-Connection",
                ]
                if any((header in headers for header in suspicious_headers)):
                    raise aiohttp.ClientConnectorError(
                        connection_key=None, os_error=OSError(111, "Connection refused")
                    )
                user_agent = headers.get("User-Agent", "")
                if not any(
                    (
                        browser in user_agent
                        for browser in ["Mozilla", "Chrome", "Safari", "Edge"]
                    )
                ):
                    raise aiohttp.ClientConnectorError(
                        connection_key=None, os_error=OSError(111, "Connection refused")
                    )
                mock_response.status = 200
                mock_response.headers = {"Content-Type": "text/html"}
                mock_response.text = AsyncMock(
                    return_value="<html><body>Allowed content</body></html>"
                )
                return mock_response

            mock_session.get = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "GET", url, *args, **kwargs
                )
            )
            mock_session.post = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "POST", url, *args, **kwargs
                )
            )
            mock_session.put = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PUT", url, *args, **kwargs
                )
            )
            mock_session.delete = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "DELETE", url, *args, **kwargs
                )
            )
            mock_session.head = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "HEAD", url, *args, **kwargs
                )
            )
            mock_session.options = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "OPTIONS", url, *args, **kwargs
                )
            )
            mock_session.patch = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PATCH", url, *args, **kwargs
                )
            )
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            result = await analyzer.analyze_http_behavior("protected-site.com", 443)
            assert result["target"] == "protected-site.com"
            assert result["method_based_blocking"] == True
            assert result["http_header_filtering"] == True
            assert result["user_agent_filtering"] == True
            assert len(result["http_method_restrictions"]) > 0
            assert len(result["filtered_headers"]) > 0
            assert len(result["blocked_user_agents"]) > 0
            assert result["reliability_score"] > 0.5

    @pytest.mark.asyncio
    async def test_no_dpi_scenario(self, analyzer):
        """Test analysis of site with no DPI blocking"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.headers = {"Content-Type": "text/html", "Server": "nginx"}
            mock_response.text = AsyncMock(
                return_value="<html><body>Normal content</body></html>"
            )
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
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
            assert result["target"] == "normal-site.com"
            assert result["http_header_filtering"] == False
            assert result["user_agent_filtering"] == False
            assert result["method_based_blocking"] == False
            assert result["redirect_injection"] == False
            assert result["http_response_modification"] == False
            assert result["content_based_blocking"] == False
            assert result["transfer_encoding_filtering"] == False
            assert result["keep_alive_manipulation"] == False
            assert result["reliability_score"] > 0.8

    @pytest.mark.asyncio
    async def test_mixed_blocking_scenario(self, analyzer):
        """Test analysis with mixed blocking methods"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get("headers", {})
                data = kwargs.get("data", "")
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                if headers.get("X-Forwarded-For"):
                    raise aiohttp.ClientConnectorError(
                        connection_key=None,
                        os_error=OSError(104, "Connection reset by peer"),
                    )
                user_agent = headers.get("User-Agent", "")
                if "curl" in user_agent:
                    mock_response.status = 403
                    mock_response.headers = {"Content-Type": "text/html"}
                    mock_response.text = AsyncMock(
                        return_value="<html><body>Forbidden</body></html>"
                    )
                    return mock_response
                if "vpn" in str(data).lower():
                    mock_response.status = 302
                    mock_response.headers = {
                        "Location": "https://warning.example.com/blocked",
                        "Content-Type": "text/html",
                    }
                    mock_response.text = AsyncMock(
                        return_value="<html>Redirecting...</html>"
                    )
                    return mock_response
                if method.upper() == "TRACE":
                    raise asyncio.TimeoutError()
                mock_response.status = 200
                mock_response.headers = {"Content-Type": "text/html"}
                mock_response.text = AsyncMock(
                    return_value="<html><body>Normal content</body></html>"
                )
                return mock_response

            mock_session.get = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "GET", url, *args, **kwargs
                )
            )
            mock_session.post = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "POST", url, *args, **kwargs
                )
            )
            mock_session.put = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PUT", url, *args, **kwargs
                )
            )
            mock_session.delete = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "DELETE", url, *args, **kwargs
                )
            )
            mock_session.head = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "HEAD", url, *args, **kwargs
                )
            )
            mock_session.options = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "OPTIONS", url, *args, **kwargs
                )
            )
            mock_session.patch = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PATCH", url, *args, **kwargs
                )
            )
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            result = await analyzer.analyze_http_behavior("mixed-blocking.com", 443)
            assert result["target"] == "mixed-blocking.com"
            assert result["http_header_filtering"] == True
            assert result["user_agent_filtering"] == True
            assert result["redirect_injection"] == True
            assert result["content_based_blocking"] == True
            assert 0.4 <= result["reliability_score"] <= 0.8

    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, analyzer):
        """Test error handling and recovery scenarios"""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session_class.side_effect = Exception("Network unreachable")
            with pytest.raises(NetworkAnalysisError):
                await analyzer.analyze_http_behavior("unreachable.com", 443)
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            call_count = 0

            def mock_request_behavior(method, url, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                if call_count <= 3:
                    raise aiohttp.ClientConnectorError(
                        connection_key=None, os_error=OSError(111, "Connection refused")
                    )
                mock_response.status = 200
                mock_response.headers = {"Content-Type": "text/html"}
                mock_response.text = AsyncMock(
                    return_value="<html><body>Recovered content</body></html>"
                )
                return mock_response

            mock_session.get = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "GET", url, *args, **kwargs
                )
            )
            mock_session.post = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "POST", url, *args, **kwargs
                )
            )
            mock_session.put = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PUT", url, *args, **kwargs
                )
            )
            mock_session.delete = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "DELETE", url, *args, **kwargs
                )
            )
            mock_session.head = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "HEAD", url, *args, **kwargs
                )
            )
            mock_session.options = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "OPTIONS", url, *args, **kwargs
                )
            )
            mock_session.patch = AsyncMock(
                side_effect=lambda url, *args, **kwargs: mock_request_behavior(
                    "PATCH", url, *args, **kwargs
                )
            )
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            result = await analyzer.analyze_http_behavior("partial-failure.com", 443)
            assert result["target"] == "partial-failure.com"
            assert isinstance(result["reliability_score"], float)
            assert 0.0 <= result["reliability_score"] <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
