# recon/core/fingerprint/test_http_simple.py
"""
Simple test to verify HTTP analyzer is working correctly
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from .http_analyzer import HTTPAnalyzer, HTTPAnalysisResult


class TestHTTPAnalyzerSimple:
    """Simple tests for HTTP analyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create HTTPAnalyzer instance for testing"""
        return HTTPAnalyzer(timeout=2.0, max_attempts=2)
    
    @pytest.mark.asyncio
    async def test_basic_analysis(self, analyzer):
        """Test basic HTTP analysis functionality"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            
            # Mock successful response
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.headers = {'Content-Type': 'text/html', 'Server': 'nginx'}
            mock_response.text = AsyncMock(return_value="<html><body>Test content</body></html>")
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)
            
            # Set up all method mocks to return the same response
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
            
            # Run analysis
            result = await analyzer.analyze_http_behavior("example.com", 443)
            
            # Verify basic structure
            assert isinstance(result, dict)
            assert result['target'] == "example.com"
            assert 'timestamp' in result
            assert 'reliability_score' in result
            assert isinstance(result['http_header_filtering'], bool)
            assert isinstance(result['user_agent_filtering'], bool)
            assert isinstance(result['content_inspection_depth'], int)
            assert isinstance(result['redirect_injection'], bool)
            assert isinstance(result['http_response_modification'], bool)
            
            # With all successful responses, should have high reliability
            assert result['reliability_score'] > 0.5
    
    @pytest.mark.asyncio
    async def test_blocking_detection(self, analyzer):
        """Test detection of various blocking methods"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            
            def mock_request_behavior(method, url, *args, **kwargs):
                headers = kwargs.get('headers', {})
                data = kwargs.get('data', '')
                
                mock_response = MagicMock()
                mock_response.__aenter__ = AsyncMock(return_value=mock_response)
                mock_response.__aexit__ = AsyncMock(return_value=None)
                
                # Block suspicious user agents
                user_agent = headers.get('User-Agent', '')
                if 'curl' in user_agent.lower():
                    raise Exception("Connection reset by peer")
                
                # Block certain headers
                if 'X-Forwarded-For' in headers:
                    raise Exception("Connection reset by peer")
                
                # Block certain content
                if 'vpn' in str(data).lower():
                    mock_response.status = 302
                    mock_response.headers = {
                        'Location': 'https://blocked.example.com',
                        'Content-Type': 'text/html'
                    }
                    mock_response.text = AsyncMock(return_value="<html>Redirecting...</html>")
                    return mock_response
                
                # Normal response
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                mock_response.text = AsyncMock(return_value="<html><body>Normal content</body></html>")
                return mock_response
            
            # Set up method mocks
            mock_session.get = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('GET', url, *args, **kwargs))
            mock_session.post = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('POST', url, *args, **kwargs))
            mock_session.put = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('PUT', url, *args, **kwargs))
            mock_session.delete = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('DELETE', url, *args, **kwargs))
            mock_session.head = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('HEAD', url, *args, **kwargs))
            mock_session.options = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('OPTIONS', url, *args, **kwargs))
            mock_session.patch = AsyncMock(side_effect=lambda url, *args, **kwargs: mock_request_behavior('PATCH', url, *args, **kwargs))
            mock_session.request = AsyncMock(side_effect=mock_request_behavior)
            
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            mock_session_class.return_value = mock_session
            
            # Run analysis
            result = await analyzer.analyze_http_behavior("blocked-site.com", 443)
            
            # Verify blocking detection
            assert result['target'] == "blocked-site.com"
            assert result['user_agent_filtering'] == True
            assert result['http_header_filtering'] == True
            assert result['redirect_injection'] == True
            assert result['content_based_blocking'] == True
            
            # Should have reasonable reliability despite blocking
            assert result['reliability_score'] > 0.3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])