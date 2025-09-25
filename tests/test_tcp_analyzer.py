import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from core.fingerprint.tcp_analyzer import TCPAnalyzer, TCPAnalysisResult, NetworkAnalysisError
from core.fingerprint.unified_models import AnalysisStatus

@pytest.mark.asyncio
async def test_tcp_analyzer_successful_connection():
    """Test TCPAnalyzer when a connection is successful."""
    analyzer = TCPAnalyzer(timeout=1)

    # Mock the internal probe methods to isolate the main analyzer logic
    analyzer._probe_rst_injection = AsyncMock()
    analyzer._probe_tcp_options_and_timing = AsyncMock()
    analyzer._probe_fragmentation = AsyncMock()
    analyzer._resolve_target = AsyncMock(return_value="127.0.0.1")

    result_dict = await analyzer.analyze_tcp_behavior("example.com", 443)

    # The method returns a dict, so we can convert it back to the dataclass for easier validation
    result = TCPAnalysisResult(**result_dict)

    assert isinstance(result, TCPAnalysisResult)
    assert result.target == "example.com"

@pytest.mark.asyncio
async def test_tcp_analyzer_dns_failure():
    """Test TCPAnalyzer when DNS resolution fails."""
    analyzer = TCPAnalyzer(timeout=1)

    # Mock _resolve_target to raise the specific exception the code would raise
    analyzer._resolve_target = AsyncMock(side_effect=NetworkAnalysisError("DNS resolution failed: lookup failed"))

    # Assert that the specific exception is caught with the correct message
    with pytest.raises(NetworkAnalysisError, match="DNS resolution failed: lookup failed"):
        await analyzer.analyze_tcp_behavior("example.com", 443)

@pytest.mark.asyncio
async def test_probe_rst_injection_logic():
    """Test the logic of the RST injection probe specifically."""
    analyzer = TCPAnalyzer(timeout=1)
    result = TCPAnalysisResult(target="example.com")

    mock_response = MagicMock()
    mock_tcp_layer = MagicMock()
    mock_tcp_layer.flags = 4  # RST flag
    mock_response.haslayer.return_value = True
    mock_response.getlayer.return_value = mock_tcp_layer

    # Patch sr1, which is called inside the probe
    with patch('core.fingerprint.tcp_analyzer.sr1', return_value=mock_response) as mock_sr1:
        await analyzer._probe_rst_injection(result, "127.0.0.1", 443)

        # The probe modifies the result object in place
        assert result.rst_injection_detected is True
        mock_sr1.assert_called_once()