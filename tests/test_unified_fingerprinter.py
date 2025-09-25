import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
from core.fingerprint.unified_models import UnifiedFingerprint, DPIType, AnalysisStatus, TCPAnalysisResult, HTTPAnalysisResult

@pytest.fixture
def mock_analyzers():
    """A fixture to provide mocked analyzer adapters."""
    # Mock for TCPAnalyzer adapter
    mock_tcp_adapter = MagicMock()
    mock_tcp_adapter.analyze = AsyncMock(return_value=TCPAnalysisResult(
        status=AnalysisStatus.COMPLETED,
        rst_injection_detected=True,
        fragmentation_vulnerable=False
    ))

    # Mock for HTTPAnalyzer adapter
    mock_http_adapter = MagicMock()
    mock_http_adapter.analyze = AsyncMock(return_value=HTTPAnalysisResult(
        status=AnalysisStatus.COMPLETED,
        http_blocking_detected=True
    ))

    analyzers = {
        'tcp': mock_tcp_adapter,
        'http': mock_http_adapter
    }

    with patch('core.fingerprint.unified_fingerprinter.get_available_analyzers', return_value=list(analyzers.keys())):
        with patch('core.fingerprint.unified_fingerprinter.check_analyzer_availability', return_value={name: {'available': True} for name in analyzers.keys()}):
            # This patch will ensure that when create_analyzer_adapter is called, it returns our mocks
            with patch('core.fingerprint.unified_fingerprinter.create_analyzer_adapter', side_effect=lambda name, **kwargs: analyzers.get(name)):
                yield analyzers

@pytest.mark.asyncio
async def test_fingerprint_target_fast_analysis(mock_analyzers):
    """Test that fast analysis only runs the TCP analyzer."""
    config = FingerprintingConfig(analysis_level="fast", enable_http_analysis=True, enable_tcp_analysis=True)
    fingerprinter = UnifiedFingerprinter(config=config)

    # Spy on the analyze methods
    fingerprinter.analyzers['tcp'].analyze = AsyncMock(wraps=fingerprinter.analyzers['tcp'].analyze)
    fingerprinter.analyzers['http'].analyze = AsyncMock(wraps=fingerprinter.analyzers['http'].analyze)

    fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

    # Assert that only TCP analyzer was called
    fingerprinter.analyzers['tcp'].analyze.assert_called_once()
    fingerprinter.analyzers['http'].analyze.assert_not_called()
    assert fingerprint.tcp_analysis.status == AnalysisStatus.COMPLETED
    assert fingerprint.http_analysis.status == AnalysisStatus.NOT_STARTED

@pytest.mark.asyncio
async def test_fingerprint_target_comprehensive_analysis(mock_analyzers):
    """Test that comprehensive analysis runs all available analyzers."""
    config = FingerprintingConfig(analysis_level="comprehensive", enable_http_analysis=True, enable_tcp_analysis=True)
    fingerprinter = UnifiedFingerprinter(config=config)

    # Spy on the analyze methods
    fingerprinter.analyzers['tcp'].analyze = AsyncMock(wraps=fingerprinter.analyzers['tcp'].analyze)
    fingerprinter.analyzers['http'].analyze = AsyncMock(wraps=fingerprinter.analyzers['http'].analyze)

    # Mock the _run_..._safe methods to check they are called
    fingerprinter._run_tcp_analysis_safe = AsyncMock(wraps=fingerprinter._run_tcp_analysis_safe)
    fingerprinter._run_http_analysis_safe = AsyncMock(wraps=fingerprinter._run_http_analysis_safe)

    fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

    # Assert that both safe runner methods were called
    fingerprinter._run_tcp_analysis_safe.assert_called_once()
    fingerprinter._run_http_analysis_safe.assert_called_once()

    # Assert that the analysis results are populated
    assert fingerprint.tcp_analysis.status == AnalysisStatus.COMPLETED
    assert fingerprint.http_analysis.status == AnalysisStatus.COMPLETED

@pytest.mark.asyncio
async def test_fingerprint_batch_execution(mock_analyzers):
    """Test that batch fingerprinting runs for all targets."""
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config=config)

    targets = [("example.com", 443), ("test.com", 443)]

    # Mock fingerprint_target to verify it's called for each target
    fingerprinter.fingerprint_target = AsyncMock(side_effect=[
        UnifiedFingerprint(target="example.com", port=443),
        UnifiedFingerprint(target="test.com", port=443)
    ])

    results = await fingerprinter.fingerprint_batch(targets)

    assert len(results) == 2
    assert fingerprinter.fingerprint_target.call_count == 2
    assert results[0].target == "example.com"
    assert results[1].target == "test.com"