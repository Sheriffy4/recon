import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
from core.fingerprint.unified_models import UnifiedFingerprint, DPIType, AnalysisStatus, TCPAnalysisResult, HTTPAnalysisResult

@pytest.fixture
def mock_analyzers():
    """A fixture to provide mocked analyzer adapters."""
    mock_tcp_adapter = MagicMock()
    mock_tcp_adapter.analyze = AsyncMock(return_value=TCPAnalysisResult(status=AnalysisStatus.COMPLETED))

    mock_http_adapter = MagicMock()
    mock_http_adapter.analyze = AsyncMock(return_value=HTTPAnalysisResult(status=AnalysisStatus.COMPLETED))

    analyzers = {'tcp': mock_tcp_adapter, 'http': mock_http_adapter}

    with patch('core.fingerprint.unified_fingerprinter.get_available_analyzers', return_value=list(analyzers.keys())):
        with patch('core.fingerprint.unified_fingerprinter.check_analyzer_availability', return_value={name: {'available': True} for name in analyzers.keys()}):
            with patch('core.fingerprint.unified_fingerprinter.create_analyzer_adapter', side_effect=lambda name, **kwargs: analyzers.get(name)):
                yield analyzers

@pytest.mark.asyncio
async def test_fingerprint_target_fast_analysis(mock_analyzers):
    """Test that fast analysis only runs the TCP analyzer."""
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config=config)

    fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

    assert fingerprint.tcp_analysis.status == AnalysisStatus.COMPLETED
    assert fingerprint.http_analysis.status == AnalysisStatus.NOT_STARTED

@pytest.mark.asyncio
async def test_fingerprint_target_comprehensive_analysis(mock_analyzers):
    """Test that comprehensive analysis runs all available analyzers."""
    config = FingerprintingConfig(analysis_level="comprehensive")
    fingerprinter = UnifiedFingerprinter(config=config)

    fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

    assert fingerprint.tcp_analysis.status == AnalysisStatus.COMPLETED
    assert fingerprint.http_analysis.status == AnalysisStatus.COMPLETED

@pytest.mark.asyncio
async def test_fingerprint_batch_execution(mock_analyzers):
    """Test that batch fingerprinting runs for all targets."""
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config=config)

    targets = [("example.com", 443), ("test.com", 443)]

    fingerprinter.fingerprint_target = AsyncMock(side_effect=[
        UnifiedFingerprint(target="example.com", port=443),
        UnifiedFingerprint(target="test.com", port=443)
    ])

    results = await fingerprinter.fingerprint_batch(targets)

    assert len(results) == 2
    assert fingerprinter.fingerprint_target.call_count == 2
    assert results[0].target == "example.com"
    assert results[1].target == "test.com"