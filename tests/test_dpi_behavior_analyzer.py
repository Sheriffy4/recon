# tests/fingerprint/test_dpi_behavior_analyzer.py
import pytest
from unittest.mock import patch, AsyncMock
from recon.core.fingerprint.dpi_behavior_analyzer import DPIBehaviorAnalyzer
from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType

pytest_plugins = ("pytest_asyncio",)


@pytest.fixture
def analyzer():
    return DPIBehaviorAnalyzer(timeout=1.0)


@pytest.mark.asyncio
async def test_analyze_timing_sensitivity(analyzer):
    """
    Tests the timing sensitivity analysis by mocking connection responses.
    """
    fp = DPIFingerprint(target="test.com:443")

    # Mock asyncio.open_connection to simulate different outcomes
    with patch("asyncio.open_connection") as mock_open_conn:
        # Simulate success for short delays, timeout for long delays
        async def open_conn_side_effect(*args, **kwargs):
            # This is a simplified mock; a real test might inspect the delay
            # passed to asyncio.sleep to alter behavior. For now, we alternate.
            if mock_open_conn.call_count % 2 == 1:
                # Success
                reader, writer = AsyncMock(), AsyncMock()
                writer.drain = AsyncMock()
                writer.close = AsyncMock()
                writer.wait_closed = AsyncMock()
                reader.read = AsyncMock(return_value=b"H")
                return reader, writer
            else:
                # Failure (e.g., timeout)
                raise asyncio.TimeoutError

        mock_open_conn.side_effect = open_conn_side_effect

        await analyzer._analyze_timing_sensitivity(fp)

        assert fp.timing_sensitivity is not None
        assert 0.0 <= fp.timing_sensitivity <= 1.0
        # With alternating success/failure, variance should be high
        assert fp.timing_sensitivity > 0.5
        assert "timing_analysis" in fp.raw_metrics


@pytest.mark.asyncio
async def test_analyze_block_patterns(analyzer):
    """
    Tests block pattern analysis for RST vs Timeout.
    """
    fp = DPIFingerprint(target="test.com:443")

    # Mock connection to raise ConnectionResetError
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open_conn:
        mock_open_conn.side_effect = ConnectionResetError("Connection reset by peer")

        await analyzer._analyze_block_patterns(fp)

        assert fp.block_type == "rst"
        assert fp.is_stateful is True  # RST injection implies stateful DPI
        assert "block_analysis" in fp.raw_metrics


@pytest.mark.asyncio
async def test_refine_fingerprint(analyzer):
    """
    Tests the refinement of a fingerprint based on bypass test results.
    """
    fp = DPIFingerprint(
        target="test.com:443",
        dpi_type=DPIType.UNKNOWN,
        confidence=0.5,
        timing_sensitivity=0.3,
    )

    test_results = {
        "successful_strategies": ["ip_fragmentation_attack", "timing_evasion"],
        "failed_strategies": ["header_manipulation"],
    }

    refined_fp = await analyzer.refine_fingerprint(fp, test_results)

    assert refined_fp.fragmentation_handling == "allowed"
    assert refined_fp.timing_sensitivity > 0.3  # Should increase
    assert refined_fp.confidence > 0.5  # Confidence should increase
    assert "strategy_testing" in refined_fp.raw_metrics
