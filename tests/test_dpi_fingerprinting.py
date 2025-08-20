"""
Tests for DPI fingerprinting system.
Tests the basic and advanced fingerprinting capabilities.
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock

# Fix import for local cli.py
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
from cli import SimpleFingerprint, SimpleDPIClassifier, SimpleFingerprinter

# Configure pytest for async tests
pytest_plugins = ("pytest_asyncio",)


@pytest.fixture
def fingerprinter():
    """Create fingerprinter instance for testing"""
    return SimpleFingerprinter(debug=True)


@pytest.fixture
def mock_socket():
    """Create mock socket for testing"""
    socket = MagicMock()
    socket.getsockname.return_value = ("127.0.0.1", 12345)
    return socket


@pytest.fixture
def mock_connection():
    """Create mock connection for testing"""
    reader = AsyncMock()
    writer = MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    return reader, writer


def test_fingerprint_initialization():
    """Test fingerprint initialization"""
    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        rst_from_target=False,
        icmp_ttl_exceeded=False,
        tcp_options=("MSS", "WScale"),
        dpi_type="LIKELY_LINUX_BASED",
        blocking_method="tcp_reset",
    )

    assert fp.domain == "test.com"
    assert fp.target_ip == "192.168.1.1"
    assert fp.rst_ttl == 64
    assert fp.rst_from_target == False
    assert fp.icmp_ttl_exceeded == False
    assert fp.tcp_options == ("MSS", "WScale")
    assert fp.dpi_type == "LIKELY_LINUX_BASED"
    assert fp.blocking_method == "tcp_reset"
    assert fp.timestamp != ""


def test_fingerprint_to_dict():
    """Test fingerprint dictionary conversion"""
    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        blocking_method="tcp_reset",
    )

    data = fp.to_dict()

    assert isinstance(data, dict)
    assert data["domain"] == "test.com"
    assert data["target_ip"] == "192.168.1.1"
    assert data["rst_ttl"] == 64
    assert data["blocking_method"] == "tcp_reset"
    assert "timestamp" in data


def test_fingerprint_short_hash():
    """Test fingerprint hash generation"""
    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        dpi_type="LIKELY_LINUX_BASED",
        blocking_method="tcp_reset",
    )

    hash1 = fp.short_hash()

    # Create similar fingerprint with different blocking method
    fp2 = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        dpi_type="LIKELY_LINUX_BASED",
        blocking_method="tcp_timeout",
    )

    hash2 = fp2.short_hash()

    assert isinstance(hash1, str)
    assert len(hash1) == 10  # Should be 10 chars
    assert hash1 != hash2  # Different blocking methods should produce different hashes


def test_dpi_classifier_linux_based():
    """Test DPI classifier with Linux-based signatures"""
    classifier = SimpleDPIClassifier()

    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        rst_from_target=False,
        blocking_method="tcp_reset",
    )

    dpi_type = classifier.classify(fp)
    assert dpi_type == "LIKELY_LINUX_BASED"


def test_dpi_classifier_windows_based():
    """Test DPI classifier with Windows-based signatures"""
    classifier = SimpleDPIClassifier()

    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=128,
        rst_from_target=False,
        blocking_method="tcp_reset",
    )

    dpi_type = classifier.classify(fp)
    assert dpi_type == "LIKELY_WINDOWS_BASED"


def test_dpi_classifier_router_based():
    """Test DPI classifier with router-based signatures"""
    classifier = SimpleDPIClassifier()

    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=1,
        rst_from_target=False,
        blocking_method="tcp_reset",
    )

    dpi_type = classifier.classify(fp)
    assert dpi_type == "LIKELY_ROUTER_BASED"


def test_dpi_classifier_transparent_proxy():
    """Test DPI classifier with transparent proxy signatures"""
    classifier = SimpleDPIClassifier()

    fp = SimpleFingerprint(
        domain="test.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        rst_from_target=True,
        blocking_method="tcp_reset",
    )

    dpi_type = classifier.classify(fp)
    assert dpi_type == "LIKELY_TRANSPARENT_PROXY"


@pytest.mark.asyncio
async def test_fingerprinter_basic_tcp():
    """Test basic TCP connectivity fingerprinting"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock successful TCP connection
    with patch("asyncio.open_connection") as mock_open_conn:
        reader, writer = MagicMock(), MagicMock()
        mock_open_conn.return_value = (reader, writer)

        fp = await fingerprinter.create_fingerprint(
            domain="test.com", target_ip="192.168.1.1", port=443
        )

        assert fp.blocking_method == "tcp_ok"
        assert not fp.rst_from_target


@pytest.mark.asyncio
async def test_fingerprinter_tcp_reset():
    """Test TCP RST fingerprinting"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock connection that raises ConnectionResetError
    with patch("asyncio.open_connection") as mock_open_conn:
        mock_open_conn.side_effect = ConnectionResetError()

        fp = await fingerprinter.create_fingerprint(
            domain="test.com", target_ip="192.168.1.1", port=443
        )

        assert fp.blocking_method == "tcp_reset"
        assert fp.rst_from_target


@pytest.mark.asyncio
async def test_fingerprinter_tcp_timeout():
    """Test TCP timeout fingerprinting"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock connection that times out
    with patch("asyncio.open_connection") as mock_open_conn:
        mock_open_conn.side_effect = asyncio.TimeoutError()

        fp = await fingerprinter.create_fingerprint(
            domain="test.com", target_ip="192.168.1.1", port=443
        )

        assert fp.blocking_method == "tcp_timeout"


@pytest.mark.asyncio
async def test_fingerprinter_https():
    """Test HTTPS connectivity fingerprinting"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock successful TCP connection but failed HTTPS
    with patch("asyncio.open_connection") as mock_open_conn:
        reader, writer = MagicMock(), MagicMock()
        mock_open_conn.return_value = (reader, writer)

        # Mock aiohttp session
        session = MagicMock()
        response = MagicMock()
        response.status = 403

        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=session_cm):
            with patch.object(session, "get", return_value=response):
                fp = await fingerprinter.create_fingerprint(
                    domain="test.com", target_ip="192.168.1.1", port=443
                )

                assert fp.blocking_method == "https_status_403"


@pytest.mark.asyncio
async def test_fingerprinter_full_success():
    """Test successful end-to-end connection fingerprinting"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock successful TCP and HTTPS connections
    with patch("asyncio.open_connection") as mock_open_conn:
        reader, writer = MagicMock(), MagicMock()
        mock_open_conn.return_value = (reader, writer)

        # Mock aiohttp session with 200 response
        session = MagicMock()
        response = MagicMock()
        response.status = 200

        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=session_cm):
            with patch.object(session, "get", return_value=response):
                fp = await fingerprinter.create_fingerprint(
                    domain="test.com", target_ip="192.168.1.1", port=443
                )

                assert fp.blocking_method == "none"
                assert not fp.rst_from_target
                assert fp.dpi_type == "UNKNOWN_DPI"  # No DPI interference detected


@pytest.mark.asyncio
async def test_fingerprinter_error_handling():
    """Test fingerprinter error handling"""
    fingerprinter = SimpleFingerprinter(debug=True)

    # Mock various connection errors
    errors = [
        ConnectionRefusedError(),
        ConnectionAbortedError(),
        OSError("Network unreachable"),
        Exception("Unknown error"),
    ]

    for error in errors:
        with patch("asyncio.open_connection", side_effect=error):
            fp = await fingerprinter.create_fingerprint(
                domain="test.com", target_ip="192.168.1.1", port=443
            )

            assert "error" in fp.blocking_method.lower()
            assert fp.dpi_type == "UNKNOWN_DPI"


def test_fingerprint_comparison():
    """Test fingerprint comparison and similarity"""
    fp1 = SimpleFingerprint(
        domain="test1.com",
        target_ip="192.168.1.1",
        rst_ttl=64,
        rst_from_target=False,
        blocking_method="tcp_reset",
        dpi_type="LIKELY_LINUX_BASED",
    )

    # Similar fingerprint with same characteristics
    fp2 = SimpleFingerprint(
        domain="test2.com",
        target_ip="192.168.1.2",
        rst_ttl=64,
        rst_from_target=False,
        blocking_method="tcp_reset",
        dpi_type="LIKELY_LINUX_BASED",
    )

    # Different fingerprint
    fp3 = SimpleFingerprint(
        domain="test3.com",
        target_ip="192.168.1.3",
        rst_ttl=128,
        rst_from_target=True,
        blocking_method="tcp_timeout",
        dpi_type="LIKELY_WINDOWS_BASED",
    )

    # Similar fingerprints should have same hash
    assert fp1.short_hash() == fp2.short_hash()
    # Different fingerprint should have different hash
    assert fp1.short_hash() != fp3.short_hash()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
