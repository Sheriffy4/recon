"""
Unit tests for core.cli.helpers module.

Tests the helper functions extracted during Step 8 refactoring.
"""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock, MagicMock, patch, mock_open
from collections import defaultdict

# Import the functions we're testing
from core.cli.helpers import (
    normalize_domains,
    setup_pcap_capture,
    enable_verbose_strategy_logging,
    setup_domain_manager,
    setup_unified_engine,
    integrate_pcap_with_engine,
    load_domain_rules,
    display_kb_summary,
)


class TestNormalizeDomains:
    """Tests for normalize_domains function."""

    def test_normalize_single_domain(self):
        """Test normalization of a single domain."""
        domains = ["example.com"]
        result = normalize_domains(domains)
        assert result == ["https://example.com"]

    def test_normalize_multiple_domains(self):
        """Test normalization of multiple domains."""
        domains = ["example.com", "test.org"]
        result = normalize_domains(domains)
        assert result == ["https://example.com", "https://test.org"]

    def test_normalize_already_has_https(self):
        """Test that domains with https:// are not double-prefixed."""
        domains = ["https://example.com"]
        result = normalize_domains(domains)
        assert result == ["https://example.com"]

    def test_normalize_http_to_https(self):
        """Test that http:// is replaced with https://."""
        domains = ["http://example.com"]
        result = normalize_domains(domains)
        assert result == ["https://example.com"]

    def test_normalize_empty_list(self):
        """Test normalization of empty list."""
        domains = []
        result = normalize_domains(domains)
        assert result == []

    def test_normalize_mixed_formats(self):
        """Test normalization of mixed domain formats."""
        domains = [
            "example.com",
            "https://test.org",
            "http://another.com",
            "www.site.net",
        ]
        result = normalize_domains(domains)
        assert result == [
            "https://example.com",
            "https://test.org",
            "https://another.com",
            "https://www.site.net",
        ]


class TestSetupPcapCapture:
    """Tests for setup_pcap_capture function."""

    def test_no_pcap_requested(self):
        """Test when PCAP capture is not requested."""
        args = Mock(pcap=None)
        console = Mock()

        result = setup_pcap_capture(args, console)

        assert result is None
        console.print.assert_not_called()

    @patch("core.cli.helpers.PacketCapturer")
    @patch("core.cli.helpers.build_bpf_from_ips")
    def test_pcap_capture_setup_success(self, mock_bpf, mock_capturer_class):
        """Test successful PCAP capture setup."""
        args = Mock(pcap="test.pcap", port=443, capture_iface=None)
        console = Mock()
        mock_bpf.return_value = "tcp port 443"
        mock_capturer = Mock()
        mock_capturer_class.return_value = mock_capturer

        result = setup_pcap_capture(args, console)

        assert result == mock_capturer
        mock_capturer.start.assert_called_once()
        console.print.assert_called()

    @patch("core.cli.helpers.SCAPY_AVAILABLE", False)
    def test_pcap_capture_scapy_not_available(self):
        """Test when Scapy is not available."""
        args = Mock(pcap="test.pcap")
        console = Mock()

        result = setup_pcap_capture(args, console)

        assert result is None
        # Should print warning about Scapy not being available
        assert any("not available" in str(call) for call in console.print.call_args_list)


class TestEnableVerboseStrategyLogging:
    """Tests for enable_verbose_strategy_logging function."""

    @patch("core.cli.helpers.logging.getLogger")
    def test_enable_verbose_logging(self, mock_get_logger):
        """Test enabling verbose strategy logging."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        console = Mock()

        enable_verbose_strategy_logging(console)

        mock_logger.setLevel.assert_called()
        console.print.assert_called()

    @patch("core.cli.helpers.logging.getLogger")
    def test_enable_verbose_logging_exception(self, mock_get_logger):
        """Test exception handling in verbose logging setup."""
        mock_get_logger.side_effect = Exception("Test error")
        console = Mock()

        # Should not raise exception
        enable_verbose_strategy_logging(console)

        # Should print warning
        assert any("warning" in str(call).lower() for call in console.print.call_args_list)


class TestSetupDomainManager:
    """Tests for setup_domain_manager function."""

    @patch("core.cli.helpers.normalize_domains")
    @patch("core.cli.helpers.DomainManager")
    def test_setup_domain_manager_success(self, mock_dm_class, mock_normalize):
        """Test successful domain manager setup."""
        args = Mock(target="example.com,test.org")
        console = Mock()
        mock_normalize.return_value = ["https://example.com", "https://test.org"]
        mock_dm = Mock()
        mock_dm_class.return_value = mock_dm

        result = setup_domain_manager(args, console)

        assert result == mock_dm
        mock_normalize.assert_called_once()
        console.print.assert_called()

    def test_setup_domain_manager_no_target(self):
        """Test when no target is provided."""
        args = Mock(target=None)
        console = Mock()

        result = setup_domain_manager(args, console)

        assert result is None
        # Should print error message
        assert any("error" in str(call).lower() for call in console.print.call_args_list)

    def test_setup_domain_manager_empty_target(self):
        """Test when target is empty string."""
        args = Mock(target="")
        console = Mock()

        result = setup_domain_manager(args, console)

        assert result is None


class TestSetupUnifiedEngine:
    """Tests for setup_unified_engine function."""

    @patch("core.cli.helpers.enable_verbose_strategy_logging")
    @patch("core.cli.helpers.UnifiedBypassEngine")
    def test_setup_engine_success(self, mock_engine_class, mock_verbose):
        """Test successful engine setup."""
        args = Mock(verbose_strategy=True, debug=False)
        console = Mock()
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = setup_unified_engine(args, console)

        assert result == mock_engine
        mock_verbose.assert_called_once_with(console)
        console.print.assert_called()

    @patch("core.cli.helpers.enable_verbose_strategy_logging")
    @patch("core.cli.helpers.UnifiedBypassEngine")
    def test_setup_engine_no_verbose(self, mock_engine_class, mock_verbose):
        """Test engine setup without verbose logging."""
        args = Mock(verbose_strategy=False, debug=False)
        console = Mock()
        mock_engine = Mock()
        mock_engine_class.return_value = mock_engine

        result = setup_unified_engine(args, console)

        assert result == mock_engine
        mock_verbose.assert_not_called()


class TestIntegratePcapWithEngine:
    """Tests for integrate_pcap_with_engine function."""

    def test_integrate_with_capturer(self):
        """Test PCAP integration when capturer is available."""
        capturer = Mock()
        engine = Mock()
        console = Mock()

        integrate_pcap_with_engine(capturer, engine, console)

        engine.set_capturer.assert_called_once_with(capturer)
        console.print.assert_called()

    def test_integrate_without_capturer(self):
        """Test PCAP integration when capturer is None."""
        capturer = None
        engine = Mock()
        console = Mock()

        integrate_pcap_with_engine(capturer, engine, console)

        engine.set_capturer.assert_not_called()
        console.print.assert_not_called()


class TestLoadDomainRules:
    """Tests for load_domain_rules function."""

    @patch("builtins.open", new_callable=mock_open, read_data='{"rules": []}')
    @patch("core.cli.helpers.Path")
    def test_load_domain_rules_success(self, mock_path, mock_file):
        """Test successful domain rules loading."""
        console = Mock()
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        result = load_domain_rules(console)

        assert result == {"rules": []}
        console.print.assert_called()

    @patch("core.cli.helpers.Path")
    def test_load_domain_rules_file_not_found(self, mock_path):
        """Test when domain rules file doesn't exist."""
        console = Mock()
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        result = load_domain_rules(console)

        assert result is None
        # Should print error
        assert any("not found" in str(call).lower() for call in console.print.call_args_list)

    @patch("builtins.open", new_callable=mock_open, read_data='invalid json')
    @patch("core.cli.helpers.Path")
    def test_load_domain_rules_invalid_json(self, mock_path, mock_file):
        """Test when domain rules file contains invalid JSON."""
        console = Mock()
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        result = load_domain_rules(console)

        assert result is None
        # Should print error about invalid JSON
        assert any("error" in str(call).lower() for call in console.print.call_args_list)


class TestDisplayKbSummary:
    """Tests for display_kb_summary function."""

    @patch("core.cli.helpers.CdnAsnKnowledgeBase")
    def test_display_kb_summary_success(self, mock_kb_class):
        """Test successful KB summary display."""
        console = Mock()
        mock_kb = Mock()
        mock_kb.cdn_profiles = {
            "cloudflare": Mock(block_reasons={"reason1": 5, "reason2": 3})
        }
        mock_kb.domain_block_reasons = {
            "example.com": {"reason1": 10, "reason2": 5}
        }
        mock_kb_class.return_value = mock_kb

        display_kb_summary(console)

        # Should print CDN and domain summaries
        assert console.print.call_count >= 2

    @patch("core.cli.helpers.CdnAsnKnowledgeBase")
    def test_display_kb_summary_no_data(self, mock_kb_class):
        """Test KB summary when no data is available."""
        console = Mock()
        mock_kb = Mock()
        mock_kb.cdn_profiles = {}
        mock_kb.domain_block_reasons = {}
        mock_kb_class.return_value = mock_kb

        display_kb_summary(console)

        # Should not print summaries if no data
        # But should not raise exception

    @patch("core.cli.helpers.CdnAsnKnowledgeBase", side_effect=ImportError("KB not available"))
    def test_display_kb_summary_import_error(self, mock_kb_class):
        """Test KB summary when KB module is not available."""
        console = Mock()

        display_kb_summary(console)

        # Should print warning about unavailability
        assert any("unavailable" in str(call).lower() for call in console.print.call_args_list)


# Async test helpers
@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Mark all async tests
pytestmark = pytest.mark.asyncio


class TestAsyncHelpers:
    """Tests for async helper functions."""

    # These tests would require more complex mocking of async dependencies
    # Placeholder for future implementation

    async def test_setup_reporters_placeholder(self):
        """Placeholder for setup_reporters tests."""
        # TODO: Implement when async testing infrastructure is ready
        pass

    async def test_run_baseline_testing_placeholder(self):
        """Placeholder for run_baseline_testing tests."""
        # TODO: Implement when async testing infrastructure is ready
        pass

    async def test_run_dpi_fingerprinting_placeholder(self):
        """Placeholder for run_dpi_fingerprinting tests."""
        # TODO: Implement when async testing infrastructure is ready
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
