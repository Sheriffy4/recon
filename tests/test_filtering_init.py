"""
Tests for filtering initialization utilities.

This module tests the runtime filtering initialization logic,
including domain loading and filter component setup.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock

import pytest

from core.bypass.engine.filtering_init import (
    load_domains_from_sites_file,
    initialize_runtime_filtering,
)


class TestLoadDomainsFromSitesFile:
    """Test domain loading from sites.txt."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.DEBUG)

    def test_load_domains_basic(self):
        """Test basic domain loading."""
        # Create temporary sites.txt
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("example.com\n")
            f.write("test.org\n")
            f.write("domain.net\n")
            temp_file = f.name

        try:
            domains = load_domains_from_sites_file(temp_file, self.logger)

            assert len(domains) == 3
            assert "example.com" in domains
            assert "test.org" in domains
            assert "domain.net" in domains

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_load_domains_with_comments(self):
        """Test domain loading with comments."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("# This is a comment\n")
            f.write("example.com\n")
            f.write("# Another comment\n")
            f.write("test.org\n")
            temp_file = f.name

        try:
            domains = load_domains_from_sites_file(temp_file, self.logger)

            assert len(domains) == 2
            assert "example.com" in domains
            assert "test.org" in domains

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_load_domains_with_empty_lines(self):
        """Test domain loading with empty lines."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("example.com\n")
            f.write("\n")
            f.write("test.org\n")
            f.write("   \n")
            f.write("domain.net\n")
            temp_file = f.name

        try:
            domains = load_domains_from_sites_file(temp_file, self.logger)

            assert len(domains) == 3

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_load_domains_case_insensitive(self):
        """Test that domains are converted to lowercase."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("Example.COM\n")
            f.write("TEST.org\n")
            temp_file = f.name

        try:
            domains = load_domains_from_sites_file(temp_file, self.logger)

            assert "example.com" in domains
            assert "test.org" in domains
            assert "Example.COM" not in domains

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_load_domains_nonexistent_file(self):
        """Test loading from nonexistent file."""
        domains = load_domains_from_sites_file("nonexistent_file.txt", self.logger)

        assert len(domains) == 0
        assert isinstance(domains, set)

    def test_load_domains_without_logger(self):
        """Test loading without logger (should not crash)."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("example.com\n")
            temp_file = f.name

        try:
            domains = load_domains_from_sites_file(temp_file, logger=None)

            assert len(domains) == 1
            assert "example.com" in domains

        finally:
            Path(temp_file).unlink(missing_ok=True)


class TestInitializeRuntimeFiltering:
    """Test runtime filtering initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.DEBUG)

    def test_initialize_with_all_components(self):
        """Test initialization when all components are available."""
        # Mock classes
        mock_filter_class = Mock()
        mock_config_class = Mock()
        mock_generator_class = Mock()
        mock_mode_enum = Mock()
        mock_mode_enum.BLACKLIST = "BLACKLIST"

        # Mock instances
        mock_filter = Mock()
        mock_generator = Mock()

        mock_filter_class.return_value = mock_filter
        mock_generator_class.return_value = mock_generator

        # Create temporary sites.txt
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("example.com\n")
            temp_file = f.name

        try:
            filter_obj, generator, enabled = initialize_runtime_filtering(
                runtime_filter_class=mock_filter_class,
                filter_config_class=mock_config_class,
                windivert_generator_class=mock_generator_class,
                filter_mode_enum=mock_mode_enum,
                logger=self.logger,
                sites_file_path=temp_file,
            )

            assert filter_obj is mock_filter
            assert generator is mock_generator
            assert enabled is False  # Default value

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_initialize_missing_components(self):
        """Test initialization when components are missing."""
        filter_obj, generator, enabled = initialize_runtime_filtering(
            runtime_filter_class=None,
            filter_config_class=None,
            windivert_generator_class=None,
            filter_mode_enum=None,
            logger=self.logger,
        )

        assert filter_obj is None
        assert generator is None
        assert enabled is False

    def test_initialize_with_exception(self):
        """Test initialization when exception occurs."""
        mock_filter_class = Mock(side_effect=Exception("Init failed"))
        mock_config_class = Mock()
        mock_generator_class = Mock()
        mock_mode_enum = Mock()
        mock_mode_enum.BLACKLIST = "BLACKLIST"

        filter_obj, generator, enabled = initialize_runtime_filtering(
            runtime_filter_class=mock_filter_class,
            filter_config_class=mock_config_class,
            windivert_generator_class=mock_generator_class,
            filter_mode_enum=mock_mode_enum,
            logger=self.logger,
        )

        assert filter_obj is None
        assert generator is None
        assert enabled is False


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that functions can be imported from base_engine."""
        from core.bypass.engine.base_engine import (
            initialize_runtime_filtering,
            load_domains_from_sites_file,
        )

        assert callable(initialize_runtime_filtering)
        assert callable(load_domains_from_sites_file)

    def test_engine_uses_filtering_init(self):
        """Test that WindowsBypassEngine uses filtering_init module."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        # Check that the method exists
        assert hasattr(WindowsBypassEngine, "_load_domains_from_sites_file")
