"""
Tests for configuration rollback utilities.

This module tests the configuration rollback point creation logic,
including file backup, rollback info generation, and error handling.
"""

import json
import logging
import shutil
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from core.bypass.engine.config_rollback import create_rollback_point


class TestConfigRollback:
    """Test configuration rollback utilities."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")
        self.logger.setLevel(logging.DEBUG)
        # Create temporary directory for tests
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = Path.cwd()

    def teardown_method(self):
        """Clean up test fixtures."""
        # Clean up temporary directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
        # Clean up any rollback directories created during tests
        for rollback_dir in Path.cwd().glob("config_rollback_*"):
            if rollback_dir.is_dir():
                shutil.rmtree(rollback_dir)

    def test_create_rollback_point_basic(self):
        """Test basic rollback point creation."""
        rollback_dir = create_rollback_point(
            filtering_mode="domain",
            domain_based_filtering_enabled=True,
            logger=self.logger,
            config_files=[],  # Empty list to avoid file dependencies
        )

        # Check that directory was created
        assert Path(rollback_dir).exists()
        assert Path(rollback_dir).is_dir()

        # Check that rollback_info.json was created
        info_file = Path(rollback_dir) / "rollback_info.json"
        assert info_file.exists()

        # Verify rollback info content
        with open(info_file) as f:
            info = json.load(f)

        assert info["filtering_mode"] == "domain"
        assert info["domain_based_filtering_enabled"] is True
        assert "timestamp" in info
        assert "backed_up_files" in info
        assert "instructions" in info
        assert len(info["instructions"]) > 0

    def test_create_rollback_point_with_files(self):
        """Test rollback point creation with actual config files."""
        # Create temporary config files
        test_files = ["test_config1.json", "test_config2.txt"]
        for filename in test_files:
            Path(filename).write_text(f"test content for {filename}")

        try:
            rollback_dir = create_rollback_point(
                filtering_mode="ip",
                domain_based_filtering_enabled=False,
                logger=self.logger,
                config_files=test_files,
            )

            # Check that files were backed up
            for filename in test_files:
                backup_file = Path(rollback_dir) / Path(filename).name
                assert backup_file.exists()
                assert backup_file.read_text() == f"test content for {filename}"

            # Check rollback info
            info_file = Path(rollback_dir) / "rollback_info.json"
            with open(info_file) as f:
                info = json.load(f)

            assert len(info["backed_up_files"]) == len(test_files)
            assert all(f in info["backed_up_files"] for f in test_files)

        finally:
            # Clean up test files
            for filename in test_files:
                Path(filename).unlink(missing_ok=True)

    def test_create_rollback_point_nonexistent_files(self):
        """Test that nonexistent files are skipped gracefully."""
        rollback_dir = create_rollback_point(
            filtering_mode="hybrid",
            domain_based_filtering_enabled=True,
            logger=self.logger,
            config_files=["nonexistent1.json", "nonexistent2.txt"],
        )

        # Should succeed even though files don't exist
        assert Path(rollback_dir).exists()

        # Check that no files were backed up
        info_file = Path(rollback_dir) / "rollback_info.json"
        with open(info_file) as f:
            info = json.load(f)

        assert len(info["backed_up_files"]) == 0

    def test_rollback_dir_naming(self):
        """Test that rollback directory has correct timestamp format."""
        rollback_dir = create_rollback_point(
            filtering_mode="domain",
            domain_based_filtering_enabled=True,
            logger=self.logger,
            config_files=[],
        )

        # Check directory name format: config_rollback_YYYYMMDD_HHMMSS
        dir_name = Path(rollback_dir).name
        assert dir_name.startswith("config_rollback_")
        timestamp_part = dir_name.replace("config_rollback_", "")
        assert len(timestamp_part) == 15  # YYYYMMDD_HHMMSS
        assert "_" in timestamp_part

    def test_default_config_files(self):
        """Test that default config files list is used when None provided."""
        rollback_dir = create_rollback_point(
            filtering_mode="domain",
            domain_based_filtering_enabled=True,
            logger=self.logger,
            config_files=None,  # Should use defaults
        )

        assert Path(rollback_dir).exists()

        # Rollback info should be created even if no files exist
        info_file = Path(rollback_dir) / "rollback_info.json"
        assert info_file.exists()

    def test_exception_propagation(self):
        """Test that exceptions are properly propagated."""
        with patch("pathlib.Path.mkdir", side_effect=PermissionError("No permission")):
            with pytest.raises(PermissionError):
                create_rollback_point(
                    filtering_mode="domain",
                    domain_based_filtering_enabled=True,
                    logger=self.logger,
                    config_files=[],
                )


class TestBackwardCompatibility:
    """Test backward compatibility with base_engine.py."""

    def test_import_from_base_engine(self):
        """Test that function can be imported from base_engine."""
        from core.bypass.engine.base_engine import create_rollback_point

        assert callable(create_rollback_point)

    def test_engine_uses_config_rollback(self):
        """Test that WindowsBypassEngine uses config_rollback module."""
        from core.bypass.engine.base_engine import WindowsBypassEngine

        # Check that the method exists
        assert hasattr(WindowsBypassEngine, "create_configuration_rollback_point")
