#!/usr/bin/env python3
"""
Test suite for Backward Compatibility Layer - Task 15 Implementation
Tests data migration, compatibility wrappers, and graceful handling of legacy formats.
"""

import unittest
import tempfile
import shutil
import json
import pickle
import os
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import sys

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from core.fingerprint.compatibility import (
        BackwardCompatibilityLayer,
        LegacyFingerprintWrapper,
        CompatibilityError,
        MigrationError,
        LegacyFormatError,
        migrate_legacy_data,
        create_legacy_wrapper,
    )
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
except ImportError:
    from recon.core.fingerprint.compatibility import (
        BackwardCompatibilityLayer,
        LegacyFingerprintWrapper,
        LegacyFormatError,
        migrate_legacy_data,
        create_legacy_wrapper,
    )
    from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType


class TestBackwardCompatibilityLayer(unittest.TestCase):
    """Test backward compatibility layer functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = os.path.join(self.temp_dir, "cache")
        self.backup_dir = os.path.join(self.temp_dir, "backup")

        os.makedirs(self.cache_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        self.compatibility_layer = BackwardCompatibilityLayer(
            cache_dir=self.cache_dir, backup_dir=self.backup_dir
        )

        # Create test legacy data
        self.legacy_dict_data = {
            "example.com_fingerprint": {
                "dpi_type": "ROSKOMNADZOR",
                "confidence": 0.85,
                "timestamp": 1640995200.0,
                "rst_detected": True,
                "header_filtering": True,
                "blocking_methods": ["RST", "HTTP"],
            },
            "blocked-site.com_fingerprint": {
                "type": "COMMERCIAL",
                "score": 0.92,
                "user_agent_block": True,
                "dns_hijack": False,
            },
        }

        self.legacy_string_data = {
            "simple-site.com": "ROSKOMNADZOR",
            "another-site.com": "COMMERCIAL",
        }

        self.legacy_list_data = {
            "list-site.com": ["GOVERNMENT", 0.95, {"rst_detected": True}],
            "basic-site.com": ["UNKNOWN", 0.3],
        }

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test compatibility layer initialization."""
        self.assertTrue(os.path.exists(self.cache_dir))
        self.assertTrue(os.path.exists(self.backup_dir))
        self.assertIsInstance(self.compatibility_layer.legacy_dpi_type_mapping, dict)
        self.assertEqual(len(self.compatibility_layer.migration_log), 0)

    def test_legacy_dpi_type_mapping(self):
        """Test legacy DPI type mapping."""
        mappings = self.compatibility_layer.legacy_dpi_type_mapping

        self.assertEqual(mappings["ROSKOMNADZOR"], DPIType.ROSKOMNADZOR_TSPU)
        self.assertEqual(mappings["COMMERCIAL"], DPIType.COMMERCIAL_DPI)
        self.assertEqual(mappings["GOVERNMENT"], DPIType.GOVERNMENT_CENSORSHIP)
        self.assertEqual(mappings["UNKNOWN"], DPIType.UNKNOWN)

    def test_create_legacy_cache_files(self):
        """Create test legacy cache files."""
        # Create pickle cache
        pickle_file = os.path.join(self.cache_dir, "fingerprint_cache.pkl")
        with open(pickle_file, "wb") as f:
            pickle.dump(self.legacy_dict_data, f)

        # Create JSON cache
        json_file = os.path.join(self.cache_dir, "simple_fingerprints.json")
        with open(json_file, "w") as f:
            json.dump(self.legacy_string_data, f)

        # Create text cache
        text_file = os.path.join(self.cache_dir, "text_cache.fingerprint")
        with open(text_file, "w") as f:
            f.write("# Legacy fingerprint cache\n")
            f.write("test-site.com=ROSKOMNADZOR\n")
            f.write('another-test.com:{"dpi_type": "COMMERCIAL", "confidence": 0.8}\n')

        return pickle_file, json_file, text_file

    def test_find_legacy_cache_files(self):
        """Test finding legacy cache files."""
        pickle_file, json_file, text_file = self.test_create_legacy_cache_files()

        found_files = self.compatibility_layer._find_legacy_cache_files()
        found_paths = [str(f) for f in found_files]

        self.assertIn(pickle_file, found_paths)
        self.assertIn(json_file, found_paths)
        self.assertIn(text_file, found_paths)

    def test_load_pickle_cache(self):
        """Test loading pickle cache files."""
        pickle_file, _, _ = self.test_create_legacy_cache_files()

        data = self.compatibility_layer._load_pickle_cache(Path(pickle_file))

        self.assertEqual(data, self.legacy_dict_data)
        self.assertIn("example.com_fingerprint", data)

    def test_load_json_cache(self):
        """Test loading JSON cache files."""
        _, json_file, _ = self.test_create_legacy_cache_files()

        data = self.compatibility_layer._load_json_cache(Path(json_file))

        self.assertEqual(data, self.legacy_string_data)
        self.assertIn("simple-site.com", data)

    def test_load_text_cache(self):
        """Test loading text cache files."""
        _, _, text_file = self.test_create_legacy_cache_files()

        data = self.compatibility_layer._load_text_cache(Path(text_file))

        self.assertIn("test-site.com", data)
        self.assertEqual(data["test-site.com"], "ROSKOMNADZOR")
        self.assertIn("another-test.com", data)
        self.assertIsInstance(data["another-test.com"], dict)

    def test_auto_detect_and_load(self):
        """Test auto-detection of file formats."""
        pickle_file, json_file, text_file = self.test_create_legacy_cache_files()

        # Test pickle detection
        pickle_data = self.compatibility_layer._auto_detect_and_load(Path(pickle_file))
        self.assertEqual(pickle_data, self.legacy_dict_data)

        # Test JSON detection
        json_data = self.compatibility_layer._auto_detect_and_load(Path(json_file))
        self.assertEqual(json_data, self.legacy_string_data)

        # Test text detection
        text_data = self.compatibility_layer._auto_detect_and_load(Path(text_file))
        self.assertIn("test-site.com", text_data)

    def test_convert_dict_entry(self):
        """Test converting dictionary-based legacy entries."""
        key = "example.com_fingerprint"
        value = self.legacy_dict_data[key]

        fingerprint = self.compatibility_layer._convert_dict_entry(key, value)

        self.assertIsInstance(fingerprint, DPIFingerprint)
        self.assertEqual(fingerprint.target, "example.com")
        self.assertEqual(fingerprint.dpi_type, DPIType.ROSKOMNADZOR_TSPU)
        self.assertEqual(fingerprint.confidence, 0.85)
        self.assertTrue(fingerprint.rst_injection_detected)
        self.assertTrue(fingerprint.http_header_filtering)

    def test_convert_string_entry(self):
        """Test converting string-based legacy entries."""
        key = "simple-site.com"
        value = "ROSKOMNADZOR"

        fingerprint = self.compatibility_layer._convert_string_entry(key, value)

        self.assertIsInstance(fingerprint, DPIFingerprint)
        self.assertEqual(fingerprint.target, "simple-site.com")
        self.assertEqual(fingerprint.dpi_type, DPIType.ROSKOMNADZOR_TSPU)
        self.assertEqual(fingerprint.confidence, 0.5)

    def test_convert_list_entry(self):
        """Test converting list-based legacy entries."""
        key = "list-site.com"
        value = ["GOVERNMENT", 0.95, {"rst_detected": True}]

        fingerprint = self.compatibility_layer._convert_list_entry(key, value)

        self.assertIsInstance(fingerprint, DPIFingerprint)
        self.assertEqual(fingerprint.target, "list-site.com")
        self.assertEqual(fingerprint.dpi_type, DPIType.GOVERNMENT_CENSORSHIP)
        self.assertEqual(fingerprint.confidence, 0.95)
        self.assertTrue(fingerprint.rst_injection_detected)

    def test_convert_legacy_entry_all_types(self):
        """Test converting all types of legacy entries."""
        # Dict entry
        dict_fp = self.compatibility_layer._convert_legacy_entry(
            "dict-site.com", {"dpi_type": "COMMERCIAL", "confidence": 0.8}
        )
        self.assertIsInstance(dict_fp, DPIFingerprint)
        self.assertEqual(dict_fp.dpi_type, DPIType.COMMERCIAL_DPI)

        # String entry
        string_fp = self.compatibility_layer._convert_legacy_entry(
            "string-site.com", "ROSKOMNADZOR"
        )
        self.assertIsInstance(string_fp, DPIFingerprint)
        self.assertEqual(string_fp.dpi_type, DPIType.ROSKOMNADZOR_TSPU)

        # List entry
        list_fp = self.compatibility_layer._convert_legacy_entry(
            "list-site.com", ["GOVERNMENT", 0.9]
        )
        self.assertIsInstance(list_fp, DPIFingerprint)
        self.assertEqual(list_fp.dpi_type, DPIType.GOVERNMENT_CENSORSHIP)

    @patch("core.fingerprint.compatibility.FingerprintCache")
    def test_save_migrated_fingerprint(self, mock_cache_class):
        """Test saving migrated fingerprints."""
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache

        fingerprint = DPIFingerprint(
            target="test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.8
        )

        self.compatibility_layer._save_migrated_fingerprint(fingerprint)

        mock_cache.set.assert_called_once_with("test.com", fingerprint)

    def test_save_migrated_fingerprint_fallback(self):
        """Test saving migrated fingerprints with fallback."""
        fingerprint = DPIFingerprint(
            target="test.com", dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.8
        )

        # This should use JSON fallback when cache import fails
        self.compatibility_layer._save_migrated_fingerprint(fingerprint)

        # Check if JSON file was created
        expected_file = Path(self.cache_dir) / "migrated_test_com.json"
        self.assertTrue(expected_file.exists())

        # Verify content
        with open(expected_file, "r") as f:
            data = json.load(f)

        self.assertEqual(data["target"], "test.com")
        self.assertEqual(data["dpi_type"], "commercial_dpi")

    def test_migrate_cache_file(self):
        """Test migrating a single cache file."""
        pickle_file, _, _ = self.test_create_legacy_cache_files()

        migrated_entries = self.compatibility_layer._migrate_cache_file(
            Path(pickle_file)
        )

        self.assertGreater(len(migrated_entries), 0)
        self.assertIsInstance(migrated_entries[0], DPIFingerprint)

        # Check that entries were migrated correctly
        targets = [fp.target for fp in migrated_entries]
        self.assertIn("example.com", targets)
        self.assertIn("blocked-site.com", targets)

    def test_migrate_legacy_cache_full_workflow(self):
        """Test full migration workflow."""
        # Create legacy files
        self.test_create_legacy_cache_files()

        # Run migration
        report = self.compatibility_layer.migrate_legacy_cache()

        # Verify report
        self.assertIn("started_at", report)
        self.assertIn("completed_at", report)
        self.assertGreater(report["files_processed"], 0)
        self.assertGreater(report["entries_migrated"], 0)

        # Verify backup was created
        backup_dirs = list(Path(self.backup_dir).glob("migration_backup_*"))
        self.assertGreater(len(backup_dirs), 0)

        # Verify migration report was saved
        report_files = list(Path(self.backup_dir).glob("migration_report_*.json"))
        self.assertGreater(len(report_files), 0)

    def test_validate_migration(self):
        """Test migration validation."""
        # Create and migrate legacy data
        pickle_file, _, _ = self.test_create_legacy_cache_files()
        self.compatibility_layer.migrate_legacy_cache()

        # Validate migration
        validation_report = self.compatibility_layer.validate_migration(
            pickle_file, self.cache_dir
        )

        self.assertIn("original_entries", validation_report)
        self.assertIn("migrated_entries", validation_report)
        self.assertIn("sample_comparisons", validation_report)
        self.assertGreater(validation_report["original_entries"], 0)

    def test_create_compatibility_wrapper(self):
        """Test creating compatibility wrapper."""
        wrapper = self.compatibility_layer.create_compatibility_wrapper()

        self.assertIsInstance(wrapper, LegacyFingerprintWrapper)
        self.assertEqual(wrapper.compatibility_layer, self.compatibility_layer)


class TestLegacyFingerprintWrapper(unittest.TestCase):
    """Test legacy fingerprint wrapper functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.compatibility_layer = BackwardCompatibilityLayer(
            cache_dir=os.path.join(self.temp_dir, "cache"),
            backup_dir=os.path.join(self.temp_dir, "backup"),
        )
        self.wrapper = LegacyFingerprintWrapper(self.compatibility_layer)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test wrapper initialization."""
        self.assertEqual(self.wrapper.compatibility_layer, self.compatibility_layer)
        self.assertIsNone(self.wrapper._advanced_fingerprinter)

    @patch("core.fingerprint.compatibility.AdvancedFingerprinter")
    def test_get_advanced_fingerprint_success(self, mock_fingerprinter_class):
        """Test getting advanced fingerprint successfully."""
        # Mock advanced fingerprinter
        mock_fingerprinter = Mock()
        mock_fingerprinter_class.return_value = mock_fingerprinter

        # Mock async fingerprint method
        async def mock_fingerprint_target(target):
            return DPIFingerprint(
                target=target, dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.85
            )

        mock_fingerprinter.fingerprint_target = AsyncMock(
            side_effect=mock_fingerprint_target
        )

        # Test getting fingerprint
        fingerprint = self.wrapper._get_advanced_fingerprint("test.com")

        self.assertIsInstance(fingerprint, DPIFingerprint)
        self.assertEqual(fingerprint.target, "test.com")
        self.assertEqual(fingerprint.dpi_type, DPIType.COMMERCIAL_DPI)

    def test_get_advanced_fingerprint_failure(self):
        """Test handling advanced fingerprinting failure."""
        # This should fail gracefully and return None
        fingerprint = self.wrapper._get_advanced_fingerprint("test.com")
        self.assertIsNone(fingerprint)

    def test_convert_to_legacy_format(self):
        """Test converting advanced fingerprint to legacy format."""
        advanced_fp = DPIFingerprint(
            target="test.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
            http_header_filtering=True,
            dns_hijacking_detected=False,
            user_agent_filtering=True,
            supports_ipv6=False,
        )

        legacy_fp = self.wrapper._convert_to_legacy_format(advanced_fp)

        self.assertEqual(legacy_fp["dpi_type"], "ROSKOMNADZOR")
        self.assertEqual(legacy_fp["confidence"], 0.85)
        self.assertIn("RST", legacy_fp["blocking_methods"])
        self.assertIn("HTTP", legacy_fp["blocking_methods"])
        self.assertNotIn("DNS", legacy_fp["blocking_methods"])
        self.assertTrue(legacy_fp["rst_detected"])
        self.assertTrue(legacy_fp["header_filtering"])
        self.assertFalse(legacy_fp["dns_hijack"])
        self.assertTrue(legacy_fp["user_agent_block"])
        self.assertFalse(legacy_fp["supports_ipv6"])

    def test_simple_fallback_detection(self):
        """Test simple fallback detection."""
        # Mock socket connection
        with patch("socket.create_connection") as mock_connect:
            mock_connect.return_value = Mock()

            legacy_fp = self.wrapper._simple_fallback_detection("test.com")

            self.assertIn("dpi_type", legacy_fp)
            self.assertIn("confidence", legacy_fp)
            self.assertIn("timestamp", legacy_fp)
            self.assertTrue(legacy_fp.get("fallback_used", False))

    def test_simple_fallback_detection_failure(self):
        """Test simple fallback detection with connection failure."""
        # Mock socket connection failure
        with patch(
            "socket.create_connection", side_effect=Exception("Connection failed")
        ):
            legacy_fp = self.wrapper._simple_fallback_detection("test.com")

            self.assertEqual(legacy_fp["dpi_type"], "UNKNOWN")
            self.assertEqual(legacy_fp["confidence"], 0.1)

    def test_create_unknown_fingerprint(self):
        """Test creating unknown fingerprint."""
        unknown_fp = self.wrapper._create_unknown_fingerprint("test.com")

        self.assertEqual(unknown_fp["dpi_type"], "UNKNOWN")
        self.assertEqual(unknown_fp["confidence"], 0.0)
        self.assertTrue(unknown_fp.get("error", False))
        self.assertEqual(unknown_fp["target"], "test.com")

    def test_get_simple_fingerprint_with_fallback(self):
        """Test getting simple fingerprint with fallback."""
        # This should use fallback since advanced fingerprinting will fail
        legacy_fp = self.wrapper.get_simple_fingerprint("test.com")

        self.assertIsInstance(legacy_fp, dict)
        self.assertIn("dpi_type", legacy_fp)
        self.assertIn("confidence", legacy_fp)
        self.assertIn("timestamp", legacy_fp)

    def test_is_blocked(self):
        """Test legacy is_blocked method."""
        # Mock get_simple_fingerprint
        with patch.object(self.wrapper, "get_simple_fingerprint") as mock_get_fp:
            # Test blocked case
            mock_get_fp.return_value = {"dpi_type": "ROSKOMNADZOR"}
            self.assertTrue(self.wrapper.is_blocked("blocked.com"))

            # Test not blocked case
            mock_get_fp.return_value = {"dpi_type": "UNKNOWN"}
            self.assertFalse(self.wrapper.is_blocked("unblocked.com"))

    def test_get_blocking_type(self):
        """Test legacy get_blocking_type method."""
        # Mock get_simple_fingerprint
        with patch.object(self.wrapper, "get_simple_fingerprint") as mock_get_fp:
            mock_get_fp.return_value = {"dpi_type": "COMMERCIAL"}

            blocking_type = self.wrapper.get_blocking_type("test.com")
            self.assertEqual(blocking_type, "COMMERCIAL")


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_migrate_legacy_data(self):
        """Test migrate_legacy_data convenience function."""
        cache_dir = os.path.join(self.temp_dir, "cache")
        backup_dir = os.path.join(self.temp_dir, "backup")

        report = migrate_legacy_data(cache_dir, backup_dir)

        self.assertIsInstance(report, dict)
        self.assertIn("started_at", report)
        self.assertIn("files_processed", report)

    def test_create_legacy_wrapper(self):
        """Test create_legacy_wrapper convenience function."""
        wrapper = create_legacy_wrapper()

        self.assertIsInstance(wrapper, LegacyFingerprintWrapper)
        self.assertIsInstance(wrapper.compatibility_layer, BackwardCompatibilityLayer)


class TestErrorHandling(unittest.TestCase):
    """Test error handling in compatibility layer."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.compatibility_layer = BackwardCompatibilityLayer(
            cache_dir=os.path.join(self.temp_dir, "cache"),
            backup_dir=os.path.join(self.temp_dir, "backup"),
        )

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_migration_error_handling(self):
        """Test migration error handling."""
        # Create invalid pickle file
        invalid_file = os.path.join(self.temp_dir, "invalid.pkl")
        with open(invalid_file, "w") as f:
            f.write("invalid pickle data")

        # Migration should handle the error gracefully
        report = self.compatibility_layer.migrate_legacy_cache(invalid_file)

        self.assertGreater(len(report["errors"]), 0)
        self.assertEqual(report["entries_failed"], 1)

    def test_legacy_format_error(self):
        """Test legacy format error handling."""
        # Create file with unknown format
        unknown_file = os.path.join(self.temp_dir, "unknown.dat")
        with open(unknown_file, "wb") as f:
            f.write(b"\x00\x01\x02\x03")  # Binary data

        # Should raise LegacyFormatError
        with self.assertRaises(LegacyFormatError):
            self.compatibility_layer._auto_detect_and_load(Path(unknown_file))

    def test_convert_legacy_entry_error_handling(self):
        """Test error handling in legacy entry conversion."""
        # Invalid entry should return None
        result = self.compatibility_layer._convert_legacy_entry("test", object())
        self.assertIsNone(result)

        # Malformed dict should be handled gracefully
        malformed_dict = {"invalid": "data", "no_dpi_type": True}
        result = self.compatibility_layer._convert_legacy_entry("test", malformed_dict)
        self.assertIsInstance(result, DPIFingerprint)  # Should create with defaults


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios and edge cases."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.compatibility_layer = BackwardCompatibilityLayer(
            cache_dir=os.path.join(self.temp_dir, "cache"),
            backup_dir=os.path.join(self.temp_dir, "backup"),
        )

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_mixed_format_migration(self):
        """Test migration with mixed legacy formats."""
        # Create multiple legacy files with different formats
        cache_dir = Path(self.temp_dir)
        cache_dir.mkdir(exist_ok=True)

        # Pickle file
        pickle_data = {"site1.com": {"dpi_type": "ROSKOMNADZOR", "confidence": 0.8}}
        with open(cache_dir / "fingerprint_cache.pkl", "wb") as f:
            pickle.dump(pickle_data, f)

        # JSON file
        json_data = {"site2.com": "COMMERCIAL"}
        with open(cache_dir / "simple_fingerprints.json", "w") as f:
            json.dump(json_data, f)

        # Text file
        with open(cache_dir / "text.fingerprint", "w") as f:
            f.write("site3.com=GOVERNMENT\n")

        # Run migration from the temp directory
        layer = BackwardCompatibilityLayer(cache_dir=str(cache_dir), backup_dir=str(Path(self.temp_dir) / "backup"))
        report = layer.migrate_legacy_cache()

        # Should process all files
        self.assertEqual(report["files_processed"], 3)
        self.assertGreater(report["entries_migrated"], 0)

    def test_large_cache_migration(self):
        """Test migration with large cache files."""
        # Create large legacy cache
        large_data = {}
        for i in range(100):
            large_data[f"site{i}.com"] = {
                "dpi_type": "COMMERCIAL",
                "confidence": 0.5 + (i % 50) / 100,
                "rst_detected": i % 2 == 0,
                "header_filtering": i % 3 == 0,
            }

        cache_file = Path(self.temp_dir) / "large_cache.pkl"
        with open(cache_file, "wb") as f:
            pickle.dump(large_data, f)

        # Run migration
        report = self.compatibility_layer.migrate_legacy_cache(str(cache_file))

        # Should migrate all entries
        self.assertEqual(report["entries_migrated"], 100)
        self.assertEqual(report["entries_failed"], 0)

    def test_corrupted_cache_handling(self):
        """Test handling of corrupted cache files."""
        # Create corrupted pickle file
        corrupted_file = Path(self.temp_dir) / "corrupted.pkl"
        with open(corrupted_file, "wb") as f:
            f.write(b"corrupted pickle data")

        # Migration should handle corruption gracefully
        report = self.compatibility_layer.migrate_legacy_cache(str(corrupted_file))

        self.assertGreater(len(report["errors"]), 0)
        self.assertEqual(report["entries_migrated"], 0)

    def test_empty_cache_migration(self):
        """Test migration with empty cache files."""
        # Create empty files in the cache directory
        cache_dir = Path(self.temp_dir)

        empty_pickle = cache_dir / "fingerprint_cache.pkl"
        with open(empty_pickle, "wb") as f:
            pickle.dump({}, f)

        empty_json = cache_dir / "simple_fingerprints.json"
        with open(empty_json, "w") as f:
            json.dump({}, f)

        layer = BackwardCompatibilityLayer(cache_dir=str(cache_dir), backup_dir=str(Path(self.temp_dir) / "backup"))
        # Run migration
        report = layer.migrate_legacy_cache()

        # Should process files but migrate no entries
        self.assertEqual(report["files_processed"], 2)
        self.assertEqual(report["entries_migrated"], 0)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
