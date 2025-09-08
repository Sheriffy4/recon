#!/usr/bin/env python3
"""
Test suite for Configuration System - Task 16 Implementation
Tests configuration loading, validation, feature flags, and runtime updates.
"""

import unittest
import tempfile
import shutil
import yaml
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)

import sys

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from core.fingerprint.config import (
        AdvancedFingerprintingConfig,
        ConfigurationManager,
        NetworkConfig,
        CacheConfig,
        MLConfig,
        MonitoringConfig,
        AnalyzerConfig,
        PerformanceConfig,
        LoggingConfig,
        AnalyzerType,
        LogLevel,
        ConfigurationError,
        ConfigValidationError,
        ConfigLoadError,
        get_config_manager,
        get_config,
        load_config,
        save_config,
        create_default_config,
    )
except ImportError:
    from recon.core.fingerprint.config import (
        AdvancedFingerprintingConfig,
        ConfigurationManager,
        NetworkConfig,
        CacheConfig,
        MLConfig,
        MonitoringConfig,
        AnalyzerConfig,
        PerformanceConfig,
        LoggingConfig,
        AnalyzerType,
        LogLevel,
        ConfigValidationError,
        ConfigLoadError,
        get_config_manager,
        get_config,
        load_config,
        save_config,
        create_default_config,
    )


class TestConfigurationDataClasses(unittest.TestCase):
    """Test configuration data classes."""

    def test_network_config_defaults(self):
        """Test NetworkConfig default values."""
        config = NetworkConfig()

        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.retry_delay, 1.0)
        self.assertEqual(config.concurrent_limit, 10)
        self.assertIn("Mozilla", config.user_agent)
        self.assertIn("8.8.8.8", config.dns_servers)
        self.assertIsNone(config.bind_address)
        self.assertIsNone(config.proxy_url)

    def test_cache_config_defaults(self):
        """Test CacheConfig default values."""
        config = CacheConfig()

        self.assertTrue(config.enabled)
        self.assertEqual(config.cache_dir, "cache")
        self.assertEqual(config.max_size, 1000)
        self.assertEqual(config.ttl_seconds, 3600)
        self.assertEqual(config.cleanup_interval, 300)
        self.assertTrue(config.compression)
        self.assertTrue(config.backup_enabled)
        self.assertEqual(config.backup_interval, 86400)

    def test_ml_config_defaults(self):
        """Test MLConfig default values."""
        config = MLConfig()

        self.assertTrue(config.enabled)
        self.assertIn("dpi_classifier.joblib", config.model_path)
        self.assertIn("training_data.json", config.training_data_path)
        self.assertEqual(config.confidence_threshold, 0.7)
        self.assertEqual(config.retrain_threshold, 0.6)
        self.assertEqual(config.max_training_samples, 10000)
        self.assertTrue(config.feature_selection)
        self.assertEqual(config.cross_validation_folds, 5)
        self.assertEqual(config.random_state, 42)

    def test_monitoring_config_defaults(self):
        """Test MonitoringConfig default values."""
        config = MonitoringConfig()

        self.assertTrue(config.enabled)
        self.assertEqual(config.check_interval, 300)
        self.assertTrue(config.adaptive_frequency)
        self.assertEqual(config.min_interval, 60)
        self.assertEqual(config.max_interval, 3600)
        self.assertEqual(config.alert_threshold, 0.8)
        self.assertEqual(config.max_alerts_per_hour, 10)
        self.assertTrue(config.background_monitoring)

    def test_analyzer_config_defaults(self):
        """Test AnalyzerConfig default values."""
        config = AnalyzerConfig()

        self.assertTrue(config.enabled)
        self.assertEqual(config.timeout, 10.0)
        self.assertEqual(config.max_samples, 10)
        self.assertEqual(config.confidence_weight, 1.0)
        self.assertEqual(config.priority, 1)
        self.assertEqual(config.custom_params, {})

    def test_performance_config_defaults(self):
        """Test PerformanceConfig default values."""
        config = PerformanceConfig()

        self.assertEqual(config.max_concurrent_fingerprints, 5)
        self.assertEqual(config.fingerprint_timeout, 30.0)
        self.assertEqual(config.batch_size, 10)
        self.assertEqual(config.memory_limit_mb, 512)
        self.assertEqual(config.cpu_limit_percent, 80)
        self.assertFalse(config.enable_profiling)
        self.assertEqual(config.profile_output_dir, "profiles")

    def test_logging_config_defaults(self):
        """Test LoggingConfig default values."""
        config = LoggingConfig()

        self.assertEqual(config.level, LogLevel.INFO)
        self.assertIn("%(asctime)s", config.format)
        self.assertIsNone(config.file_path)
        self.assertEqual(config.max_file_size, 10485760)
        self.assertEqual(config.backup_count, 5)
        self.assertTrue(config.console_output)
        self.assertFalse(config.structured_logging)


class TestAdvancedFingerprintingConfig(unittest.TestCase):
    """Test main configuration class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = AdvancedFingerprintingConfig()

    def test_default_configuration(self):
        """Test default configuration values."""
        self.assertTrue(self.config.enabled)
        self.assertFalse(self.config.debug_mode)
        self.assertEqual(self.config.config_version, "1.0")

        # Check component configurations exist
        self.assertIsInstance(self.config.network, NetworkConfig)
        self.assertIsInstance(self.config.cache, CacheConfig)
        self.assertIsInstance(self.config.ml, MLConfig)
        self.assertIsInstance(self.config.monitoring, MonitoringConfig)
        self.assertIsInstance(self.config.performance, PerformanceConfig)
        self.assertIsInstance(self.config.logging, LoggingConfig)

        # Check analyzers
        self.assertIn("tcp", self.config.analyzers)
        self.assertIn("http", self.config.analyzers)
        self.assertIn("dns", self.config.analyzers)
        self.assertIn("ml_classifier", self.config.analyzers)

        # Check feature flags
        self.assertTrue(self.config.feature_flags["advanced_tcp_analysis"])
        self.assertTrue(self.config.feature_flags["ml_classification"])
        self.assertFalse(self.config.feature_flags["experimental_features"])

    def test_validate_valid_config(self):
        """Test validation of valid configuration."""
        errors = self.config.validate()
        self.assertEqual(len(errors), 0)

    def test_validate_invalid_network_config(self):
        """Test validation of invalid network configuration."""
        self.config.network.timeout = -1.0
        self.config.network.max_retries = -1
        self.config.network.concurrent_limit = 0

        errors = self.config.validate()

        self.assertGreater(len(errors), 0)
        self.assertTrue(any("timeout must be positive" in error for error in errors))
        self.assertTrue(any("retries cannot be negative" in error for error in errors))
        self.assertTrue(
            any("concurrent limit must be positive" in error for error in errors)
        )

    def test_validate_invalid_cache_config(self):
        """Test validation of invalid cache configuration."""
        self.config.cache.max_size = 0
        self.config.cache.ttl_seconds = -1

        errors = self.config.validate()

        self.assertGreater(len(errors), 0)
        self.assertTrue(any("max size must be positive" in error for error in errors))
        self.assertTrue(any("TTL must be positive" in error for error in errors))

    def test_validate_invalid_ml_config(self):
        """Test validation of invalid ML configuration."""
        self.config.ml.confidence_threshold = 1.5
        self.config.ml.retrain_threshold = -0.1

        errors = self.config.validate()

        self.assertGreater(len(errors), 0)
        self.assertTrue(
            any(
                "confidence threshold must be between 0 and 1" in error
                for error in errors
            )
        )
        self.assertTrue(
            any(
                "retrain threshold must be between 0 and 1" in error for error in errors
            )
        )

    def test_validate_invalid_analyzer_config(self):
        """Test validation of invalid analyzer configuration."""
        self.config.analyzers["tcp"].timeout = -1.0
        self.config.analyzers["http"].max_samples = 0
        self.config.analyzers["dns"].confidence_weight = -1.0

        errors = self.config.validate()

        self.assertGreater(len(errors), 0)
        self.assertTrue(
            any("tcp timeout must be positive" in error for error in errors)
        )
        self.assertTrue(
            any("http max samples must be positive" in error for error in errors)
        )
        self.assertTrue(
            any("dns confidence weight cannot be negative" in error for error in errors)
        )

    def test_is_analyzer_enabled(self):
        """Test analyzer enabled check."""
        # Test with string
        self.assertTrue(self.config.is_analyzer_enabled("tcp"))

        # Test with enum
        self.assertTrue(self.config.is_analyzer_enabled(AnalyzerType.HTTP))

        # Test disabled analyzer
        self.config.analyzers["tcp"].enabled = False
        self.assertFalse(self.config.is_analyzer_enabled("tcp"))

        # Test non-existent analyzer
        self.assertFalse(self.config.is_analyzer_enabled("non_existent"))

        # Test with disabled main config
        self.config.enabled = False
        self.assertFalse(self.config.is_analyzer_enabled("http"))

    def test_is_feature_enabled(self):
        """Test feature enabled check."""
        # Test enabled feature
        self.assertTrue(self.config.is_feature_enabled("ml_classification"))

        # Test disabled feature
        self.assertFalse(self.config.is_feature_enabled("experimental_features"))

        # Test non-existent feature
        self.assertFalse(self.config.is_feature_enabled("non_existent_feature"))

        # Test with disabled main config
        self.config.enabled = False
        self.assertFalse(self.config.is_feature_enabled("ml_classification"))

    def test_get_analyzer_config(self):
        """Test getting analyzer configuration."""
        # Test with string
        tcp_config = self.config.get_analyzer_config("tcp")
        self.assertIsInstance(tcp_config, AnalyzerConfig)
        self.assertEqual(tcp_config.timeout, 5.0)

        # Test with enum
        http_config = self.config.get_analyzer_config(AnalyzerType.HTTP)
        self.assertIsInstance(http_config, AnalyzerConfig)
        self.assertEqual(http_config.timeout, 10.0)

        # Test non-existent analyzer
        non_existent = self.config.get_analyzer_config("non_existent")
        self.assertIsNone(non_existent)

    def test_update_analyzer_config(self):
        """Test updating analyzer configuration."""
        # Update existing analyzer
        self.config.update_analyzer_config("tcp", timeout=15.0, max_samples=20)

        tcp_config = self.config.get_analyzer_config("tcp")
        self.assertEqual(tcp_config.timeout, 15.0)
        self.assertEqual(tcp_config.max_samples, 20)

        # Update non-existent analyzer (should create new)
        self.config.update_analyzer_config("new_analyzer", timeout=5.0)

        new_config = self.config.get_analyzer_config("new_analyzer")
        self.assertIsNotNone(new_config)
        self.assertEqual(new_config.timeout, 5.0)

    def test_enable_disable_analyzer(self):
        """Test enabling and disabling analyzers."""
        # Disable analyzer
        self.config.disable_analyzer("tcp")
        self.assertFalse(self.config.is_analyzer_enabled("tcp"))

        # Enable analyzer
        self.config.enable_analyzer("tcp")
        self.assertTrue(self.config.is_analyzer_enabled("tcp"))

        # Test with enum
        self.config.disable_analyzer(AnalyzerType.HTTP)
        self.assertFalse(self.config.is_analyzer_enabled(AnalyzerType.HTTP))

    def test_enable_disable_feature(self):
        """Test enabling and disabling features."""
        # Disable feature
        self.config.disable_feature("ml_classification")
        self.assertFalse(self.config.is_feature_enabled("ml_classification"))

        # Enable feature
        self.config.enable_feature("experimental_features")
        self.assertTrue(self.config.is_feature_enabled("experimental_features"))

    def test_to_dict(self):
        """Test converting configuration to dictionary."""
        config_dict = self.config.to_dict()

        self.assertIsInstance(config_dict, dict)
        self.assertIn("enabled", config_dict)
        self.assertIn("network", config_dict)
        self.assertIn("analyzers", config_dict)
        self.assertIn("feature_flags", config_dict)

        # Check nested structures
        self.assertIsInstance(config_dict["network"], dict)
        self.assertIsInstance(config_dict["analyzers"], dict)
        self.assertIn("tcp", config_dict["analyzers"])

    def test_from_dict(self):
        """Test creating configuration from dictionary."""
        config_dict = {
            "enabled": True,
            "debug_mode": True,
            "network": {"timeout": 10.0, "max_retries": 5},
            "analyzers": {"tcp": {"enabled": False, "timeout": 15.0}},
            "feature_flags": {"ml_classification": False},
        }

        config = AdvancedFingerprintingConfig.from_dict(config_dict)

        self.assertTrue(config.enabled)
        self.assertTrue(config.debug_mode)
        self.assertEqual(config.network.timeout, 10.0)
        self.assertEqual(config.network.max_retries, 5)
        self.assertFalse(config.analyzers["tcp"].enabled)
        self.assertEqual(config.analyzers["tcp"].timeout, 15.0)
        self.assertFalse(config.feature_flags["ml_classification"])


class TestConfigurationManager(unittest.TestCase):
    """Test configuration manager."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_config.yaml")
        self.manager = ConfigurationManager()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test configuration manager initialization."""
        self.assertIsInstance(self.manager.config, AdvancedFingerprintingConfig)
        self.assertEqual(len(self.manager._watchers), 0)

    def test_create_default_config(self):
        """Test creating default configuration file."""
        self.manager.create_default_config(self.config_path)

        self.assertTrue(os.path.exists(self.config_path))

        # Verify file content
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        self.assertIn("enabled", data)
        self.assertIn("network", data)
        self.assertIn("analyzers", data)

    def test_save_and_load_yaml_config(self):
        """Test saving and loading YAML configuration."""
        # Modify configuration
        self.manager.config.debug_mode = True
        self.manager.config.network.timeout = 15.0
        self.manager.config.disable_analyzer("tcp")

        # Save configuration
        self.manager.save_config(self.config_path)
        self.assertTrue(os.path.exists(self.config_path))

        # Load configuration
        new_manager = ConfigurationManager()
        loaded_config = new_manager.load_config(self.config_path)

        self.assertTrue(loaded_config.debug_mode)
        self.assertEqual(loaded_config.network.timeout, 15.0)
        self.assertFalse(loaded_config.is_analyzer_enabled("tcp"))

    def test_save_and_load_json_config(self):
        """Test saving and loading JSON configuration."""
        json_path = os.path.join(self.temp_dir, "test_config.json")

        # Modify configuration
        self.manager.config.ml.confidence_threshold = 0.9

        # Save as JSON
        self.manager.save_config(json_path)
        self.assertTrue(os.path.exists(json_path))

        # Load JSON configuration
        new_manager = ConfigurationManager()
        loaded_config = new_manager.load_config(json_path)

        self.assertEqual(loaded_config.ml.confidence_threshold, 0.9)

    def test_load_invalid_config_file(self):
        """Test loading invalid configuration file."""
        # Create invalid YAML file
        with open(self.config_path, "w") as f:
            f.write("invalid: yaml: content: [")

        with self.assertRaises(ConfigLoadError):
            self.manager.load_config(self.config_path)

    def test_load_nonexistent_config_file(self):
        """Test loading non-existent configuration file."""
        with self.assertRaises(ConfigLoadError):
            self.manager.load_config("/non/existent/path.yaml")

    def test_validate_invalid_config(self):
        """Test validation of invalid configuration."""
        # Create invalid configuration
        invalid_config = {"network": {"timeout": -1.0}}

        with open(self.config_path, "w") as f:
            yaml.dump(invalid_config, f)

        with self.assertRaises(ConfigValidationError):
            self.manager.load_config(self.config_path)

    def test_update_config(self):
        """Test updating configuration."""
        original_timeout = self.manager.config.network.timeout

        self.manager.update_config(debug_mode=True)

        self.assertTrue(self.manager.config.debug_mode)
        self.assertEqual(self.manager.config.network.timeout, original_timeout)

    def test_update_config_invalid(self):
        """Test updating configuration with invalid values."""
        with self.assertRaises(ConfigValidationError):
            self.manager.update_config(network=NetworkConfig(timeout=-1.0))

    def test_reset_to_defaults(self):
        """Test resetting configuration to defaults."""
        # Modify configuration
        self.manager.config.debug_mode = True
        self.manager.config.network.timeout = 99.0

        # Reset to defaults
        self.manager.reset_to_defaults()

        self.assertFalse(self.manager.config.debug_mode)
        self.assertEqual(self.manager.config.network.timeout, 5.0)

    def test_reload_if_changed(self):
        """Test reloading configuration if file changed."""
        # Save initial configuration
        self.manager.save_config(self.config_path)

        # Modify file externally
        import time

        time.sleep(0.1)  # Ensure different modification time

        modified_config = self.manager.config.to_dict()
        modified_config["debug_mode"] = True

        with open(self.config_path, "w") as f:
            yaml.dump(modified_config, f)

        # Reload if changed
        reloaded = self.manager.reload_if_changed()

        self.assertTrue(reloaded)
        self.assertTrue(self.manager.config.debug_mode)

    def test_reload_if_not_changed(self):
        """Test not reloading configuration if file unchanged."""
        # Save configuration
        self.manager.save_config(self.config_path)

        # Try to reload without changes
        reloaded = self.manager.reload_if_changed()

        self.assertFalse(reloaded)


class TestGlobalConfigurationFunctions(unittest.TestCase):
    """Test global configuration functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "global_test_config.yaml")

        # Reset global config manager
        import core.fingerprint.config as config_module

        config_module._config_manager = None

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Reset global config manager
        import core.fingerprint.config as config_module

        config_module._config_manager = None

    def test_get_config_manager(self):
        """Test getting global configuration manager."""
        manager1 = get_config_manager()
        manager2 = get_config_manager()

        # Should return same instance
        self.assertIs(manager1, manager2)
        self.assertIsInstance(manager1, ConfigurationManager)

    def test_get_config(self):
        """Test getting current configuration."""
        config = get_config()

        self.assertIsInstance(config, AdvancedFingerprintingConfig)
        self.assertTrue(config.enabled)

    def test_create_default_config_global(self):
        """Test creating default configuration globally."""
        create_default_config(self.config_path)

        self.assertTrue(os.path.exists(self.config_path))

        # Verify content
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        self.assertIn("enabled", data)
        self.assertTrue(data["enabled"])

    def test_load_config_global(self):
        """Test loading configuration globally."""
        # Create test configuration
        test_config = AdvancedFingerprintingConfig()
        test_config.debug_mode = True

        with open(self.config_path, "w") as f:
            yaml.dump(test_config.to_dict(), f)

        # Load configuration
        loaded_config = load_config(self.config_path)

        self.assertTrue(loaded_config.debug_mode)

    def test_save_config_global(self):
        """Test saving configuration globally."""
        # Modify global configuration
        config = get_config()
        config.debug_mode = True

        # Save configuration
        save_config(self.config_path)

        self.assertTrue(os.path.exists(self.config_path))

        # Verify content
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        self.assertTrue(data["debug_mode"])


class TestConfigurationIntegration(unittest.TestCase):
    """Test configuration system integration scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complex_configuration_scenario(self):
        """Test complex configuration scenario."""
        config_path = os.path.join(self.temp_dir, "complex_config.yaml")

        # Create complex configuration
        config = AdvancedFingerprintingConfig()

        # Modify various settings
        config.debug_mode = True
        config.network.timeout = 20.0
        config.network.concurrent_limit = 20
        config.cache.max_size = 5000
        config.ml.confidence_threshold = 0.85
        config.monitoring.check_interval = 600

        # Modify analyzers
        config.disable_analyzer("dns")
        config.update_analyzer_config("tcp", timeout=25.0, max_samples=15)
        config.update_analyzer_config(
            "custom_analyzer",
            enabled=True,
            timeout=10.0,
            custom_params={"param1": "value1"},
        )

        # Modify feature flags
        config.enable_feature("experimental_features")
        config.disable_feature("cache_compression")

        # Add custom settings
        config.custom_settings = {
            "custom_param1": "value1",
            "custom_param2": 42,
            "nested_param": {"sub_param": True},
        }

        # Save and reload
        manager = ConfigurationManager()
        manager.config = config
        manager.save_config(config_path)

        # Load in new manager
        new_manager = ConfigurationManager()
        loaded_config = new_manager.load_config(config_path)

        # Verify all settings
        self.assertTrue(loaded_config.debug_mode)
        self.assertEqual(loaded_config.network.timeout, 20.0)
        self.assertEqual(loaded_config.network.concurrent_limit, 20)
        self.assertEqual(loaded_config.cache.max_size, 5000)
        self.assertEqual(loaded_config.ml.confidence_threshold, 0.85)
        self.assertEqual(loaded_config.monitoring.check_interval, 600)

        # Verify analyzer settings
        self.assertFalse(loaded_config.is_analyzer_enabled("dns"))
        self.assertEqual(loaded_config.get_analyzer_config("tcp").timeout, 25.0)
        self.assertEqual(loaded_config.get_analyzer_config("tcp").max_samples, 15)

        custom_analyzer = loaded_config.get_analyzer_config("custom_analyzer")
        self.assertIsNotNone(custom_analyzer)
        self.assertTrue(custom_analyzer.enabled)
        self.assertEqual(custom_analyzer.custom_params["param1"], "value1")

        # Verify feature flags
        self.assertTrue(loaded_config.is_feature_enabled("experimental_features"))
        self.assertFalse(loaded_config.is_feature_enabled("cache_compression"))

        # Verify custom settings
        self.assertEqual(loaded_config.custom_settings["custom_param1"], "value1")
        self.assertEqual(loaded_config.custom_settings["custom_param2"], 42)
        self.assertTrue(loaded_config.custom_settings["nested_param"]["sub_param"])

    def test_configuration_migration_scenario(self):
        """Test configuration migration scenario."""
        # Create old-style configuration
        old_config = {
            "enabled": True,
            "timeout": 10.0,  # Old flat structure
            "cache_size": 2000,
            "ml_enabled": True,
            "analyzers": ["tcp", "http"],  # Old list format
        }

        config_path = os.path.join(self.temp_dir, "old_config.yaml")
        with open(config_path, "w") as f:
            yaml.dump(old_config, f)

        # This would normally require migration logic
        # For now, we test that the system handles missing fields gracefully
        try:
            manager = ConfigurationManager()
            # This should fail gracefully or use defaults
            config = AdvancedFingerprintingConfig.from_dict(old_config)

            # Should have defaults for missing fields
            self.assertIsInstance(config.network, NetworkConfig)
            self.assertIsInstance(config.cache, CacheConfig)

        except Exception as e:
            # Expected to fail with current implementation
            self.assertIsInstance(e, (TypeError, KeyError))


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
