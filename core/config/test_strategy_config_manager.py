"""
Unit tests for the enhanced strategy configuration manager.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, mock_open

from .strategy_config_manager import (
    StrategyConfigManager,
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
    ConfigurationError
)


class TestStrategyMetadata(unittest.TestCase):
    """Test StrategyMetadata dataclass."""
    
    def test_default_values(self):
        """Test default metadata values."""
        metadata = StrategyMetadata()
        self.assertEqual(metadata.priority, 1)
        self.assertEqual(metadata.description, "")
        self.assertEqual(metadata.success_rate, 0.0)
        self.assertEqual(metadata.avg_latency_ms, 0.0)
        self.assertIsNone(metadata.last_tested)
        self.assertEqual(metadata.test_count, 0)
        self.assertIsNone(metadata.created_at)
        self.assertIsNone(metadata.updated_at)
    
    def test_custom_values(self):
        """Test custom metadata values."""
        metadata = StrategyMetadata(
            priority=2,
            description="Test strategy",
            success_rate=0.85,
            avg_latency_ms=150.5,
            test_count=10
        )
        self.assertEqual(metadata.priority, 2)
        self.assertEqual(metadata.description, "Test strategy")
        self.assertEqual(metadata.success_rate, 0.85)
        self.assertEqual(metadata.avg_latency_ms, 150.5)
        self.assertEqual(metadata.test_count, 10)


class TestStrategyRule(unittest.TestCase):
    """Test StrategyRule dataclass."""
    
    def test_wildcard_detection(self):
        """Test wildcard pattern detection."""
        # Test wildcard patterns
        rule1 = StrategyRule("*.example.com", "strategy1", StrategyMetadata())
        self.assertTrue(rule1.is_wildcard)
        
        rule2 = StrategyRule("test?.example.com", "strategy2", StrategyMetadata())
        self.assertTrue(rule2.is_wildcard)
        
        # Test exact patterns
        rule3 = StrategyRule("example.com", "strategy3", StrategyMetadata())
        self.assertFalse(rule3.is_wildcard)
    
    def test_static_wildcard_method(self):
        """Test static wildcard detection method."""
        self.assertTrue(StrategyRule._is_wildcard_pattern("*.example.com"))
        self.assertTrue(StrategyRule._is_wildcard_pattern("test?.com"))
        self.assertFalse(StrategyRule._is_wildcard_pattern("example.com"))


class TestStrategyConfiguration(unittest.TestCase):
    """Test StrategyConfiguration dataclass."""
    
    def test_default_initialization(self):
        """Test default configuration initialization."""
        config = StrategyConfiguration()
        self.assertEqual(config.version, "3.0")
        self.assertEqual(config.strategy_priority, ["domain", "ip", "global"])
        self.assertEqual(config.domain_strategies, {})
        self.assertEqual(config.ip_strategies, {})
        self.assertIsNone(config.global_strategy)
        self.assertIsNotNone(config.last_updated)


class TestStrategyConfigManager(unittest.TestCase):
    """Test StrategyConfigManager class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = StrategyConfigManager(self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test manager initialization."""
        manager = StrategyConfigManager("/test/path")
        self.assertEqual(manager.config_dir, Path("/test/path"))
        self.assertEqual(manager.config_file.name, "domain_strategies.json")
    
    def test_create_default_configuration(self):
        """Test default configuration creation."""
        config = self.config_manager._create_default_configuration()
        
        self.assertEqual(config.version, "3.0")
        self.assertIsNotNone(config.global_strategy)
        self.assertEqual(config.global_strategy.pattern, "*")
        self.assertIn("badsum_race", config.global_strategy.strategy)
    
    def test_load_nonexistent_configuration(self):
        """Test loading configuration when file doesn't exist."""
        config = self.config_manager.load_configuration()
        
        # Should create default configuration
        self.assertEqual(config.version, "3.0")
        self.assertIsNotNone(config.global_strategy)
    
    def test_save_and_load_configuration(self):
        """Test saving and loading configuration."""
        # Create test configuration
        metadata = StrategyMetadata(
            priority=1,
            description="Test strategy",
            success_rate=0.85
        )
        
        rule = StrategyRule(
            pattern="*.example.com",
            strategy="--dpi-desync=multisplit --dpi-desync-split-count=5",
            metadata=metadata
        )
        
        config = StrategyConfiguration()
        config.domain_strategies["*.example.com"] = rule
        
        # Save configuration
        self.config_manager.save_configuration(config)
        
        # Load configuration
        loaded_config = self.config_manager.load_configuration()
        
        self.assertEqual(loaded_config.version, "3.0")
        self.assertIn("*.example.com", loaded_config.domain_strategies)
        
        loaded_rule = loaded_config.domain_strategies["*.example.com"]
        self.assertEqual(loaded_rule.pattern, "*.example.com")
        self.assertTrue(loaded_rule.is_wildcard)
        self.assertEqual(loaded_rule.metadata.priority, 1)
        self.assertEqual(loaded_rule.metadata.description, "Test strategy")
    
    def test_convert_legacy_config(self):
        """Test conversion of legacy v2.0 configuration."""
        legacy_config = {
            "version": "2.0",
            "last_updated": "2025-01-01T00:00:00",
            "domain_strategies": {
                "default": {
                    "domain": "default",
                    "strategy": "--dpi-desync=badsum_race",
                    "success_rate": 0.8,
                    "avg_latency_ms": 200.0,
                    "test_count": 100
                },
                "example.com": {
                    "domain": "example.com",
                    "strategy": "--dpi-desync=multisplit",
                    "success_rate": 0.9,
                    "avg_latency_ms": 150.0,
                    "test_count": 50
                }
            }
        }
        
        config = self.config_manager._convert_legacy_config(legacy_config)
        
        # Check version upgrade
        self.assertEqual(config.version, "3.0")
        
        # Check global strategy conversion
        self.assertIsNotNone(config.global_strategy)
        self.assertEqual(config.global_strategy.pattern, "*")
        self.assertIn("badsum_race", config.global_strategy.strategy)
        self.assertEqual(config.global_strategy.metadata.success_rate, 0.8)
        
        # Check domain strategy conversion
        self.assertIn("example.com", config.domain_strategies)
        rule = config.domain_strategies["example.com"]
        self.assertEqual(rule.pattern, "example.com")
        self.assertIn("multisplit", rule.strategy)
        self.assertEqual(rule.metadata.success_rate, 0.9)
        self.assertEqual(rule.metadata.priority, 1)
    
    def test_add_domain_strategy(self):
        """Test adding domain strategy."""
        self.config_manager.load_configuration()  # Initialize config
        
        metadata = StrategyMetadata(
            priority=2,
            description="Twitter CDN strategy"
        )
        
        self.config_manager.add_domain_strategy(
            "*.twimg.com",
            "--dpi-desync=multisplit --dpi-desync-split-count=7",
            metadata
        )
        
        strategies = self.config_manager.get_domain_strategies()
        self.assertIn("*.twimg.com", strategies)
        
        rule = strategies["*.twimg.com"]
        self.assertTrue(rule.is_wildcard)
        self.assertEqual(rule.metadata.priority, 2)
        self.assertEqual(rule.metadata.description, "Twitter CDN strategy")
    
    def test_remove_domain_strategy(self):
        """Test removing domain strategy."""
        self.config_manager.load_configuration()
        
        # Add strategy first
        self.config_manager.add_domain_strategy(
            "test.com",
            "--dpi-desync=fake"
        )
        
        # Verify it exists
        strategies = self.config_manager.get_domain_strategies()
        self.assertIn("test.com", strategies)
        
        # Remove it
        result = self.config_manager.remove_domain_strategy("test.com")
        self.assertTrue(result)
        
        # Verify it's gone
        strategies = self.config_manager.get_domain_strategies()
        self.assertNotIn("test.com", strategies)
        
        # Try to remove non-existent
        result = self.config_manager.remove_domain_strategy("nonexistent.com")
        self.assertFalse(result)
    
    def test_get_wildcard_patterns(self):
        """Test getting wildcard patterns."""
        self.config_manager.load_configuration()
        
        # Add mixed patterns
        self.config_manager.add_domain_strategy("*.example.com", "strategy1")
        self.config_manager.add_domain_strategy("exact.com", "strategy2")
        self.config_manager.add_domain_strategy("test?.net", "strategy3")
        
        wildcards = self.config_manager.get_wildcard_patterns()
        
        self.assertIn("*.example.com", wildcards)
        self.assertIn("test?.net", wildcards)
        self.assertNotIn("exact.com", wildcards)
    
    def test_validate_strategy_syntax(self):
        """Test strategy syntax validation."""
        manager = self.config_manager
        
        # Valid strategies
        self.assertTrue(manager.validate_strategy_syntax(
            "--dpi-desync=multisplit --dpi-desync-split-count=5"
        ))
        self.assertTrue(manager.validate_strategy_syntax(
            "seqovl(split_pos=76, overlap_size=336)"
        ))
        self.assertTrue(manager.validate_strategy_syntax(
            "fakedisorder(split_pos=midsld, ttl=4)"
        ))
        
        # Invalid strategies
        self.assertFalse(manager.validate_strategy_syntax("invalid_strategy"))
        self.assertFalse(manager.validate_strategy_syntax(""))
    
    def test_configuration_validation(self):
        """Test configuration validation."""
        # Valid configuration
        config = StrategyConfiguration()
        config.domain_strategies["test.com"] = StrategyRule(
            "test.com",
            "--dpi-desync=fake",
            StrategyMetadata()
        )
        
        # Should not raise exception
        self.config_manager._validate_configuration(config)
        
        # Invalid version
        config.version = "999.0"
        with self.assertRaises(ConfigurationError):
            self.config_manager._validate_configuration(config)
        
        # Invalid strategy priority
        config.version = "3.0"
        config.strategy_priority = ["invalid", "priority"]
        with self.assertRaises(ConfigurationError):
            self.config_manager._validate_configuration(config)
        
        # Empty strategy
        config.strategy_priority = ["domain", "ip", "global"]
        config.domain_strategies["empty.com"] = StrategyRule(
            "empty.com",
            "",
            StrategyMetadata()
        )
        with self.assertRaises(ConfigurationError):
            self.config_manager._validate_configuration(config)
    
    def test_backup_creation(self):
        """Test backup file creation during save."""
        # Create initial configuration
        config = StrategyConfiguration()
        self.config_manager.save_configuration(config)
        
        # Modify and save again (should create backup)
        config.domain_strategies["test.com"] = StrategyRule(
            "test.com",
            "--dpi-desync=fake",
            StrategyMetadata()
        )
        self.config_manager.save_configuration(config, create_backup=True)
        
        # Check backup exists
        backup_file = self.config_manager.config_file.with_suffix(
            self.config_manager.config_file.suffix + self.config_manager.BACKUP_SUFFIX
        )
        self.assertTrue(backup_file.exists())
    
    def test_invalid_json_handling(self):
        """Test handling of invalid JSON files."""
        # Create invalid JSON file
        invalid_json = "{ invalid json content"
        config_file = self.config_manager.config_file
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            f.write(invalid_json)
        
        with self.assertRaises(ConfigurationError):
            self.config_manager.load_configuration()


if __name__ == '__main__':
    unittest.main()