"""
Integration tests for the enhanced configuration system with existing components.
"""

import json
import tempfile
import unittest
from pathlib import Path

from .strategy_config_manager import StrategyConfigManager, StrategyMetadata
from ..strategy_selector import StrategySelector, StrategyResult


class TestConfigurationIntegration(unittest.TestCase):
    """Test integration between configuration manager and strategy selector."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = StrategyConfigManager(self.temp_dir)
        
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_integration_with_strategy_selector(self):
        """Test that enhanced configuration works with StrategySelector."""
        # Create enhanced configuration with Twitter optimizations
        self.config_manager.load_configuration()  # Initialize
        
        # Add Twitter wildcard strategy
        twitter_metadata = StrategyMetadata(
            priority=1,
            description="Twitter CDN optimization",
            success_rate=0.85
        )
        
        self.config_manager.add_domain_strategy(
            "*.twimg.com",
            "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
            twitter_metadata
        )
        
        # Add X.com specific strategy
        x_metadata = StrategyMetadata(
            priority=1,
            description="X.com main domain",
            success_rate=0.88
        )
        
        self.config_manager.add_domain_strategy(
            "x.com",
            "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            x_metadata
        )
        
        # Save configuration
        config_file = Path(self.temp_dir) / "test_strategies.json"
        self.config_manager.save_configuration(self.config_manager._config, str(config_file))
        
        # Verify configuration was saved correctly
        self.assertTrue(config_file.exists())
        
        # Load configuration and verify structure
        with open(config_file, 'r') as f:
            saved_config = json.load(f)
        
        self.assertEqual(saved_config['version'], '3.0')
        self.assertIn('*.twimg.com', saved_config['domain_strategies'])
        self.assertIn('x.com', saved_config['domain_strategies'])
        
        # Verify wildcard detection
        twimg_rule = saved_config['domain_strategies']['*.twimg.com']
        x_rule = saved_config['domain_strategies']['x.com']
        
        self.assertTrue(twimg_rule['is_wildcard'])
        self.assertFalse(x_rule['is_wildcard'])
        
        # Verify metadata preservation
        self.assertEqual(twimg_rule['metadata']['success_rate'], 0.85)
        self.assertEqual(x_rule['metadata']['success_rate'], 0.88)
        self.assertEqual(twimg_rule['metadata']['description'], "Twitter CDN optimization")
    
    def test_legacy_migration_integration(self):
        """Test that legacy configuration migration works correctly."""
        # Create legacy configuration
        legacy_config = {
            "version": "2.0",
            "last_updated": "2025-09-01T10:00:00.000000",
            "domain_strategies": {
                "default": {
                    "domain": "default",
                    "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
                    "success_rate": 0.70,
                    "avg_latency_ms": 300.0,
                    "test_count": 500
                },
                "abs.twimg.com": {
                    "domain": "abs.twimg.com",
                    "strategy": "seqovl(split_pos=76, overlap_size=336, ttl=1)",
                    "success_rate": 0.38,
                    "avg_latency_ms": 259.3,
                    "test_count": 204
                },
                "abs-0.twimg.com": {
                    "domain": "abs-0.twimg.com", 
                    "strategy": "seqovl(split_pos=76, overlap_size=336, ttl=1)",
                    "success_rate": 0.38,
                    "avg_latency_ms": 259.3,
                    "test_count": 204
                }
            }
        }
        
        # Save legacy configuration
        legacy_file = Path(self.temp_dir) / "legacy_config.json"
        with open(legacy_file, 'w') as f:
            json.dump(legacy_config, f, indent=2)
        
        # Load and convert
        config = self.config_manager.load_configuration(str(legacy_file))
        
        # Verify conversion
        self.assertEqual(config.version, "3.0")
        self.assertIsNotNone(config.global_strategy)
        self.assertEqual(len(config.domain_strategies), 2)  # abs.twimg.com and abs-0.twimg.com
        
        # Verify global strategy conversion
        self.assertIn("badsum_race", config.global_strategy.strategy)
        self.assertEqual(config.global_strategy.metadata.success_rate, 0.70)
        
        # Verify domain strategy conversion
        self.assertIn("abs.twimg.com", config.domain_strategies)
        abs_rule = config.domain_strategies["abs.twimg.com"]
        self.assertEqual(abs_rule.metadata.success_rate, 0.38)
        self.assertEqual(abs_rule.metadata.priority, 1)  # Default domain priority
    
    def test_wildcard_optimization_workflow(self):
        """Test the complete workflow of optimizing individual rules to wildcards."""
        # Start with individual Twitter subdomain rules (simulating legacy setup)
        twitter_subdomains = [
            "abs.twimg.com",
            "abs-0.twimg.com", 
            "pbs.twimg.com",
            "video.twimg.com",
            "ton.twimg.com"
        ]
        
        # Add individual rules
        self.config_manager.load_configuration()
        for domain in twitter_subdomains:
            metadata = StrategyMetadata(
                priority=1,
                description=f"Individual rule for {domain}",
                success_rate=0.38,  # Poor performance with old strategy
                avg_latency_ms=259.3
            )
            self.config_manager.add_domain_strategy(
                domain,
                "seqovl(split_pos=76, overlap_size=336, ttl=1)",
                metadata
            )
        
        # Verify individual rules were added
        strategies = self.config_manager.get_domain_strategies()
        self.assertEqual(len(strategies), 5)
        for domain in twitter_subdomains:
            self.assertIn(domain, strategies)
            self.assertFalse(strategies[domain].is_wildcard)
        
        # Optimize by replacing with wildcard rule
        for domain in twitter_subdomains:
            self.config_manager.remove_domain_strategy(domain)
        
        # Add optimized wildcard rule
        optimized_metadata = StrategyMetadata(
            priority=1,
            description="Optimized wildcard rule for Twitter CDN",
            success_rate=0.85,  # Much better performance
            avg_latency_ms=180.5
        )
        
        self.config_manager.add_domain_strategy(
            "*.twimg.com",
            "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
            optimized_metadata
        )
        
        # Verify optimization
        strategies = self.config_manager.get_domain_strategies()
        self.assertEqual(len(strategies), 1)  # Reduced from 5 to 1
        
        wildcard_rule = strategies["*.twimg.com"]
        self.assertTrue(wildcard_rule.is_wildcard)
        self.assertEqual(wildcard_rule.metadata.success_rate, 0.85)
        self.assertIn("multisplit", wildcard_rule.strategy)
        
        # Verify wildcard patterns detection
        wildcards = self.config_manager.get_wildcard_patterns()
        self.assertEqual(wildcards, ["*.twimg.com"])
    
    def test_configuration_validation_workflow(self):
        """Test configuration validation in realistic scenarios."""
        # Test valid configuration
        self.config_manager.load_configuration()
        
        # Add valid strategies
        valid_strategies = [
            ("*.twimg.com", "--dpi-desync=multisplit --dpi-desync-split-count=7"),
            ("x.com", "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badseq"),
            ("youtube.com", "seqovl(split_pos=76, overlap_size=336)")
        ]
        
        for pattern, strategy in valid_strategies:
            self.assertTrue(self.config_manager.validate_strategy_syntax(strategy))
            self.config_manager.add_domain_strategy(pattern, strategy)
        
        # Verify all strategies were added
        strategies = self.config_manager.get_domain_strategies()
        self.assertEqual(len(strategies), 3)
        
        # Test configuration validation
        config = self.config_manager._config
        try:
            self.config_manager._validate_configuration(config)
        except Exception as e:
            self.fail(f"Valid configuration failed validation: {e}")
        
        # Test saving and loading preserves validation
        config_file = Path(self.temp_dir) / "validated_config.json"
        self.config_manager.save_configuration(config, str(config_file))
        
        # Load and verify
        loaded_config = self.config_manager.load_configuration(str(config_file))
        self.assertEqual(len(loaded_config.domain_strategies), 3)
        
        # Verify wildcard detection is preserved
        twimg_rule = loaded_config.domain_strategies["*.twimg.com"]
        self.assertTrue(twimg_rule.is_wildcard)


if __name__ == '__main__':
    unittest.main()