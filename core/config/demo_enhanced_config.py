"""
Demonstration of the enhanced strategy configuration system.

This script shows how to use the new configuration manager with wildcard patterns,
priorities, and backward compatibility features.
"""

import json
import logging
from pathlib import Path

from .strategy_config_manager import (
    StrategyConfigManager,
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
    ConfigurationError
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def demo_basic_usage():
    """Demonstrate basic configuration management."""
    print("=== Basic Configuration Management Demo ===")
    
    # Initialize manager
    manager = StrategyConfigManager("demo_config")
    
    # Create new configuration
    config = StrategyConfiguration()
    
    # Add Twitter/X.com optimized strategies
    twitter_metadata = StrategyMetadata(
        priority=1,
        description="Twitter CDN optimization with multisplit",
        success_rate=0.85,
        avg_latency_ms=180.5
    )
    
    manager.add_domain_strategy(
        "*.twimg.com",
        "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
        twitter_metadata
    )
    
    x_metadata = StrategyMetadata(
        priority=1,
        description="X.com main domain with optimized multisplit",
        success_rate=0.88,
        avg_latency_ms=165.2
    )
    
    manager.add_domain_strategy(
        "x.com",
        "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        x_metadata
    )
    
    # Save configuration
    manager.save_configuration(manager._config, "demo_config/enhanced_strategies.json")
    
    # Display results
    strategies = manager.get_domain_strategies()
    print(f"Added {len(strategies)} domain strategies:")
    for pattern, rule in strategies.items():
        wildcard_indicator = " (wildcard)" if rule.is_wildcard else ""
        print(f"  {pattern}{wildcard_indicator}: {rule.metadata.description}")
    
    print(f"Wildcard patterns: {manager.get_wildcard_patterns()}")


def demo_legacy_migration():
    """Demonstrate legacy configuration migration."""
    print("\n=== Legacy Configuration Migration Demo ===")
    
    # Create a sample legacy configuration
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
            },
            "pbs.twimg.com": {
                "domain": "pbs.twimg.com",
                "strategy": "seqovl(split_pos=76, overlap_size=336, ttl=1)",
                "success_rate": 0.38,
                "avg_latency_ms": 259.3,
                "test_count": 133
            }
        }
    }
    
    # Save legacy configuration
    Path("demo_config").mkdir(exist_ok=True)
    with open("demo_config/legacy_config.json", 'w') as f:
        json.dump(legacy_config, f, indent=2)
    
    # Load and convert
    manager = StrategyConfigManager("demo_config")
    config = manager.load_configuration("demo_config/legacy_config.json")
    
    print(f"Converted configuration from v{legacy_config['version']} to v{config.version}")
    print(f"Global strategy: {config.global_strategy.strategy if config.global_strategy else 'None'}")
    print(f"Domain strategies: {len(config.domain_strategies)}")
    
    # Show conversion results
    for pattern, rule in config.domain_strategies.items():
        print(f"  {pattern}: {rule.metadata.description}")


def demo_wildcard_optimization():
    """Demonstrate wildcard pattern optimization."""
    print("\n=== Wildcard Pattern Optimization Demo ===")
    
    manager = StrategyConfigManager("demo_config")
    
    # Add multiple Twitter subdomains (simulating legacy individual rules)
    twitter_domains = [
        "abs.twimg.com",
        "abs-0.twimg.com", 
        "pbs.twimg.com",
        "video.twimg.com",
        "ton.twimg.com"
    ]
    
    # Add individual rules first
    for domain in twitter_domains:
        metadata = StrategyMetadata(
            priority=1,
            description=f"Individual rule for {domain}",
            success_rate=0.38
        )
        manager.add_domain_strategy(
            domain,
            "seqovl(split_pos=76, overlap_size=336, ttl=1)",
            metadata
        )
    
    print(f"Added {len(twitter_domains)} individual Twitter subdomain rules")
    
    # Now replace with optimized wildcard rule
    optimized_metadata = StrategyMetadata(
        priority=1,
        description="Optimized wildcard rule for all Twitter CDN subdomains",
        success_rate=0.85,  # Much better with optimized strategy
        avg_latency_ms=180.5
    )
    
    # Remove individual rules
    for domain in twitter_domains:
        manager.remove_domain_strategy(domain)
    
    # Add wildcard rule
    manager.add_domain_strategy(
        "*.twimg.com",
        "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
        optimized_metadata
    )
    
    print(f"Optimized to 1 wildcard rule: *.twimg.com")
    print(f"Success rate improved from 38% to 85%")
    
    # Show final configuration
    strategies = manager.get_domain_strategies()
    wildcards = manager.get_wildcard_patterns()
    print(f"Total domain rules: {len(strategies)}")
    print(f"Wildcard patterns: {wildcards}")


def demo_configuration_validation():
    """Demonstrate configuration validation features."""
    print("\n=== Configuration Validation Demo ===")
    
    manager = StrategyConfigManager("demo_config")
    
    # Test valid strategy syntax
    valid_strategies = [
        "--dpi-desync=multisplit --dpi-desync-split-count=5",
        "seqovl(split_pos=76, overlap_size=336)",
        "fakedisorder(split_pos=midsld, ttl=4)",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badseq"
    ]
    
    print("Testing valid strategy syntax:")
    for strategy in valid_strategies:
        is_valid = manager.validate_strategy_syntax(strategy)
        print(f"  ✓ {strategy[:50]}... -> {is_valid}")
    
    # Test invalid strategy syntax
    invalid_strategies = [
        "invalid_strategy_format",
        "",
        "random text without strategy markers"
    ]
    
    print("\nTesting invalid strategy syntax:")
    for strategy in invalid_strategies:
        is_valid = manager.validate_strategy_syntax(strategy)
        print(f"  ✗ {strategy or '(empty)'}... -> {is_valid}")
    
    # Test configuration validation
    print("\nTesting configuration validation:")
    try:
        config = StrategyConfiguration()
        config.domain_strategies["test.com"] = StrategyRule(
            "test.com",
            "--dpi-desync=multisplit --dpi-desync-split-count=5",
            StrategyMetadata()
        )
        manager._validate_configuration(config)
        print("  ✓ Valid configuration passed validation")
    except ConfigurationError as e:
        print(f"  ✗ Configuration validation failed: {e}")


def demo_priority_system():
    """Demonstrate strategy priority system."""
    print("\n=== Strategy Priority System Demo ===")
    
    config = StrategyConfiguration()
    
    # Set custom priority order
    config.strategy_priority = ["domain", "ip", "global"]
    
    # Add strategies with different priorities
    high_priority = StrategyMetadata(priority=1, description="High priority domain rule")
    medium_priority = StrategyMetadata(priority=2, description="Medium priority IP rule") 
    low_priority = StrategyMetadata(priority=0, description="Low priority global fallback")
    
    # Domain strategy (highest priority in order)
    config.domain_strategies["example.com"] = StrategyRule(
        "example.com",
        "--dpi-desync=multisplit --dpi-desync-split-count=5",
        high_priority
    )
    
    # IP strategy (medium priority in order)
    config.ip_strategies["192.168.1.0/24"] = StrategyRule(
        "192.168.1.0/24",
        "--dpi-desync=fake --dpi-desync-fooling=badseq",
        medium_priority
    )
    
    # Global strategy (lowest priority in order)
    config.global_strategy = StrategyRule(
        "*",
        "--dpi-desync=badsum_race --dpi-desync-ttl=4",
        low_priority
    )
    
    print(f"Strategy priority order: {config.strategy_priority}")
    print("Configured strategies:")
    print(f"  Domain: example.com (priority {high_priority.priority})")
    print(f"  IP: 192.168.1.0/24 (priority {medium_priority.priority})")
    print(f"  Global: * (priority {low_priority.priority})")
    
    # Save demonstration configuration
    manager = StrategyConfigManager("demo_config")
    manager.save_configuration(config, "demo_config/priority_demo.json")
    print("Saved priority demonstration configuration")


def main():
    """Run all demonstrations."""
    print("Enhanced Strategy Configuration System Demonstration")
    print("=" * 60)
    
    try:
        demo_basic_usage()
        demo_legacy_migration()
        demo_wildcard_optimization()
        demo_configuration_validation()
        demo_priority_system()
        
        print("\n" + "=" * 60)
        print("All demonstrations completed successfully!")
        print("Check the 'demo_config' directory for generated configuration files.")
        
    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
        raise


if __name__ == '__main__':
    main()