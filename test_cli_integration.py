#!/usr/bin/env python3
"""
Test script for CLI integration functionality.

This script tests the enhanced CLI components to ensure they work correctly
with the new configuration management, validation, and strategy selection features.
"""

import asyncio
import json
import tempfile
import os
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from cli_integration import ComprehensiveStrategyCLI
from core.config.strategy_config_manager import (
    StrategyConfigManager, 
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata
)


class MockArgs:
    """Mock arguments class for testing CLI commands."""
    
    def __init__(self, **kwargs):
        self.config_file = kwargs.get('config_file')
        self.verbose = kwargs.get('verbose', False)
        self.log_level = kwargs.get('log_level', 'INFO')
        self.domains = kwargs.get('domains', [])
        self.pattern = kwargs.get('pattern')
        self.strategy = kwargs.get('strategy')
        self.priority = kwargs.get('priority', 1)
        self.description = kwargs.get('description')
        self.input_file = kwargs.get('input_file')
        self.output_file = kwargs.get('output_file')
        self.no_backup = kwargs.get('no_backup', False)
        self.pcap_file = kwargs.get('pcap_file')
        self.output = kwargs.get('output')
        self.interface = kwargs.get('interface', 'any')
        self.filter = kwargs.get('filter')
        self.domains_file = kwargs.get('domains_file')
        self.iterations = kwargs.get('iterations', 100)


async def test_configuration_management():
    """Test configuration management functionality."""
    print("Testing Configuration Management...")
    
    cli = ComprehensiveStrategyCLI()
    
    # Create a temporary configuration file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        test_config = {
            "version": "3.0",
            "strategy_priority": ["domain", "ip", "global"],
            "domain_strategies": {
                "x.com": {
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5",
                    "metadata": {
                        "priority": 1,
                        "description": "Test strategy for x.com",
                        "success_rate": 0.85,
                        "test_count": 10
                    },
                    "is_wildcard": False
                },
                "*.twimg.com": {
                    "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=7",
                    "metadata": {
                        "priority": 1,
                        "description": "Test wildcard strategy",
                        "success_rate": 0.90,
                        "test_count": 15
                    },
                    "is_wildcard": True
                }
            },
            "global_strategy": {
                "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
                "metadata": {
                    "priority": 0,
                    "description": "Global fallback",
                    "success_rate": 0.75,
                    "test_count": 50
                }
            }
        }
        json.dump(test_config, f, indent=2)
        config_file = f.name
    
    try:
        # Test loading configuration
        args = MockArgs(config_file=config_file, verbose=True)
        result = await cli.cmd_config_load(args)
        assert result, "Failed to load configuration"
        print("✓ Configuration loading works")
        
        # Test validating configuration
        result = await cli.cmd_config_validate(args)
        assert result, "Configuration validation failed"
        print("✓ Configuration validation works")
        
        # Test listing strategies
        result = await cli.cmd_strategy_list(args)
        assert result, "Failed to list strategies"
        print("✓ Strategy listing works")
        
        # Test adding a strategy
        add_args = MockArgs(
            config_file=config_file,
            pattern="test.example.com",
            strategy="--dpi-desync=fakedisorder --dpi-desync-split-pos=3",
            priority=2,
            description="Test strategy addition"
        )
        result = await cli.cmd_strategy_add(add_args)
        assert result, "Failed to add strategy"
        print("✓ Strategy addition works")
        
        # Test strategy selection
        test_args = MockArgs(
            config_file=config_file,
            domains=["x.com", "abs.twimg.com", "test.example.com", "unknown.com"]
        )
        result = await cli.cmd_strategy_test(test_args)
        assert result, "Strategy testing failed"
        print("✓ Strategy selection testing works")
        
        # Test benchmarking
        benchmark_args = MockArgs(
            config_file=config_file,
            domains=["x.com", "abs.twimg.com"],
            iterations=50
        )
        result = await cli.cmd_strategy_benchmark(benchmark_args)
        assert result, "Strategy benchmarking failed"
        print("✓ Strategy benchmarking works")
        
        print("✓ All configuration management tests passed!")
        
    finally:
        # Clean up temporary file
        os.unlink(config_file)


async def test_twitter_optimization():
    """Test Twitter/X.com optimization functionality."""
    print("\nTesting Twitter/X.com Optimization...")
    
    cli = ComprehensiveStrategyCLI()
    
    # Create a minimal configuration file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        minimal_config = {
            "version": "3.0",
            "strategy_priority": ["domain", "ip", "global"],
            "domain_strategies": {},
            "global_strategy": {
                "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
                "metadata": {
                    "priority": 0,
                    "description": "Global fallback"
                }
            }
        }
        json.dump(minimal_config, f, indent=2)
        config_file = f.name
    
    try:
        # Load the minimal configuration
        args = MockArgs(config_file=config_file)
        await cli.cmd_config_load(args)
        
        # Test Twitter optimization
        result = await cli.cmd_twitter_optimize(args)
        assert result, "Twitter optimization failed"
        print("✓ Twitter optimization works")
        
        # Verify the strategies were added
        result = await cli.cmd_strategy_list(args)
        assert result, "Failed to list strategies after optimization"
        
        # Test that Twitter domains now have strategies
        test_args = MockArgs(
            config_file=config_file,
            domains=["x.com", "abs.twimg.com", "pbs.twimg.com", "video.twimg.com"]
        )
        result = await cli.cmd_strategy_test(test_args)
        assert result, "Twitter strategy testing failed"
        print("✓ Twitter strategy selection works")
        
        print("✓ All Twitter optimization tests passed!")
        
    finally:
        # Clean up temporary file
        os.unlink(config_file)


async def test_configuration_migration():
    """Test configuration migration functionality."""
    print("\nTesting Configuration Migration...")
    
    cli = ComprehensiveStrategyCLI()
    
    # Create a legacy v2.0 configuration
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        legacy_config = {
            "version": "2.0",
            "domain_strategies": {
                "x.com": {
                    "strategy": "--dpi-desync=seqovl --dpi-desync-split-pos=3",
                    "success_rate": 0.7,
                    "test_count": 5
                },
                "instagram.com": {
                    "strategy": "--dpi-desync=fakedisorder --dpi-desync-split-pos=4",
                    "success_rate": 0.8,
                    "test_count": 8
                },
                "default": {
                    "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
                    "success_rate": 0.6,
                    "test_count": 20
                }
            }
        }
        json.dump(legacy_config, f, indent=2)
        legacy_file = f.name
    
    # Create output file path
    migrated_file = legacy_file + '.migrated'
    
    try:
        # Test migration
        migrate_args = MockArgs(
            input_file=legacy_file,
            output_file=migrated_file,
            no_backup=True
        )
        result = await cli.cmd_config_migrate(migrate_args)
        assert result, "Configuration migration failed"
        print("✓ Configuration migration works")
        
        # Verify the migrated configuration
        load_args = MockArgs(config_file=migrated_file)
        result = await cli.cmd_config_load(load_args)
        assert result, "Failed to load migrated configuration"
        print("✓ Migrated configuration loads correctly")
        
        # Validate the migrated configuration
        result = await cli.cmd_config_validate(load_args)
        assert result, "Migrated configuration validation failed"
        print("✓ Migrated configuration is valid")
        
        print("✓ All configuration migration tests passed!")
        
    finally:
        # Clean up temporary files
        os.unlink(legacy_file)
        if os.path.exists(migrated_file):
            os.unlink(migrated_file)


async def test_help_commands():
    """Test help command functionality."""
    print("\nTesting Help Commands...")
    
    cli = ComprehensiveStrategyCLI()
    
    # Test wildcard help
    args = MockArgs()
    await cli.cmd_help_wildcards(args)
    print("✓ Wildcard help works")
    
    # Test strategy help
    await cli.cmd_help_strategies(args)
    print("✓ Strategy help works")
    
    print("✓ All help command tests passed!")


async def test_validation_functionality():
    """Test configuration validation with various scenarios."""
    print("\nTesting Validation Functionality...")
    
    cli = ComprehensiveStrategyCLI()
    
    # Test with invalid configuration
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        invalid_config = {
            "version": "3.0",
            "strategy_priority": ["invalid_priority"],
            "domain_strategies": {
                "example.com": {
                    "strategy": "",  # Empty strategy should cause error
                    "metadata": {
                        "priority": 1
                    },
                    "is_wildcard": False
                }
            }
        }
        json.dump(invalid_config, f, indent=2)
        invalid_file = f.name
    
    try:
        # Test validation with invalid config (should fail)
        args = MockArgs(config_file=invalid_file, verbose=True)
        result = await cli.cmd_config_validate(args)
        assert not result, "Validation should have failed for invalid configuration"
        print("✓ Validation correctly identifies invalid configuration")
        
        print("✓ All validation tests passed!")
        
    finally:
        # Clean up temporary file
        os.unlink(invalid_file)


async def run_all_tests():
    """Run all CLI integration tests."""
    print("Starting CLI Integration Tests...\n")
    
    try:
        await test_configuration_management()
        await test_twitter_optimization()
        await test_configuration_migration()
        await test_help_commands()
        await test_validation_functionality()
        
        print("\n🎉 All CLI integration tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    # Run tests
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)