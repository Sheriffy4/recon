#!/usr/bin/env python3
"""
Demo script for Configuration System - Task 16 Implementation
Demonstrates configuration loading, feature flags, runtime updates, and performance tuning.
"""

import os
import sys
import json
import yaml
import tempfile
import shutil
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

try:
    from core.fingerprint.config import (
        AdvancedFingerprintingConfig, ConfigurationManager,
        NetworkConfig, CacheConfig, MLConfig, MonitoringConfig,
        AnalyzerConfig, PerformanceConfig, LoggingConfig,
        AnalyzerType, LogLevel,
        get_config_manager, get_config, load_config, save_config, create_default_config
    )
except ImportError:
    from recon.core.fingerprint.config import (
        AdvancedFingerprintingConfig, ConfigurationManager,
        NetworkConfig, CacheConfig, MLConfig, MonitoringConfig,
        AnalyzerConfig, PerformanceConfig, LoggingConfig,
        AnalyzerType, LogLevel,
        get_config_manager, get_config, load_config, save_config, create_default_config
    )


def demo_default_configuration():
    """Demonstrate default configuration structure."""
    print("=" * 80)
    print("DEMO: Default Configuration Structure")
    print("=" * 80)
    
    config = AdvancedFingerprintingConfig()
    
    print(f"🔧 Main Configuration:")
    print(f"   Enabled: {config.enabled}")
    print(f"   Debug Mode: {config.debug_mode}")
    print(f"   Config Version: {config.config_version}")
    
    print(f"\n🌐 Network Configuration:")
    print(f"   Timeout: {config.network.timeout}s")
    print(f"   Max Retries: {config.network.max_retries}")
    print(f"   Concurrent Limit: {config.network.concurrent_limit}")
    print(f"   DNS Servers: {config.network.dns_servers}")
    
    print(f"\n💾 Cache Configuration:")
    print(f"   Enabled: {config.cache.enabled}")
    print(f"   Max Size: {config.cache.max_size}")
    print(f"   TTL: {config.cache.ttl_seconds}s")
    print(f"   Compression: {config.cache.compression}")
    
    print(f"\n🤖 ML Configuration:")
    print(f"   Enabled: {config.ml.enabled}")
    print(f"   Confidence Threshold: {config.ml.confidence_threshold}")
    print(f"   Model Path: {config.ml.model_path}")
    print(f"   Max Training Samples: {config.ml.max_training_samples}")
    
    print(f"\n📊 Monitoring Configuration:")
    print(f"   Enabled: {config.monitoring.enabled}")
    print(f"   Check Interval: {config.monitoring.check_interval}s")
    print(f"   Adaptive Frequency: {config.monitoring.adaptive_frequency}")
    print(f"   Background Monitoring: {config.monitoring.background_monitoring}")
    
    print(f"\n⚡ Performance Configuration:")
    print(f"   Max Concurrent Fingerprints: {config.performance.max_concurrent_fingerprints}")
    print(f"   Fingerprint Timeout: {config.performance.fingerprint_timeout}s")
    print(f"   Memory Limit: {config.performance.memory_limit_mb}MB")
    print(f"   CPU Limit: {config.performance.cpu_limit_percent}%")
    
    print(f"\n📝 Logging Configuration:")
    print(f"   Level: {config.logging.level.value}")
    print(f"   Console Output: {config.logging.console_output}")
    print(f"   File Path: {config.logging.file_path}")
    print(f"   Max File Size: {config.logging.max_file_size} bytes")


def demo_analyzer_configuration():
    """Demonstrate analyzer configuration management."""
    print("\n" + "=" * 80)
    print("DEMO: Analyzer Configuration Management")
    print("=" * 80)
    
    config = AdvancedFingerprintingConfig()
    
    print(f"🔍 Available Analyzers:")
    for name, analyzer_config in config.analyzers.items():
        status = "✅ Enabled" if analyzer_config.enabled else "❌ Disabled"
        print(f"   {name}: {status}")
        print(f"      Timeout: {analyzer_config.timeout}s")
        print(f"      Max Samples: {analyzer_config.max_samples}")
        print(f"      Confidence Weight: {analyzer_config.confidence_weight}")
        print(f"      Priority: {analyzer_config.priority}")
        if analyzer_config.custom_params:
            print(f"      Custom Params: {analyzer_config.custom_params}")
        print()
    
    print(f"🛠️  Analyzer Management Operations:")
    
    # Test analyzer status checks
    print(f"   TCP Analyzer Enabled: {config.is_analyzer_enabled('tcp')}")
    print(f"   HTTP Analyzer Enabled: {config.is_analyzer_enabled(AnalyzerType.HTTP)}")
    
    # Disable an analyzer
    print(f"\n   Disabling DNS analyzer...")
    config.disable_analyzer("dns")
    print(f"   DNS Analyzer Enabled: {config.is_analyzer_enabled('dns')}")
    
    # Update analyzer configuration
    print(f"\n   Updating TCP analyzer configuration...")
    config.update_analyzer_config("tcp", timeout=15.0, max_samples=20)
    tcp_config = config.get_analyzer_config("tcp")
    print(f"   TCP Timeout: {tcp_config.timeout}s")
    print(f"   TCP Max Samples: {tcp_config.max_samples}")
    
    # Add custom analyzer
    print(f"\n   Adding custom analyzer...")
    config.update_analyzer_config("custom_analyzer", 
                                 enabled=True,
                                 timeout=8.0,
                                 max_samples=5,
                                 custom_params={"param1": "value1", "param2": 42})
    
    custom_config = config.get_analyzer_config("custom_analyzer")
    print(f"   Custom Analyzer Added: {custom_config is not None}")
    if custom_config:
        print(f"   Custom Params: {custom_config.custom_params}")


def demo_feature_flags():
    """Demonstrate feature flag management."""
    print("\n" + "=" * 80)
    print("DEMO: Feature Flag Management")
    print("=" * 80)
    
    config = AdvancedFingerprintingConfig()
    
    print(f"🚩 Available Feature Flags:")
    for flag_name, enabled in config.feature_flags.items():
        status = "✅ Enabled" if enabled else "❌ Disabled"
        print(f"   {flag_name}: {status}")
    
    print(f"\n🔧 Feature Flag Operations:")
    
    # Test feature status
    print(f"   ML Classification: {config.is_feature_enabled('ml_classification')}")
    print(f"   Experimental Features: {config.is_feature_enabled('experimental_features')}")
    
    # Enable experimental features
    print(f"\n   Enabling experimental features...")
    config.enable_feature("experimental_features")
    print(f"   Experimental Features: {config.is_feature_enabled('experimental_features')}")
    
    # Disable cache compression
    print(f"\n   Disabling cache compression...")
    config.disable_feature("cache_compression")
    print(f"   Cache Compression: {config.is_feature_enabled('cache_compression')}")
    
    # Add custom feature flag
    print(f"\n   Adding custom feature flag...")
    config.feature_flags["custom_feature"] = True
    print(f"   Custom Feature: {config.is_feature_enabled('custom_feature')}")


def demo_configuration_validation():
    """Demonstrate configuration validation."""
    print("\n" + "=" * 80)
    print("DEMO: Configuration Validation")
    print("=" * 80)
    
    print(f"✅ Valid Configuration:")
    valid_config = AdvancedFingerprintingConfig()
    errors = valid_config.validate()
    print(f"   Validation Errors: {len(errors)}")
    if errors:
        for error in errors:
            print(f"      - {error}")
    else:
        print(f"   Configuration is valid!")
    
    print(f"\n❌ Invalid Configuration:")
    invalid_config = AdvancedFingerprintingConfig()
    
    # Introduce validation errors
    invalid_config.network.timeout = -1.0
    invalid_config.cache.max_size = 0
    invalid_config.ml.confidence_threshold = 1.5
    invalid_config.monitoring.min_interval = 1000
    invalid_config.monitoring.max_interval = 500  # Less than min_interval
    invalid_config.analyzers["tcp"].timeout = -5.0
    
    errors = invalid_config.validate()
    print(f"   Validation Errors: {len(errors)}")
    for error in errors:
        print(f"      - {error}")


def demo_configuration_serialization():
    """Demonstrate configuration serialization and deserialization."""
    print("\n" + "=" * 80)
    print("DEMO: Configuration Serialization")
    print("=" * 80)
    
    # Create custom configuration
    config = AdvancedFingerprintingConfig()
    config.debug_mode = True
    config.network.timeout = 20.0
    config.cache.max_size = 5000
    config.ml.confidence_threshold = 0.85
    config.disable_analyzer("dns")
    config.enable_feature("experimental_features")
    config.custom_settings = {
        "custom_param": "custom_value",
        "nested": {"param": 42}
    }
    
    print(f"📤 Serialization to Dictionary:")
    config_dict = config.to_dict()
    print(f"   Dictionary Keys: {list(config_dict.keys())}")
    print(f"   Debug Mode: {config_dict['debug_mode']}")
    print(f"   Network Timeout: {config_dict['network']['timeout']}")
    print(f"   DNS Analyzer Enabled: {config_dict['analyzers']['dns']['enabled']}")
    
    print(f"\n📥 Deserialization from Dictionary:")
    restored_config = AdvancedFingerprintingConfig.from_dict(config_dict)
    print(f"   Debug Mode: {restored_config.debug_mode}")
    print(f"   Network Timeout: {restored_config.network.timeout}")
    print(f"   DNS Analyzer Enabled: {restored_config.is_analyzer_enabled('dns')}")
    print(f"   Custom Settings: {restored_config.custom_settings}")
    
    # Verify configurations are equivalent
    original_dict = config.to_dict()
    restored_dict = restored_config.to_dict()
    print(f"   Configurations Match: {original_dict == restored_dict}")


def demo_configuration_file_operations():
    """Demonstrate configuration file operations."""
    print("\n" + "=" * 80)
    print("DEMO: Configuration File Operations")
    print("=" * 80)
    
    # Create temporary directory for demo
    demo_dir = tempfile.mkdtemp(prefix='config_demo_')
    
    try:
        yaml_path = os.path.join(demo_dir, 'config.yaml')
        json_path = os.path.join(demo_dir, 'config.json')
        
        print(f"📁 Demo directory: {demo_dir}")
        
        # Create configuration manager
        manager = ConfigurationManager()
        
        # Customize configuration
        manager.config.debug_mode = True
        manager.config.network.timeout = 25.0
        manager.config.cache.max_size = 2000
        manager.config.update_analyzer_config("tcp", timeout=30.0)
        manager.config.enable_feature("experimental_features")
        
        print(f"\n💾 Saving Configuration Files:")
        
        # Save as YAML
        manager.save_config(yaml_path)
        yaml_size = os.path.getsize(yaml_path)
        print(f"   YAML saved: {yaml_path} ({yaml_size} bytes)")
        
        # Save as JSON
        manager.save_config(json_path)
        json_size = os.path.getsize(json_path)
        print(f"   JSON saved: {json_path} ({json_size} bytes)")
        
        print(f"\n📖 Loading Configuration Files:")
        
        # Load YAML configuration
        yaml_manager = ConfigurationManager()
        yaml_config = yaml_manager.load_config(yaml_path)
        print(f"   YAML loaded - Debug Mode: {yaml_config.debug_mode}")
        print(f"   YAML loaded - Network Timeout: {yaml_config.network.timeout}")
        
        # Load JSON configuration
        json_manager = ConfigurationManager()
        json_config = json_manager.load_config(json_path)
        print(f"   JSON loaded - Debug Mode: {json_config.debug_mode}")
        print(f"   JSON loaded - Network Timeout: {json_config.network.timeout}")
        
        print(f"\n📋 Configuration File Contents (YAML):")
        with open(yaml_path, 'r') as f:
            yaml_content = f.read()
        
        # Show first 20 lines
        lines = yaml_content.split('\n')[:20]
        for i, line in enumerate(lines, 1):
            print(f"   {i:2d}: {line}")
        
        if len(yaml_content.split('\n')) > 20:
            print(f"   ... ({len(yaml_content.split('\n')) - 20} more lines)")
    
    finally:
        # Cleanup
        shutil.rmtree(demo_dir, ignore_errors=True)


def demo_runtime_configuration_updates():
    """Demonstrate runtime configuration updates."""
    print("\n" + "=" * 80)
    print("DEMO: Runtime Configuration Updates")
    print("=" * 80)
    
    manager = ConfigurationManager()
    
    print(f"🔄 Initial Configuration:")
    print(f"   Debug Mode: {manager.config.debug_mode}")
    print(f"   Network Timeout: {manager.config.network.timeout}")
    print(f"   TCP Analyzer Enabled: {manager.config.is_analyzer_enabled('tcp')}")
    
    print(f"\n🛠️  Runtime Updates:")
    
    # Update main settings
    print(f"   Enabling debug mode...")
    manager.update_config(debug_mode=True)
    print(f"   Debug Mode: {manager.config.debug_mode}")
    
    # Update network settings
    print(f"   Updating network configuration...")
    new_network = NetworkConfig(timeout=15.0, max_retries=5, concurrent_limit=20)
    manager.update_config(network=new_network)
    print(f"   Network Timeout: {manager.config.network.timeout}")
    print(f"   Max Retries: {manager.config.network.max_retries}")
    print(f"   Concurrent Limit: {manager.config.network.concurrent_limit}")
    
    # Update analyzer settings
    print(f"   Updating analyzer configurations...")
    manager.config.update_analyzer_config("tcp", timeout=20.0, max_samples=25)
    manager.config.disable_analyzer("dns")
    
    tcp_config = manager.config.get_analyzer_config("tcp")
    print(f"   TCP Timeout: {tcp_config.timeout}")
    print(f"   TCP Max Samples: {tcp_config.max_samples}")
    print(f"   DNS Analyzer Enabled: {manager.config.is_analyzer_enabled('dns')}")
    
    # Update feature flags
    print(f"   Updating feature flags...")
    manager.config.enable_feature("experimental_features")
    manager.config.disable_feature("cache_compression")
    
    print(f"   Experimental Features: {manager.config.is_feature_enabled('experimental_features')}")
    print(f"   Cache Compression: {manager.config.is_feature_enabled('cache_compression')}")
    
    print(f"\n✅ Configuration updated successfully!")


def demo_performance_tuning_scenarios():
    """Demonstrate performance tuning scenarios."""
    print("\n" + "=" * 80)
    print("DEMO: Performance Tuning Scenarios")
    print("=" * 80)
    
    print(f"🚀 Performance Tuning Scenarios:")
    
    scenarios = [
        {
            "name": "High-Performance Setup",
            "description": "Optimized for speed and throughput",
            "config": {
                "network": NetworkConfig(timeout=2.0, concurrent_limit=50),
                "performance": PerformanceConfig(
                    max_concurrent_fingerprints=20,
                    fingerprint_timeout=10.0,
                    batch_size=50,
                    memory_limit_mb=1024,
                    cpu_limit_percent=90
                ),
                "cache": CacheConfig(max_size=10000, ttl_seconds=7200),
                "analyzers": {
                    "tcp": AnalyzerConfig(timeout=1.0, max_samples=5),
                    "http": AnalyzerConfig(timeout=2.0, max_samples=3),
                    "dns": AnalyzerConfig(timeout=1.0, max_samples=2)
                }
            }
        },
        {
            "name": "Resource-Constrained Setup",
            "description": "Optimized for low resource usage",
            "config": {
                "network": NetworkConfig(timeout=10.0, concurrent_limit=3),
                "performance": PerformanceConfig(
                    max_concurrent_fingerprints=2,
                    fingerprint_timeout=60.0,
                    batch_size=5,
                    memory_limit_mb=128,
                    cpu_limit_percent=50
                ),
                "cache": CacheConfig(max_size=100, ttl_seconds=1800),
                "analyzers": {
                    "tcp": AnalyzerConfig(timeout=15.0, max_samples=3),
                    "http": AnalyzerConfig(timeout=20.0, max_samples=2),
                    "dns": AnalyzerConfig(enabled=False)  # Disable to save resources
                }
            }
        },
        {
            "name": "Accuracy-Focused Setup",
            "description": "Optimized for maximum accuracy",
            "config": {
                "network": NetworkConfig(timeout=30.0, max_retries=5),
                "performance": PerformanceConfig(
                    max_concurrent_fingerprints=3,
                    fingerprint_timeout=120.0,
                    batch_size=10
                ),
                "ml": MLConfig(confidence_threshold=0.9, max_training_samples=50000),
                "analyzers": {
                    "tcp": AnalyzerConfig(timeout=45.0, max_samples=20),
                    "http": AnalyzerConfig(timeout=60.0, max_samples=15),
                    "dns": AnalyzerConfig(timeout=30.0, max_samples=10),
                    "metrics_collector": AnalyzerConfig(timeout=90.0, max_samples=50)
                }
            }
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print(f"   Description: {scenario['description']}")
        
        config = AdvancedFingerprintingConfig()
        
        # Apply scenario configuration
        for component, settings in scenario['config'].items():
            if component == 'analyzers':
                for analyzer_name, analyzer_config in settings.items():
                    if isinstance(analyzer_config, dict):
                        config.update_analyzer_config(analyzer_name, **analyzer_config)
                    else:
                        config.analyzers[analyzer_name] = analyzer_config
            else:
                setattr(config, component, settings)
        
        # Display key metrics
        print(f"   Network Timeout: {config.network.timeout}s")
        print(f"   Concurrent Limit: {config.network.concurrent_limit}")
        print(f"   Max Concurrent Fingerprints: {config.performance.max_concurrent_fingerprints}")
        print(f"   Memory Limit: {config.performance.memory_limit_mb}MB")
        print(f"   Cache Size: {config.cache.max_size}")
        
        # Show analyzer settings
        enabled_analyzers = [name for name, cfg in config.analyzers.items() if cfg.enabled]
        print(f"   Enabled Analyzers: {', '.join(enabled_analyzers)}")


def demo_global_configuration_management():
    """Demonstrate global configuration management."""
    print("\n" + "=" * 80)
    print("DEMO: Global Configuration Management")
    print("=" * 80)
    
    print(f"🌍 Global Configuration Functions:")
    
    # Get global configuration
    global_config = get_config()
    print(f"   Global Config Enabled: {global_config.enabled}")
    print(f"   Global Config Debug: {global_config.debug_mode}")
    
    # Get global configuration manager
    manager1 = get_config_manager()
    manager2 = get_config_manager()
    print(f"   Same Manager Instance: {manager1 is manager2}")
    
    # Modify global configuration
    print(f"\n🔧 Modifying Global Configuration:")
    global_config.debug_mode = True
    global_config.network.timeout = 12.0
    global_config.enable_feature("experimental_features")
    
    # Verify changes
    updated_config = get_config()
    print(f"   Updated Debug Mode: {updated_config.debug_mode}")
    print(f"   Updated Network Timeout: {updated_config.network.timeout}")
    print(f"   Experimental Features: {updated_config.is_feature_enabled('experimental_features')}")
    
    # Create temporary config file for global operations
    demo_dir = tempfile.mkdtemp(prefix='global_config_demo_')
    
    try:
        config_path = os.path.join(demo_dir, 'global_config.yaml')
        
        print(f"\n💾 Global Configuration File Operations:")
        
        # Save global configuration
        save_config(config_path)
        print(f"   Global config saved to: {config_path}")
        
        # Reset global configuration
        get_config_manager().reset_to_defaults()
        reset_config = get_config()
        print(f"   Reset Debug Mode: {reset_config.debug_mode}")
        
        # Load global configuration
        loaded_config = load_config(config_path)
        print(f"   Loaded Debug Mode: {loaded_config.debug_mode}")
        print(f"   Loaded Network Timeout: {loaded_config.network.timeout}")
    
    finally:
        shutil.rmtree(demo_dir, ignore_errors=True)


def main():
    """Run all configuration system demos."""
    print("🚀 Advanced DPI Fingerprinting Configuration System Demo")
    print("Task 16: Add configuration and customization options")
    print("=" * 80)
    
    try:
        demo_default_configuration()
        demo_analyzer_configuration()
        demo_feature_flags()
        demo_configuration_validation()
        demo_configuration_serialization()
        demo_configuration_file_operations()
        demo_runtime_configuration_updates()
        demo_performance_tuning_scenarios()
        demo_global_configuration_management()
        
        print("\n" + "=" * 80)
        print("✅ DEMO COMPLETE")
        print("=" * 80)
        print("\nKey Features Demonstrated:")
        print("• ✅ Comprehensive configuration structure with nested components")
        print("• ✅ Analyzer configuration management with enable/disable controls")
        print("• ✅ Feature flag system for runtime feature control")
        print("• ✅ Configuration validation with detailed error reporting")
        print("• ✅ YAML and JSON serialization/deserialization")
        print("• ✅ File-based configuration loading and saving")
        print("• ✅ Runtime configuration updates and modifications")
        print("• ✅ Performance tuning scenarios for different use cases")
        print("• ✅ Global configuration management with singleton pattern")
        print("• ✅ Custom settings and extensibility support")
        print("\n🎯 Task 16 Implementation: COMPLETE")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()