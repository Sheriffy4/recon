# Enhanced Strategy Configuration System

This module provides an enhanced configuration management system for DPI bypass strategies with support for wildcard patterns, priorities, and backward compatibility.

## Features

- **Wildcard Pattern Support**: Use `*.domain.com` patterns to match multiple subdomains
- **Strategy Priorities**: Clear priority order (domain > IP > global) with configurable metadata
- **Backward Compatibility**: Automatic migration from legacy v2.0 configuration format
- **Configuration Validation**: Syntax validation and error handling for strategy configurations
- **Metadata Support**: Rich metadata including success rates, latency, test counts, and descriptions

## Quick Start

### Basic Usage

```python
from recon.core.config import StrategyConfigManager, StrategyMetadata

# Initialize manager
manager = StrategyConfigManager("path/to/config")

# Add a wildcard strategy for Twitter CDN
metadata = StrategyMetadata(
    priority=1,
    description="Twitter CDN optimization",
    success_rate=0.85
)

manager.add_domain_strategy(
    "*.twimg.com",
    "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30",
    metadata
)

# Save configuration
manager.save_configuration(manager._config)
```

### Loading and Converting Legacy Configurations

```python
# Load existing configuration (auto-converts from v2.0 to v3.0)
config = manager.load_configuration("domain_strategies.json")

# The system automatically detects and converts legacy formats
print(f"Loaded configuration version: {config.version}")
```

## Configuration Format

### Version 3.0 Format (Enhanced)

```json
{
  "version": "3.0",
  "strategy_priority": ["domain", "ip", "global"],
  "last_updated": "2025-09-01T12:00:00.000000",
  "domain_strategies": {
    "*.twimg.com": {
      "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
      "metadata": {
        "priority": 1,
        "description": "Twitter CDN optimization with multisplit strategy",
        "success_rate": 0.85,
        "avg_latency_ms": 180.5,
        "last_tested": "2025-09-01T11:30:00.000000",
        "test_count": 150,
        "created_at": "2025-09-01T10:00:00.000000",
        "updated_at": "2025-09-01T11:30:00.000000"
      },
      "is_wildcard": true
    }
  },
  "ip_strategies": {
    "192.168.1.0/24": {
      "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4",
      "metadata": {
        "priority": 2,
        "description": "Local network strategy"
      }
    }
  },
  "global_strategy": {
    "strategy": "--dpi-desync=badsum_race --dpi-desync-ttl=4 --dpi-desync-split-pos=3",
    "metadata": {
      "priority": 0,
      "description": "Global fallback strategy"
    }
  }
}
```

### Legacy Version 2.0 Format (Supported)

```json
{
  "version": "2.0",
  "domain_strategies": {
    "default": {
      "domain": "default",
      "strategy": "--dpi-desync=badsum_race",
      "success_rate": 0.70,
      "avg_latency_ms": 300.0
    },
    "example.com": {
      "domain": "example.com", 
      "strategy": "--dpi-desync=multisplit",
      "success_rate": 0.85
    }
  }
}
```

## Strategy Priority System

The configuration system uses a clear priority hierarchy:

1. **Domain Strategies** (Priority 1): Exact domain matches and wildcard patterns
2. **IP Strategies** (Priority 2): IP address and subnet matches  
3. **Global Strategy** (Priority 0): Fallback strategy for unmatched connections

### Wildcard Pattern Matching

- `*.twimg.com` matches `abs.twimg.com`, `pbs.twimg.com`, etc.
- `test?.example.com` matches `test1.example.com`, `testa.example.com`, etc.
- Exact domain matches take priority over wildcard patterns

## Migration and Optimization Tools

### Configuration Analysis

```bash
python -m recon.core.config.config_migration_tool analyze domain_strategies.json
```

Output:
```
Configuration Analysis for domain_strategies.json
Current version: 2.0
Domain rules: 39

Wildcard opportunities (4):
  *.twimg.com: 4 rules can be consolidated
  *.x.com: 3 rules can be consolidated

Recommendations:
  • Upgrade from version 2.0 to 3.0 for enhanced features
  • Use wildcards to reduce 11 domain rules
```

### Configuration Migration

```bash
python -m recon.core.config.config_migration_tool migrate domain_strategies.json
```

### Configuration Optimization

```bash
python -m recon.core.config.config_migration_tool optimize domain_strategies.json -o optimized_config.json
```

## API Reference

### StrategyConfigManager

Main class for configuration management.

#### Methods

- `load_configuration(config_file=None)`: Load configuration with auto-conversion
- `save_configuration(config, config_file=None, create_backup=True)`: Save configuration
- `add_domain_strategy(pattern, strategy, metadata=None)`: Add domain strategy rule
- `remove_domain_strategy(pattern)`: Remove domain strategy rule
- `get_domain_strategies()`: Get all domain strategy rules
- `get_wildcard_patterns()`: Get wildcard domain patterns
- `validate_strategy_syntax(strategy)`: Validate strategy syntax

### StrategyRule

Represents a strategy rule with pattern, strategy, and metadata.

#### Properties

- `pattern`: Domain pattern (can include wildcards)
- `strategy`: Strategy command string
- `metadata`: StrategyMetadata object
- `is_wildcard`: Boolean indicating if pattern contains wildcards

### StrategyMetadata

Metadata for strategy rules.

#### Properties

- `priority`: Strategy priority (1=high, 0=low)
- `description`: Human-readable description
- `success_rate`: Success rate (0.0-1.0)
- `avg_latency_ms`: Average latency in milliseconds
- `last_tested`: ISO timestamp of last test
- `test_count`: Number of tests performed
- `created_at`: ISO timestamp of creation
- `updated_at`: ISO timestamp of last update

## Twitter/X.com Optimization Example

The enhanced configuration system is specifically designed to optimize Twitter/X.com access:

```python
# Instead of multiple individual rules:
# abs.twimg.com, abs-0.twimg.com, pbs.twimg.com, video.twimg.com, ton.twimg.com

# Use a single optimized wildcard rule:
manager.add_domain_strategy(
    "*.twimg.com",
    "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
    StrategyMetadata(
        priority=1,
        description="Twitter CDN optimization",
        success_rate=0.85  # Improved from 0.38 with old seqovl strategy
    )
)
```

## Error Handling

The configuration system provides comprehensive error handling:

- `ConfigurationError`: Raised for configuration-related errors
- Automatic backup creation before saving
- Validation of strategy syntax and configuration structure
- Graceful handling of missing or corrupted configuration files

## Testing

Run the test suite:

```bash
python -m pytest recon/core/config/test_strategy_config_manager.py -v
```

Run the demonstration:

```bash
python -m recon.core.config.demo_enhanced_config
```

## Requirements Addressed

This implementation addresses the following requirements from the specification:

- **4.1**: Wildcard pattern support (`*.domain.com`)
- **4.2**: Exact domain priority over wildcard patterns  
- **4.3**: Backward compatibility with existing `domain_strategies.json` format
- **4.4**: Configuration validation and error handling
- **Metadata Support**: Priority, description, success_rate tracking

## Performance Considerations

- Wildcard pattern matching is optimized for common use cases
- Configuration loading is cached to avoid repeated file I/O
- Large rule sets are supported with efficient lookup algorithms
- Memory usage is optimized for production deployments

## Security Considerations

- Strategy strings are validated to prevent injection attacks
- Configuration files are validated before loading
- Backup files are created automatically to prevent data loss
- Access control should be implemented at the file system level