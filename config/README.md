# Engine Factory Configuration

This directory contains configuration files for the enhanced engine factory system.

## Configuration Files

### `engine_config.json`
Default configuration file loaded automatically by the engine factory. Contains balanced settings suitable for most use cases.

### `engine_config_development.json`
Development configuration with:
- Debug logging enabled
- Longer timeouts for debugging
- Smaller buffer sizes for testing
- Packet logging enabled

### `engine_config_production.json`
Production configuration with:
- Optimized performance settings
- Larger buffer sizes
- Higher connection limits
- Minimal logging

## Configuration Structure

```json
{
  "global": {
    "default_engine": "engine_type_or_null",
    "enable_fallback": true,
    "validate_dependencies": true,
    "log_level": "INFO"
  },
  "profiles": {
    "engine_type": {
      "priority": 100,
      "enabled": true,
      "default_config": {
        "debug": false,
        "timeout": 30.0,
        "packet_buffer_size": 65535,
        "max_concurrent_connections": 1000,
        "log_packets": false
      },
      "required_permissions": ["administrator"],
      "dependencies": ["package_name"],
      "fallback_engines": ["fallback_engine_type"],
      "platform_specific": {
        "Windows": {
          "setting": "windows_value"
        },
        "Linux": {
          "setting": "linux_value"
        }
      },
      "description": "Engine description"
    }
  }
}
```

## Global Settings

- `default_engine`: Preferred engine type (null for auto-detection)
- `enable_fallback`: Allow fallback to alternative engines
- `validate_dependencies`: Validate engine dependencies before creation
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Profile Settings

- `priority`: Engine preference (higher = more preferred)
- `enabled`: Whether the engine is available for use
- `default_config`: Default configuration parameters
- `required_permissions`: Required system permissions
- `dependencies`: Required Python packages or system components
- `fallback_engines`: Alternative engines to try if this one fails
- `platform_specific`: Platform-specific configuration overrides
- `description`: Human-readable description

## Environment Variables

You can override configuration using environment variables with the `ENGINE_` prefix:

```bash
# Global settings
export ENGINE_DEFAULT_ENGINE=external_tool
export ENGINE_ENABLE_FALLBACK=true
export ENGINE_LOG_LEVEL=DEBUG

# Engine-specific settings
export ENGINE_EXTERNAL_TOOL_DEBUG=true
export ENGINE_EXTERNAL_TOOL_TIMEOUT=60.0
export ENGINE_NATIVE_PYDIVERT_PACKET_BUFFER_SIZE=131072
```

## Using Different Configurations

### Method 1: File Selection
Copy the desired configuration file to `engine_config.json`:

```bash
# For development
cp engine_config_development.json engine_config.json

# For production
cp engine_config_production.json engine_config.json
```

### Method 2: Custom Configuration Directory
```python
from core.bypass.engines.engine_config_manager import EngineConfigManager

# Use custom config directory
config_manager = EngineConfigManager(config_dir="/path/to/custom/config")
```

### Method 3: Programmatic Configuration
```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory

factory = EnhancedEngineFactory()

# Override settings
factory.set_engine_priority(EngineType.EXTERNAL_TOOL, 95)
factory.enable_engine(EngineType.NATIVE_NETFILTER, False)
factory.set_engine_config_override(EngineType.EXTERNAL_TOOL, {
    "debug": True,
    "timeout": 60.0
})
```

## Configuration Validation

Validate your configuration files:

```python
from core.bypass.engines.config_models import validate_config_file

result = validate_config_file("config/engine_config.json")
if not result.valid:
    print(f"Configuration errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
```

## Migration Guide

### From Legacy Factory

If you're migrating from the legacy engine factory:

1. **Old code:**
   ```python
   from core.bypass.engines.factory import create_engine
   engine = create_engine(EngineType.NATIVE_PYDIVERT, config)
   ```

2. **New code:**
   ```python
   from core.bypass.engines.enhanced_factory import create_engine_enhanced
   engine = create_engine_enhanced(EngineType.NATIVE_PYDIVERT, config)
   ```

3. **Or use the factory directly:**
   ```python
   from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
   factory = EnhancedEngineFactory()
   engine = factory.create_with_fallback()
   ```

### Configuration Migration

1. Create a configuration file based on your current settings
2. Test the configuration with `validate_config_file()`
3. Update your code to use the enhanced factory
4. Enable fallback mechanisms for better reliability

## Troubleshooting

### Common Issues

1. **Configuration file not found**
   - Ensure the file exists in the config directory
   - Check file permissions
   - Verify JSON syntax

2. **Invalid JSON format**
   - Use a JSON validator
   - Check for trailing commas
   - Ensure proper quoting

3. **Engine not available**
   - Check engine dependencies
   - Verify system permissions
   - Review platform compatibility

### Debug Configuration

Enable debug logging to troubleshoot configuration issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
factory = EnhancedEngineFactory()

# Check configuration state
config_info = factory.get_configuration_info()
print(f"Configuration loaded from: {config_info['loaded_from']}")
print(f"Validation errors: {config_info['validation_errors']}")
```

## Best Practices

1. **Use version control** for configuration files
2. **Validate configurations** before deployment
3. **Use environment-specific** configurations
4. **Document custom settings** and their purposes
5. **Test configuration changes** in development first
6. **Monitor engine performance** after configuration changes
7. **Keep backups** of working configurations

## Examples

See the `USAGE_GUIDE.md` for detailed examples of using the configuration system.