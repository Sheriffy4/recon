# Enhanced Engine Factory Usage Guide

This guide provides comprehensive documentation for using the enhanced engine factory system, including troubleshooting and best practices.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Usage](#basic-usage)
3. [Advanced Configuration](#advanced-configuration)
4. [Error Handling](#error-handling)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)
7. [API Reference](#api-reference)

## Quick Start

### Simple Engine Creation

```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
from core.bypass.engines.base import EngineType

# Create factory instance
factory = EnhancedEngineFactory()

# Create engine with automatic fallback
engine = factory.create_with_fallback()

# Or create specific engine type
engine = factory.create_engine(EngineType.EXTERNAL_TOOL)
```

### Using Convenience Functions

```python
from core.bypass.engines.enhanced_factory import create_engine_enhanced
from core.bypass.engines.base import EngineType, EngineConfig

# Simple creation with enhanced features
engine = create_engine_enhanced(
    engine_type=EngineType.EXTERNAL_TOOL,
    config=EngineConfig(debug=True, timeout=30.0)
)
```

## Basic Usage

### Engine Creation with Validation

```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
from core.bypass.engines.config_models import EngineCreationRequest, EnhancedEngineConfig

factory = EnhancedEngineFactory()

# Create enhanced configuration
config = EnhancedEngineConfig(
    debug=True,
    timeout=45.0,
    tool_name="zapret",
    enable_metrics=True
)

# Create detailed request
request = EngineCreationRequest(
    engine_type=EngineType.EXTERNAL_TOOL,
    config=config,
    allow_fallback=True,
    validate_dependencies=True
)

# Get detailed result
result = factory.create_engine_with_result(request)

if result.success:
    print(f"Engine created: {result.engine.__class__.__name__}")
    if result.fallback_used:
        print("Fallback was used")
    if result.warnings:
        print(f"Warnings: {result.warnings}")
else:
    print(f"Creation failed: {result.error_message}")
```

### System Capabilities Detection

```python
factory = EnhancedEngineFactory()

# Check system capabilities
capabilities = factory.get_system_capabilities()
print(f"Platform: {capabilities['platform']}")
print(f"Is Admin: {capabilities['is_admin']}")

# Get available engines
available = factory.get_available_engines()
print(f"Available engines: {[et.value for et in available]}")

# Get recommended engine
recommended = factory.detect_best_engine_type()
print(f"Recommended: {recommended.value}")
```

### Engine Validation

```python
factory = EnhancedEngineFactory()

# Validate specific engine
requirements = factory.validate_engine_requirements(EngineType.NATIVE_PYDIVERT)
print(f"Dependencies met: {requirements['dependencies_met']}")
print(f"Available: {requirements['available']}")

# Get detailed detection info
details = factory.get_engine_detection_details(EngineType.NATIVE_PYDIVERT)
print(f"Score: {details['score']}")
print(f"Missing dependencies: {details['missing_dependencies']}")
```

## Advanced Configuration

### Configuration Management

```python
factory = EnhancedEngineFactory()

# Set engine priority (higher = more preferred)
factory.set_engine_priority(EngineType.EXTERNAL_TOOL, 90)

# Enable/disable engines
factory.enable_engine(EngineType.NATIVE_NETFILTER, False)

# Set configuration overrides
factory.set_engine_config_override(EngineType.EXTERNAL_TOOL, {
    "debug": True,
    "timeout": 60.0,
    "tool_name": "custom_tool"
})

# Get current configuration
config_info = factory.get_configuration_info()
print(f"Loaded from: {config_info['loaded_from']}")
print(f"Profiles: {len(config_info['profiles'])}")
```

### Configuration Files

Create `config/engine_config.json`:

```json
{
  "global": {
    "default_engine": "external_tool",
    "enable_fallback": true,
    "validate_dependencies": true
  },
  "profiles": {
    "external_tool": {
      "priority": 75,
      "enabled": true,
      "default_config": {
        "debug": false,
        "timeout": 30.0,
        "tool_name": "zapret"
      },
      "description": "External tool engine for cross-platform support"
    },
    "native_pydivert": {
      "priority": 100,
      "enabled": true,
      "default_config": {
        "debug": false,
        "timeout": 30.0,
        "packet_buffer_size": 65535,
        "log_packets": false
      },
      "platform_specific": {
        "Windows": {
          "packet_buffer_size": 131072
        }
      },
      "description": "High-performance Windows packet interception"
    }
  }
}
```

### Environment Variables

Set environment variables with `ENGINE_` prefix:

```bash
# Global settings
export ENGINE_DEFAULT_ENGINE=external_tool
export ENGINE_ENABLE_FALLBACK=true

# Engine-specific settings
export ENGINE_EXTERNAL_TOOL_DEBUG=true
export ENGINE_EXTERNAL_TOOL_TIMEOUT=60.0
```

### Hot Configuration Reload

```python
factory = EnhancedEngineFactory()

# Reload configuration from files and environment
factory.reload_configuration()

# Export current configuration
factory.export_configuration("backup_config.json")

# Validate configuration file
from core.bypass.engines.config_models import validate_config_file
result = validate_config_file("config/engine_config.json")
if not result.valid:
    print(f"Configuration errors: {result.errors}")
```

## Error Handling

### Structured Error Information

```python
factory = EnhancedEngineFactory()

try:
    engine = factory.create_engine("invalid_engine_type")
except Exception as e:
    print(f"Error: {e}")
    
    # Get structured error information if available
    if hasattr(e, 'get_detailed_message'):
        print(f"Detailed: {e.get_detailed_message()}")
    
    if hasattr(e, 'suggestions'):
        print("Suggestions:")
        for suggestion in e.suggestions:
            print(f"  - {suggestion.action}")
```

### Error Recovery with Fallback

```python
factory = EnhancedEngineFactory()

request = EngineCreationRequest(
    engine_type=EngineType.NATIVE_PYDIVERT,  # Might fail on non-Windows
    allow_fallback=True
)

result = factory.create_engine_with_result(request)

if result.success:
    if result.fallback_used:
        print(f"Primary engine failed, using fallback: {result.engine_type.value}")
        print(f"Warnings: {result.warnings}")
    else:
        print(f"Primary engine successful: {result.engine_type.value}")
else:
    print(f"All engines failed: {result.error_message}")
```

### Custom Error Handling

```python
from core.bypass.engines.error_handling import ErrorContext

factory = EnhancedEngineFactory()

# Create error context for better error reporting
context = factory.create_error_context(
    engine_type=EngineType.NATIVE_PYDIVERT,
    operation="manual_creation",
    user_action="create_specific_engine"
)

# Handle errors with context
try:
    engine = factory.create_engine(EngineType.NATIVE_PYDIVERT)
except Exception as e:
    error_result = factory.handle_engine_error(e, context)
    print(f"Error handled: {error_result}")
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "Engine creation failed: PyDivert not available"

**Problem**: PyDivert engine cannot be created.

**Solutions**:
- Install PyDivert: `pip install pydivert`
- Run as administrator (PyDivert requires elevated privileges)
- Use fallback: `factory.create_with_fallback()`

```python
# Check PyDivert availability
details = factory.get_engine_detection_details(EngineType.NATIVE_PYDIVERT)
if not details['available']:
    print(f"PyDivert issues: {details['missing_dependencies']}")
    print(f"Installation hints: {details['installation_hints']}")
```

#### 2. "Permission denied" errors

**Problem**: Insufficient permissions for engine creation.

**Solutions**:
- Run as administrator/root
- Use engines that don't require elevated privileges
- Check permissions: `factory.check_engine_permissions(engine_type)`

```python
# Check permissions for all engines
for engine_type in EngineType:
    perm_result = factory.check_engine_permissions(engine_type)
    if not perm_result['valid']:
        print(f"{engine_type.value} permission issues: {perm_result['errors']}")
```

#### 3. Configuration file errors

**Problem**: Invalid configuration file format.

**Solutions**:
- Validate configuration: `validate_config_file("config.json")`
- Check JSON syntax
- Use configuration templates

```python
# Validate and fix configuration
result = validate_config_file("config/engine_config.json")
if not result.valid:
    print("Configuration errors:")
    for error in result.errors:
        print(f"  - {error}")
    
    # Export working configuration as template
    factory.export_configuration("working_config.json")
```

#### 4. Engine detection issues

**Problem**: Engines not detected correctly.

**Solutions**:
- Clear detection cache: `factory._detector.clear_cache()`
- Check system capabilities: `factory.get_system_capabilities()`
- Verify dependencies manually

```python
# Debug engine detection
for engine_type in EngineType:
    details = factory.get_engine_detection_details(engine_type)
    print(f"{engine_type.value}:")
    print(f"  Available: {details['available']}")
    print(f"  Score: {details['score']}")
    print(f"  Issues: {details['missing_dependencies']}")
```

### Diagnostic Tools

#### System Health Check

```python
def diagnose_engine_factory():
    """Comprehensive engine factory diagnostics."""
    factory = EnhancedEngineFactory()
    
    print("=== Engine Factory Diagnostics ===")
    
    # System capabilities
    capabilities = factory.get_system_capabilities()
    print(f"Platform: {capabilities['platform']}")
    print(f"Admin privileges: {capabilities['is_admin']}")
    print(f"Python version: {capabilities['python_version']}")
    
    # Engine availability
    print("\n=== Engine Availability ===")
    for engine_type in EngineType:
        details = factory.get_engine_detection_details(engine_type)
        status = "✅" if details['available'] else "❌"
        print(f"{status} {engine_type.value} (score: {details['score']})")
        
        if not details['available']:
            print(f"    Missing: {details['missing_dependencies']}")
            print(f"    Hints: {details['installation_hints']}")
    
    # Configuration status
    print("\n=== Configuration Status ===")
    config_info = factory.get_configuration_info()
    print(f"Loaded from: {config_info['loaded_from']}")
    print(f"Config files: {config_info['config_files']}")
    print(f"Validation errors: {len(config_info['validation_errors'])}")
    
    # Test engine creation
    print("\n=== Engine Creation Test ===")
    try:
        engine = factory.create_with_fallback()
        print(f"✅ Successfully created: {engine.__class__.__name__}")
    except Exception as e:
        print(f"❌ Engine creation failed: {e}")

# Run diagnostics
diagnose_engine_factory()
```

#### Performance Monitoring

```python
import time

def benchmark_engine_creation():
    """Benchmark engine creation performance."""
    factory = EnhancedEngineFactory()
    
    # Benchmark different operations
    operations = {
        "detection": lambda: factory.detect_best_engine_type(),
        "validation": lambda: factory.validate_engine_requirements(EngineType.EXTERNAL_TOOL),
        "config_retrieval": lambda: factory._config_manager.get_engine_config(EngineType.EXTERNAL_TOOL),
        "creation": lambda: factory.create_with_fallback()
    }
    
    for name, operation in operations.items():
        start_time = time.time()
        try:
            for _ in range(10):
                operation()
            avg_time = (time.time() - start_time) / 10
            print(f"{name}: {avg_time:.3f}s average")
        except Exception as e:
            print(f"{name}: Failed - {e}")

# Run benchmarks
benchmark_engine_creation()
```

## Best Practices

### 1. Always Use Fallback for Production

```python
# Good: Robust engine creation
engine = factory.create_with_fallback()

# Better: With detailed error handling
request = EngineCreationRequest(allow_fallback=True, validate_dependencies=True)
result = factory.create_engine_with_result(request)

if result.success:
    engine = result.engine
    if result.warnings:
        logger.warning(f"Engine creation warnings: {result.warnings}")
else:
    logger.error(f"Engine creation failed: {result.error_message}")
    raise RuntimeError("Cannot proceed without engine")
```

### 2. Validate Configuration Early

```python
# Validate configuration at startup
config_result = validate_config_file("config/engine_config.json")
if not config_result.valid:
    logger.error(f"Configuration errors: {config_result.errors}")
    # Use defaults or exit

# Check system capabilities
capabilities = factory.get_system_capabilities()
if not capabilities['is_admin'] and requires_admin:
    logger.warning("Running without admin privileges - some engines may not work")
```

### 3. Use Structured Configuration

```python
# Good: Use enhanced configuration
config = EnhancedEngineConfig(
    debug=settings.DEBUG,
    timeout=settings.ENGINE_TIMEOUT,
    enable_metrics=settings.ENABLE_METRICS,
    custom_parameters=settings.ENGINE_CUSTOM_PARAMS
)

request = EngineCreationRequest(
    config=config,
    allow_fallback=True,
    validate_dependencies=True,
    tags=["production", "high-priority"]
)
```

### 4. Monitor Engine Health

```python
# Regular health checks
def check_engine_health():
    factory = EnhancedEngineFactory()
    
    # Check if current engines are still available
    available = factory.get_available_engines()
    if not available:
        logger.critical("No engines available!")
        return False
    
    # Test engine creation
    try:
        test_engine = factory.create_with_fallback()
        logger.info(f"Engine health check passed: {test_engine.__class__.__name__}")
        return True
    except Exception as e:
        logger.error(f"Engine health check failed: {e}")
        return False

# Run periodically
import threading
import time

def health_check_loop():
    while True:
        check_engine_health()
        time.sleep(300)  # Check every 5 minutes

health_thread = threading.Thread(target=health_check_loop, daemon=True)
health_thread.start()
```

### 5. Handle Errors Gracefully

```python
def create_engine_safely():
    """Create engine with comprehensive error handling."""
    factory = EnhancedEngineFactory()
    
    try:
        # Try primary approach
        engine = factory.create_with_fallback()
        return engine, None
        
    except Exception as e:
        logger.error(f"Engine creation failed: {e}")
        
        # Get diagnostic information
        capabilities = factory.get_system_capabilities()
        available = factory.get_available_engines()
        
        error_info = {
            "error": str(e),
            "platform": capabilities['platform'],
            "is_admin": capabilities['is_admin'],
            "available_engines": [et.value for et in available]
        }
        
        return None, error_info

# Usage
engine, error_info = create_engine_safely()
if engine:
    # Proceed with engine
    pass
else:
    # Handle error with diagnostic info
    logger.error(f"Engine creation failed: {error_info}")
```

## API Reference

### EnhancedEngineFactory

Main factory class for creating and managing engines.

#### Methods

- `create_engine(engine_type, config=None, **kwargs)` - Create engine with specified type
- `create_with_fallback(preferred_type=None)` - Create engine with automatic fallback
- `create_engine_with_result(request)` - Create engine and return detailed result
- `detect_best_engine_type()` - Get recommended engine type
- `get_available_engines()` - Get list of available engine types
- `validate_engine_requirements(engine_type)` - Validate engine requirements
- `get_system_capabilities()` - Get system capabilities information
- `set_engine_priority(engine_type, priority)` - Set engine priority
- `enable_engine(engine_type, enabled=True)` - Enable/disable engine
- `reload_configuration()` - Reload configuration from files

### Configuration Models

#### EngineCreationRequest

Request object for engine creation.

```python
request = EngineCreationRequest(
    engine_type=EngineType.EXTERNAL_TOOL,  # Optional
    config=enhanced_config,                # Optional
    parameters={},                         # Additional parameters
    allow_fallback=True,                   # Enable fallback
    validate_dependencies=True,            # Validate before creation
    timeout=30.0,                         # Creation timeout
    tags=["production"]                   # Request tags
)
```

#### EngineCreationResult

Result object from engine creation.

```python
result = factory.create_engine_with_result(request)

# Properties
result.success          # bool: Creation success
result.engine          # BaseBypassEngine: Created engine
result.engine_type     # EngineType: Actual engine type used
result.fallback_used   # bool: Whether fallback was used
result.warnings        # List[str]: Warning messages
result.error_message   # str: Error message if failed
```

#### EnhancedEngineConfig

Enhanced configuration with serialization support.

```python
config = EnhancedEngineConfig(
    debug=True,
    timeout=30.0,
    tool_name="zapret",
    packet_buffer_size=65535,
    enable_metrics=True,
    custom_parameters={"key": "value"}
)

# Serialization
json_str = config.to_json()
config_dict = config.to_dict()
restored = EnhancedEngineConfig.from_json(json_str)
```

### Convenience Functions

- `create_engine_enhanced(engine_type, config, **kwargs)` - Enhanced engine creation
- `get_enhanced_factory()` - Get global factory instance
- `validate_config_file(file_path)` - Validate configuration file

For more detailed API documentation, see the source code docstrings and type hints.