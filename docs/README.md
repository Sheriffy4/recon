# Engine Factory System

This directory contains the engine factory system for creating and managing DPI bypass engines.

## Components

### Original Factory (`factory.py`)
- `create_engine(engine_type, config)` - Original engine creation function
- `detect_best_engine()` - Automatic engine type detection
- `create_best_engine(config)` - Create best available engine
- `create_engine_with_validation()` - Bridge to enhanced factory

### Enhanced Factory (`enhanced_factory.py`)
- `EnhancedEngineFactory` - Advanced factory class with validation and error handling
- `create_engine_enhanced()` - Enhanced engine creation with automatic fallback
- Comprehensive validation and error reporting
- Detailed creation results and diagnostics

### Engine Type Detector (`engine_type_detector.py`)
- `EngineTypeDetector` - Service for automatic engine type detection and validation
- `detect_available_engines()` - Get all available engine types
- `get_recommended_engine()` - Get best engine for current system
- `check_engine_dependencies()` - Validate engine requirements
- System capability assessment and installation recommendations

### Engine Validator (`engine_validator.py`)
- `EngineValidator` - Service for parameter and requirement validation
- `validate_engine_type()` - Validate engine type support and availability
- `validate_parameters()` - Validate engine-specific parameters
- `check_permissions()` - Check required permissions for engine types
- `validate_dependencies()` - Validate engine dependencies with detailed messages
- `validate_config()` - Validate EngineConfig objects
- Comprehensive validation with detailed error reporting and suggestions

### Engine Configuration Manager (`engine_config_manager.py`)
- `EngineConfigManager` - Centralized configuration management service
- `get_default_engine_type()` - Get configured default engine type
- `get_engine_config()` - Get configuration for specific engine types
- `get_fallback_order()` - Get engine fallback order based on configuration
- `validate_config()` - Validate configuration dictionaries
- Configuration loading from files and environment variables
- Priority management and engine enable/disable functionality
- Configuration overrides and hot-reloading support

### Configuration Models (`config_models.py`)
- `EnhancedEngineConfig` - Enhanced engine configuration with serialization support
- `EngineCreationRequest` - Serializable engine creation request model
- `EngineCreationResult` - Serializable engine creation result model
- `ValidationResult` - Comprehensive validation result with detailed issues
- `EngineConfigProfile` - Serializable engine configuration profile
- `ConfigurationState` - Serializable configuration state information
- `ConfigurationManager` - Utilities for configuration serialization and validation
- Full JSON serialization/deserialization support
- File save/load operations with format support
- Comprehensive validation with detailed error reporting

### Error Handling Framework (`error_handling.py`)
- `BaseEngineError` - Base exception class with structured error information
- `EngineDependencyError` - Errors related to missing dependencies
- `EnginePermissionError` - Errors related to insufficient permissions
- `EnginePlatformError` - Errors related to platform compatibility
- `EngineConfigurationError` - Errors related to configuration issues
- `ErrorHandler` - Centralized error handling with categorization and suggestions
- `ErrorContext` - Rich context information for errors
- `ResolutionSuggestion` - Actionable suggestions for resolving errors
- Comprehensive error categorization and severity levels
- Automatic resolution suggestions with installation commands
- Error serialization and structured logging support

## Usage Examples

### Basic Usage (Original Factory)
```python
from core.bypass.engines.factory import create_engine, EngineType, EngineConfig

# Create specific engine type
config = EngineConfig(debug=True)
engine = create_engine(EngineType.NATIVE_PYDIVERT, config)

# Create best available engine
engine = create_best_engine(config)
```

### Enhanced Usage (With Validation)
```python
from core.bypass.engines.factory import create_engine_with_validation

# Auto-detect engine with validation
engine = create_engine_with_validation()

# Create specific engine with fallback
engine = create_engine_with_validation("native_pydivert", debug=True)
```

### Advanced Usage (Enhanced Factory)
```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory, EngineCreationRequest

factory = EnhancedEngineFactory()

# Get detailed creation results
request = EngineCreationRequest(
    engine_type="native_pydivert",
    allow_fallback=True,
    validate_dependencies=True
)

result = factory.create_engine_with_result(request)

if result.success:
    print(f"Created: {result.engine.__class__.__name__}")
    print(f"Validation: {result.validation_results}")
    print(f"Warnings: {result.warnings}")
else:
    print(f"Failed: {result.error_message}")

# Check available engines
available = factory.get_available_engines()
print(f"Available engines: {[e.value for e in available]}")

# Get system capabilities
capabilities = factory.get_system_capabilities()
print(f"Platform: {capabilities['platform']}")
print(f"Admin: {capabilities['is_admin']}")

# Get installation recommendations
recommendations = factory.get_installation_recommendations()
for engine, hints in recommendations.items():
    print(f"{engine}: {hints}")
```

### Engine Type Detection Usage
```python
from core.bypass.engines.engine_type_detector import get_engine_type_detector

detector = get_engine_type_detector()

# Check system capabilities
capabilities = detector.check_system_capabilities()
print(f"Platform: {capabilities.platform}")
print(f"Available packages: {capabilities.available_packages}")

# Get detailed detection results
from core.bypass.engines.base import EngineType
result = detector.get_detection_details(EngineType.NATIVE_PYDIVERT)
print(f"PyDivert available: {result.available}")
print(f"Missing dependencies: {result.missing_dependencies}")
print(f"Installation hints: {result.installation_hints}")

# Get all available engines
available = detector.detect_available_engines()
print(f"Available engines: {[e.value for e in available]}")

# Get recommended engine
recommended = detector.get_recommended_engine()
print(f"Recommended: {recommended.value}")
```

### Engine Validation Usage
```python
from core.bypass.engines.engine_validator import get_engine_validator
from core.bypass.engines.base import EngineType, EngineConfig

validator = get_engine_validator()

# Validate engine type
result = validator.validate_engine_type(EngineType.NATIVE_PYDIVERT)
print(f"Engine valid: {result.valid}")
print(f"Errors: {result.errors}")
print(f"Warnings: {result.warnings}")

# Validate parameters
params = {"debug": True, "timeout": 30.0, "invalid_param": "value"}
result = validator.validate_parameters(EngineType.NATIVE_PYDIVERT, params)
print(f"Parameters valid: {result.valid}")

# Check permissions
result = validator.check_permissions(EngineType.NATIVE_PYDIVERT)
print(f"Has permissions: {result.valid}")

# Validate dependencies
result = validator.validate_dependencies(EngineType.NATIVE_PYDIVERT)
print(f"Dependencies met: {result.valid}")

# Comprehensive validation
config = EngineConfig(debug=True, timeout=30.0)
result = validator.validate_all(EngineType.NATIVE_PYDIVERT, config, params)
print(f"Overall valid: {result.valid}")

# Get detailed issue information
for issue in result.issues:
    print(f"{issue.severity.value}: {issue.message}")
    if issue.suggestion:
        print(f"  Suggestion: {issue.suggestion}")
```

### Enhanced Factory with Validation
```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
from core.bypass.engines.base import EngineType, EngineConfig

factory = EnhancedEngineFactory()

# Validate engine configuration
config = EngineConfig(debug=True, timeout=30.0)
validation = factory.validate_engine_configuration(EngineType.NATIVE_PYDIVERT, config)
print(f"Config valid: {validation['valid']}")
print(f"Issues: {len(validation['issues'])}")

# Check permissions through factory
permissions = factory.check_engine_permissions(EngineType.NATIVE_PYDIVERT)
print(f"Has permissions: {permissions['has_required_permissions']}")

# Validate dependencies through factory
dependencies = factory.validate_engine_dependencies(EngineType.NATIVE_PYDIVERT)
print(f"Dependencies valid: {dependencies['valid']}")
```

### Configuration Management Usage
```python
from core.bypass.engines.engine_config_manager import get_engine_config_manager
from core.bypass.engines.base import EngineType

config_manager = get_engine_config_manager()

# Get default engine type
default_engine = config_manager.get_default_engine_type()
print(f"Default engine: {default_engine.value}")

# Get engine configuration
config = config_manager.get_engine_config(EngineType.NATIVE_PYDIVERT)
print(f"PyDivert config: {config}")

# Get EngineConfig object
config_obj = config_manager.get_engine_config_object(EngineType.NATIVE_PYDIVERT)
print(f"Config object: {config_obj}")

# Get fallback order
fallback_order = config_manager.get_fallback_order()
print(f"Fallback order: {[e.value for e in fallback_order]}")

# Set engine priority
config_manager.set_engine_priority(EngineType.EXTERNAL_TOOL, 75)

# Enable/disable engines
config_manager.enable_engine(EngineType.NATIVE_NETFILTER, False)

# Set configuration overrides
config_manager.set_config_override(EngineType.EXTERNAL_TOOL, {"debug": True})

# Get configuration state
state = config_manager.get_configuration_state()
print(f"Loaded from: {state['loaded_from']}")
print(f"Config files: {state['config_files']}")

# Reload configuration
config_manager.reload_configuration()
```

### Configuration File Format
Create `config/engine_config.json`:
```json
{
  "global": {
    "default_engine": "native_pydivert",
    "enable_fallback": true,
    "validate_dependencies": true,
    "log_level": "INFO"
  },
  "profiles": {
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
          "packet_buffer_size": 65535
        }
      }
    },
    "external_tool": {
      "priority": 50,
      "enabled": true,
      "default_config": {
        "debug": false,
        "timeout": 30.0,
        "tool_name": "zapret"
      }
    }
  }
}
```

### Environment Variables
Set configuration via environment variables:
```bash
# Global configuration
export ENGINE_DEFAULT_ENGINE=external_tool
export ENGINE_LOG_LEVEL=DEBUG
export ENGINE_ENABLE_FALLBACK=true

# Engine-specific configuration
export ENGINE_PYDIVERT_DEBUG=true
export ENGINE_EXTERNAL_TOOL_TIMEOUT=45.0
```

### Configuration Models Usage
```python
from core.bypass.engines.config_models import (
    EnhancedEngineConfig, EngineCreationRequest, EngineCreationResult,
    ValidationResult, EngineConfigProfile, ConfigurationManager
)
from core.bypass.engines.base import EngineType

# Create enhanced configuration
config = EnhancedEngineConfig(
    debug=True,
    timeout=45.0,
    packet_buffer_size=32768,
    custom_parameters={"custom_setting": "value"},
    retry_attempts=3,
    enable_metrics=True
)

# Validate configuration
errors = config.validate()
print(f"Validation errors: {errors}")

# Serialize configuration
config_json = config.to_json(indent=2)
config_dict = config.to_dict()

# Save/load from file
config.save_to_file("engine_config.json")
loaded_config = EnhancedEngineConfig.load_from_file("engine_config.json")

# Create engine creation request
request = EngineCreationRequest(
    engine_type=EngineType.NATIVE_PYDIVERT,
    config=config,
    parameters={"additional": "param"},
    tags=["production", "high-priority"],
    metadata={"source": "api"}
)

# Serialize request
request_json = request.to_json()
request_from_json = EngineCreationRequest.from_json(request_json)

# Create configuration profile
profile = EngineConfigProfile(
    engine_type=EngineType.NATIVE_PYDIVERT,
    priority=100,
    enabled=True,
    default_config=config,
    required_permissions=["administrator"],
    dependencies=["pydivert"],
    fallback_engines=[EngineType.EXTERNAL_TOOL],
    description="High-performance Windows engine"
)

# Serialize profile
profile.save_to_file("pydivert_profile.json")

# Configuration management
config_manager = ConfigurationManager()

# Validate configuration file
validation = config_manager.validate_configuration_file("config.json")
print(f"Config valid: {validation.valid}")
print(f"Errors: {validation.errors}")

# Serialize multiple profiles
profiles = {
    EngineType.NATIVE_PYDIVERT: profile,
    # ... more profiles
}
serialized = config_manager.serialize_profiles(profiles)
deserialized = config_manager.deserialize_profiles(serialized)
```

### Enhanced Factory with Models
```python
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory
from core.bypass.engines.config_models import (
    EnhancedEngineConfig, EngineCreationRequest, SerializationFormat
)

factory = EnhancedEngineFactory()

# Create enhanced configuration
config = factory.create_enhanced_config(
    debug=True,
    timeout=60.0,
    custom_parameters={"test": True}
)

# Create engine from request
request = EngineCreationRequest(
    engine_type="native_pydivert",
    config=config,
    tags=["test"]
)

result = factory.create_engine_from_request(request)
print(f"Success: {result.success}")
print(f"Summary: {result.get_summary()}")

# Export configuration
factory.export_configuration("factory_config.json")

# Validate configuration file
validation = factory.validate_configuration_file("config.json")
print(f"Valid: {validation.valid}")

# Get serializable state
state = factory.get_serializable_state()
print(f"State: {state}")
```

### Error Handling Usage
```python
from core.bypass.engines.error_handling import (
    BaseEngineError, EngineDependencyError, EnginePermissionError,
    ErrorHandler, ErrorContext, ResolutionSuggestion, get_error_handler
)
from core.bypass.engines.base import EngineType

# Create structured errors
dependency_error = EngineDependencyError(
    "PyDivert package not found",
    missing_dependencies=["pydivert"],
    context=ErrorContext(
        engine_type=EngineType.NATIVE_PYDIVERT,
        operation="engine_creation"
    )
)

permission_error = EnginePermissionError(
    "Administrator privileges required",
    required_permissions=["administrator"]
)

# Handle errors with resolution suggestions
error_handler = get_error_handler()
result = error_handler.handle_error(dependency_error)

print(f"Error handled: {result['handled']}")
print(f"Suggestions: {result['suggestions_count']}")

# Get detailed error information
print(f"Detailed message: {dependency_error.get_detailed_message()}")
print(f"Resolution text: {dependency_error.get_resolution_text()}")

# Serialize errors
error_dict = dependency_error.to_dict()
print(f"Serialized error: {error_dict}")

# Create errors from exceptions
try:
    import non_existent_module
except ImportError as e:
    structured_error = error_handler.create_error_from_exception(e)
    print(f"Created error: {structured_error.__class__.__name__}")

# Enhanced factory error handling
from core.bypass.engines.enhanced_factory import EnhancedEngineFactory

factory = EnhancedEngineFactory()

# Create error context
context = factory.create_error_context(
    engine_type=EngineType.NATIVE_PYDIVERT,
    operation="engine_creation",
    user_action="create_engine"
)

# Handle errors through factory
error = BaseEngineError("Test error")
result = factory.handle_engine_error(error, context)

# Get error suggestions
suggestions = factory.get_error_suggestions("PYDIVERT_NOT_FOUND", context)
for suggestion in suggestions:
    print(f"Suggestion: {suggestion['action']}")
    if suggestion['command']:
        print(f"  Command: {suggestion['command']}")
```

### Error Categories and Types
The framework provides comprehensive error categorization:

**Error Categories:**
- `CONFIGURATION` - Configuration-related errors
- `DEPENDENCY` - Missing or invalid dependencies
- `PERMISSION` - Insufficient permissions
- `PLATFORM` - Platform compatibility issues
- `VALIDATION` - Validation failures
- `CREATION` - Engine creation errors
- `RUNTIME` - Runtime operation errors
- `NETWORK` - Network-related errors
- `SYSTEM` - General system errors

**Error Severity Levels:**
- `LOW` - Minor issues that don't prevent operation
- `MEDIUM` - Issues that may affect functionality
- `HIGH` - Serious issues that prevent normal operation
- `CRITICAL` - Critical failures that require immediate attention

**Automatic Resolution Suggestions:**
- Dependency installation commands
- Permission elevation instructions
- Platform-specific guidance
- Configuration fix suggestions
- Alternative engine recommendations

## Engine Types

- `NATIVE_PYDIVERT` - Windows-only, high-performance packet interception
- `EXTERNAL_TOOL` - Cross-platform, uses external tools like zapret
- `NATIVE_NETFILTER` - Linux-only, direct netfilter integration (not implemented)

## Error Handling

The enhanced factory provides detailed error categorization:

- `MissingParameterError` - Required parameters not provided
- `InvalidEngineTypeError` - Unknown or invalid engine type
- `DependencyError` - Required dependencies missing
- `PermissionError` - Insufficient permissions
- `EngineCreationError` - General creation failure

## Validation

The enhanced factory validates:

- Platform compatibility
- Required dependencies (PyDivert, etc.)
- System permissions
- Engine-specific requirements

## Fallback Mechanisms

When primary engine creation fails, the system automatically tries:

1. Alternative engines based on platform
2. Engines with fewer requirements
3. Mock engines for testing (if available)

## Configuration

Engine configuration is handled through the `EngineConfig` dataclass:

```python
@dataclass
class EngineConfig:
    debug: bool = False
    timeout: float = 30.0
    base_path: Optional[str] = None
    tool_name: Optional[str] = None
    packet_buffer_size: int = 65535
    max_concurrent_connections: int = 1000
    log_packets: bool = False
```

## Migration Guide

### From Original Factory
Replace:
```python
from core.bypass.engines.factory import create_engine
engine = create_engine(engine_type, config)
```

With:
```python
from core.bypass.engines.factory import create_engine_with_validation
engine = create_engine_with_validation(engine_type, config)
```

### Benefits of Enhanced Factory
- Automatic engine type detection
- Comprehensive validation
- Detailed error messages
- Fallback mechanisms
- Better debugging information
- Forward compatibility