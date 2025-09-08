# Zapret Attack Adapter Implementation

## Overview

The **Zapret Attack Adapter** is a unified interface that integrates Zapret DPI bypass attacks into the main RECON bypass system. This adapter bridges between the core attack system and the specialized Zapret implementations, enabling seamless integration with the strategy manager and execution engines.

## Key Features

### 1. Multiple Execution Modes
- **AUTO**: Automatic mode selection based on available components
- **DIRECT**: Direct execution using ZapretStrategy 
- **PRESET**: Execution using predefined configurations
- **INTEGRATION**: Execution through ZapretIntegration component

### 2. Robust Configuration Management
- Type-safe configuration through `ZapretAdapterConfig` 
- Support for custom Zapret parameters
- Preset-based configuration for common use cases
- Runtime configuration validation and updates

### 3. Error Handling & Fallbacks
- Configurable retry mechanisms with progressive backoff
- Automatic fallback to direct mode when other modes fail
- Comprehensive error logging and reporting
- Timeout protection for long-running operations

### 4. Compatibility Layer
- Context conversion between base and Zapret-specific types
- Result format harmonization across different execution paths
- Type annotation compatibility with existing attack interfaces
- Backward compatibility with legacy Zapret components

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   ZapretAttackAdapter                       │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │
│  │  AUTO MODE    │  │ PRESET MODE   │  │ DIRECT MODE   │   │
│  │               │  │               │  │               │   │
│  │ • Auto select │  │ • Use presets │  │ • Direct exec │   │
│  │ • Fallbacks   │  │ • Combo engine│  │ • ZapretStrategy │ │
│  └───────────────┘  └───────────────┘  └───────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Context & Result Conversion             │   │
│  │ • AttackContext ↔ ZapretIntegrationContext          │   │
│  │ • AttackResult harmonization                        │   │
│  │ • Type safety with compatibility layers             │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Usage Examples

### Basic Usage
```python
from core.bypass.attacks.combo.zapret_attack_adapter import ZapretAttackAdapter
from core.bypass.attacks.base import AttackContext

# Create adapter with auto mode
adapter = ZapretAttackAdapter()

# Create attack context
context = AttackContext(
    dst_ip="8.8.8.8",
    dst_port=443,
    domain="example.com"
)

# Execute attack
result = adapter.execute(context)
print(f"Attack result: {result.status}")
```

### Preset-based Configuration
```python
from core.bypass.attacks.combo.zapret_attack_adapter import create_zapret_adapter_with_preset

# Create adapter with aggressive preset
adapter = create_zapret_adapter_with_preset("aggressive")
result = adapter.execute(context)
```

### Custom Configuration
```python
from core.bypass.attacks.combo.zapret_attack_adapter import create_zapret_adapter_with_config

# Create adapter with custom configuration
custom_config = {
    'split_seqovl': 400,
    'repeats': 5,
    'auto_ttl': True
}
adapter = create_zapret_adapter_with_config(custom_config)
result = adapter.execute(context)
```

### Advanced Configuration
```python
from core.bypass.attacks.combo.zapret_attack_adapter import (
    ZapretAttackAdapter, ZapretAdapterConfig, ZapretAdapterMode
)
from core.bypass.attacks.combo.zapret_strategy import ZapretConfig

config = ZapretAdapterConfig(
    mode=ZapretAdapterMode.DIRECT,
    validation_enabled=True,
    retry_count=3,
    timeout_seconds=10.0,
    zapret_config=ZapretConfig(
        split_seqovl=350,
        repeats=7,
        auto_ttl=True
    )
)

adapter = ZapretAttackAdapter(config)
result = adapter.execute(context)
```

## Configuration Options

### ZapretAdapterConfig Parameters
- `mode`: Execution mode (AUTO, DIRECT, PRESET, INTEGRATION)
- `preset_name`: Name of preset configuration to use
- `custom_config`: Custom Zapret parameters
- `fallback_enabled`: Enable automatic fallback to direct mode
- `validation_enabled`: Enable configuration validation
- `retry_count`: Number of retry attempts on failure
- `timeout_seconds`: Maximum execution timeout
- `zapret_config`: Direct ZapretConfig object
- `use_combo_engine`: Enable combo engine integration
- `enable_network_validation`: Enable network validation

### Available Presets
- **default**: Original highly effective configuration
- **aggressive**: More aggressive for stubborn DPI systems
- **conservative**: Less aggressive to avoid detection
- **fast**: Optimized for speed with minimal delays
- **stealth**: Designed to avoid DPI detection

## Integration Points

### Base Attack System
- Implements `BaseAttack` interface with synchronous `execute()` method
- Provides standard `AttackResult` format
- Supports attack categorization and protocol specification
- Compatible with existing strategy management

### Zapret Components
- Integrates with `ZapretStrategy` for direct execution
- Uses `ZapretIntegration` for preset and combo engine support
- Handles type conversions between different context formats
- Manages result format harmonization

### Error Handling
- Comprehensive exception handling with detailed logging
- Automatic retry mechanisms with configurable attempts
- Fallback execution modes for enhanced reliability
- Timeout protection for hanging operations

## Benefits

1. **Unified Interface**: Single adapter for all Zapret integration needs
2. **Flexibility**: Multiple execution modes for different use cases
3. **Reliability**: Robust error handling and fallback mechanisms
4. **Type Safety**: Proper type annotations and validation
5. **Compatibility**: Works with existing attack system architecture
6. **Maintainability**: Clean separation of concerns and modular design

## Files Created/Modified

### New Files
- `core/bypass/attacks/combo/zapret_attack_adapter.py` - Main adapter implementation
- `demo_zapret_adapter.py` - Demonstration script showing usage examples

### Integration
The adapter integrates seamlessly with existing components:
- Uses existing `ZapretStrategy` and `ZapretIntegration` classes
- Compatible with `BaseAttack` interface requirements
- Follows established patterns from other combo attacks
- Maintains compatibility with attack registry and strategy management

## Testing

The implementation has been tested with:
- ✅ Basic import and instantiation
- ✅ All execution modes (AUTO, DIRECT, PRESET, INTEGRATION)
- ✅ Configuration validation and updates
- ✅ Factory function usage
- ✅ Context and result conversion
- ✅ Error handling and fallback mechanisms

## Next Steps

The Zapret Attack Adapter is now ready for integration into the main system. It can be:
1. Registered in the attack registry
2. Used by strategy managers for Zapret-based bypass strategies
3. Integrated into the main CLI and API interfaces
4. Extended with additional preset configurations as needed

This implementation provides a robust, flexible, and maintainable solution for Zapret integration within the RECON bypass system.