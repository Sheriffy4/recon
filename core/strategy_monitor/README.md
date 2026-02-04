# Strategy Monitor Package

Enhanced automatic strategy effectiveness monitoring and DPI change detection system.

## Overview

This package provides comprehensive monitoring capabilities for DPI bypass strategies and attacks,
integrating with FastBypassEngine, AdvancedFingerprintEngine, and the unified attack system.

## Architecture

The package is organized into focused, cohesive modules:

### Core Components

- **`strategy_monitor_core.py`** - Main orchestrator class that coordinates all monitoring activities
- **`models.py`** - Data models (AttackEffectivenessReport, EffectivenessReport, DPIChange, Strategy)
- **`metrics_calculator.py`** - Trend and confidence calculation utilities
- **`database_manager.py`** - Strategy database persistence (best_strategy.json)
- **`dpi_detector.py`** - DPI behavior change detection and analysis
- **`attack_monitor.py`** - Attack-level effectiveness monitoring and ranking
- **`strategy_discovery.py`** - Automatic strategy discovery for failing domains

### Usage

```python
from core.strategy_monitor import StrategyMonitor

# Initialize with engines
monitor = StrategyMonitor(
    fast_bypass_engine=engine,
    advanced_fingerprint_engine=fingerprint_engine,
    debug=True
)

# Start background monitoring
monitor.start_monitoring()

# Monitor specific strategy
report = monitor.monitor_strategy_effectiveness("strategy_id", "example.com")

# Detect DPI changes
changes = monitor.detect_dpi_changes("example.com")

# Get statistics
stats = monitor.get_monitoring_stats()

# Stop monitoring
monitor.stop_monitoring()
```

## Refactoring History

This package was refactored from a single 1322-line god class into 7 focused modules:

**Before:**
- Single file: `core/strategy_monitor.py` (1322 LOC)
- God class with 40+ methods
- Multiple responsibilities mixed together

**After:**
- 7 specialized modules (1737 LOC total)
- Clear separation of concerns
- Improved testability and maintainability
- 31% LOC increase justified by better organization

### Benefits

1. **Reduced Complexity**: Each module has a single, well-defined responsibility
2. **Improved Testability**: Components can be tested in isolation
3. **Better Maintainability**: Changes are localized to specific modules
4. **Enhanced Reusability**: Components can be used independently
5. **Clearer Dependencies**: Explicit component relationships

## Components Detail

### StrategyMonitor (Main Class)

Orchestrates all monitoring activities:
- Strategy effectiveness monitoring
- DPI change detection
- Attack monitoring
- Strategy discovery
- Database updates

### MetricsCalculator

Pure functions for calculating:
- Effectiveness trends (improving/degrading/stable)
- Confidence scores based on data quality
- Latency estimates from statistics

### DatabaseManager

Handles persistence:
- Load/save strategy database
- Load existing domain-strategy mappings
- Update strategies in best_strategy.json format

### DPIChangeDetector

Monitors DPI behavior:
- Fingerprint comparison
- Technique effectiveness changes
- Change recommendations
- Historical data tracking

### AttackMonitor

Attack-level monitoring:
- Individual attack effectiveness
- Attack rankings by category
- Alternative attack recommendations
- Performance tracking

### StrategyDiscovery

Automatic discovery:
- Test techniques for failing domains
- Fingerprint-based technique selection
- Strategy creation and validation

## Migration Notes

The refactored package maintains full backward compatibility:

```python
# Old import (still works)
from core.strategy_monitor import StrategyMonitor

# New imports (for direct component access)
from core.strategy_monitor import (
    StrategyMonitor,
    AttackEffectivenessReport,
    EffectivenessReport,
    DPIChange,
    Strategy,
)
```

All public APIs remain unchanged. The old monolithic file is preserved as `core/strategy_monitor.py.old`.
