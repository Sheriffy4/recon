# Diagnostic System Package

Comprehensive monitoring, analysis, and optimization system for DPI bypass operations.

## Overview

The Diagnostic System provides real-time monitoring, performance analysis, and optimization recommendations for byte-level DPI bypass operations. It has been refactored from a monolithic 2,881 LOC god class into a modular architecture with 9 specialized components.

## Architecture

```
core/diagnostic_system/
├── __init__.py                     # Package exports and documentation
├── diagnostic_system_main.py       # Main coordinator/facade (1,200 LOC)
├── metrics_manager.py              # Attack metrics & failure tracking (360 LOC)
├── packet_analyzer.py              # Byte-level packet analysis (345 LOC)
├── protocol_logger.py              # Protocol-specific logging (155 LOC)
├── recommendation_engine.py        # Recommendation generation (380 LOC)
├── attack_logger.py                # Attack result logging (90 LOC)
├── error_classifier.py             # Error categorization (110 LOC)
├── report_generator.py             # Performance report generation (230 LOC)
├── monitoring_coordinator.py       # Real-time monitoring (105 LOC)
└── statistics_manager.py           # Statistics & health scoring (180 LOC)
```

## Modules

### DiagnosticSystem (Main Facade)
Main coordinator that provides unified interface to all diagnostic functionality.

**Key Methods:**
- `start_monitoring()` - Start real-time monitoring
- `stop_monitoring()` - Stop monitoring
- `log_packet_processing()` - Log packet processing events
- `log_attack_result()` - Log attack execution results
- `analyze_bypass_effectiveness()` - Analyze bypass effectiveness
- `generate_performance_report()` - Generate performance report
- `get_stats()` - Get system statistics

### MetricsManager
Manages attack performance metrics and failure analysis.

**Responsibilities:**
- Track attack execution metrics
- Analyze attack failures
- Calculate performance metrics
- Maintain category health scores

### PacketAnalyzer
Performs byte-level packet analysis and protocol detection.

**Responsibilities:**
- Analyze packet bytes
- Extract IPv4/IPv6 headers
- Analyze TCP/UDP segments
- Detect protocol patterns

### ProtocolLogger
Provides protocol-specific logging for TLS, HTTP, and QUIC.

**Responsibilities:**
- Log TLS packet details
- Log HTTP packet details
- Log QUIC packet details
- Extract SNI and cipher suites

### RecommendationEngine
Generates optimization and troubleshooting recommendations.

**Responsibilities:**
- Generate effectiveness recommendations
- Generate failure recommendations
- Generate optimization recommendations
- Provide troubleshooting steps

### AttackLogger
Handles unified attack result logging.

**Responsibilities:**
- Log attack results
- Track attack performance
- Analyze attack failures
- Maintain attack history

### ErrorClassifier
Categorizes errors and analyzes error patterns.

**Responsibilities:**
- Categorize error messages
- Analyze error patterns
- Determine error severity
- Track error frequencies

### ReportGenerator
Generates comprehensive performance reports.

**Responsibilities:**
- Generate performance reports
- Analyze technique performance
- Analyze attack performance
- Calculate health scores

### MonitoringCoordinator
Coordinates real-time monitoring operations.

**Responsibilities:**
- Run monitoring loop
- Check critical performance
- Monitor technique performance
- Alert on issues

### StatisticsManager
Manages statistics collection and health scoring.

**Responsibilities:**
- Calculate health scores
- Calculate performance scores
- Calculate percentiles
- Generate statistics summaries

## Usage Examples

### Basic Usage

```python
from core.diagnostic_system import DiagnosticSystem

# Create diagnostic system
diagnostic = DiagnosticSystem(attack_adapter, debug=True)

# Start monitoring
diagnostic.start_monitoring(fast_bypass_engine)

# Log packet processing
diagnostic.log_packet_processing(
    packet=packet,
    action="bypassed",
    technique_used="tcp_fragmentation",
    processing_time_ms=5.2,
    success=True
)

# Generate report
report = diagnostic.generate_performance_report()
print(f"Health Score: {report.system_health_score:.2f}")
print(f"Success Rate: {report.bypass_success_rate:.2%}")
```

### Advanced Analysis

```python
# Analyze effectiveness over last hour
analysis = diagnostic.analyze_bypass_effectiveness(time_window_minutes=60)

print(f"Overall Effectiveness: {analysis['bypass_effectiveness']:.2%}")
print(f"Top Techniques: {analysis['technique_effectiveness']}")
print(f"Recommendations: {analysis['recommendations']}")

# Analyze attack failures
failures = diagnostic.analyze_attack_failures(time_window_minutes=30)
print(f"Total Failures: {failures['total_failures']}")
print(f"Critical Attacks: {failures['critical_attacks']}")
```

### Component Usage

```python
from core.diagnostic_system import (
    ErrorClassifier,
    StatisticsManager,
    ReportGenerator
)

# Use ErrorClassifier independently
classifier = ErrorClassifier(recommendation_engine, debug=True)
category = classifier.categorize_error("WinError 87: Invalid parameter")
print(f"Error Category: {category}")

# Use StatisticsManager independently
stats_mgr = StatisticsManager(thresholds, debug=True)
health = stats_mgr.calculate_health_score(
    effectiveness=0.85,
    processing_time=45.0,
    packet_events=events,
    error_events=errors
)
print(f"Health Score: {health:.2f}")
```

## Design Patterns

### Facade Pattern
`DiagnosticSystem` acts as a facade, providing a simplified interface to the complex subsystem of specialized modules.

### Delegation Pattern
The main class delegates responsibilities to specialized components, maintaining loose coupling.

### Callback Pattern
`MonitoringCoordinator` uses callbacks for loose coupling with the main system.

### Single Responsibility Principle
Each module has one clear, well-defined responsibility.

## Testing

Each module can be tested independently:

```python
import pytest
from core.diagnostic_system import ErrorClassifier

def test_error_classifier():
    classifier = ErrorClassifier(mock_engine, debug=False)
    
    # Test categorization
    assert classifier.categorize_error("WinError 87") == "winerror_87"
    assert classifier.categorize_error("Timeout occurred") == "timeout"
    
    # Test severity
    assert classifier.determine_severity("winerror_87", 15) == "critical"
    assert classifier.determine_severity("timeout", 5) == "low"
```

## Performance

- **Method Call Overhead**: Negligible (Python method calls are cheap)
- **Memory Usage**: ~9 additional objects (~2KB total)
- **Maintainability**: Significantly improved
- **Development Speed**: Faster due to better organization

## Backward Compatibility

All original APIs are preserved. The refactoring is purely structural and maintains 100% backward compatibility:

```python
# Old code still works
from core.diagnostic_system import DiagnosticSystem
diagnostic = DiagnosticSystem(adapter)
diagnostic.log_packet_processing(packet, "bypassed")
report = diagnostic.generate_performance_report()
```

## Migration Guide

No migration needed! All existing code continues to work without changes.

If you want to use new modular components:

```python
# Before (still works)
from core.diagnostic_system import DiagnosticSystem

# After (also works, more explicit)
from core.diagnostic_system import (
    DiagnosticSystem,
    MetricsManager,
    PacketAnalyzer,
    ErrorClassifier
)
```

## Version History

- **v2.0.0** - Major refactoring into modular architecture
  - Extracted 9 specialized modules
  - Reduced main class by 58%
  - Improved testability and maintainability
  - Maintained 100% backward compatibility

- **v1.0.0** - Original monolithic implementation
  - Single file with 2,881 LOC
  - God class with mixed responsibilities

## Contributing

When adding new functionality:

1. Identify the appropriate module
2. Add functionality to that module
3. Update the facade if needed
4. Add tests for the new functionality
5. Update documentation

## License

See LICENSE file in project root.
