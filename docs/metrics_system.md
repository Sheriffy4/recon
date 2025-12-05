# Attack Parity Metrics System

## Overview

The Attack Parity Metrics System provides comprehensive monitoring and tracking of the DPI bypass system's performance, focusing on:

1. **Compliance Scores** - How well PCAP captures match expected strategies
2. **Attack Detection Rates** - Success rate of detecting attacks in PCAP files
3. **Strategy Application Failures** - Tracking when and why strategy applications fail
4. **PCAP Validation Errors** - Monitoring PCAP parsing and validation issues

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                  Metrics Collection Layer                    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │     AttackParityMetricsCollector                     │  │
│  │  - Thread-safe metric recording                      │  │
│  │  - Automatic persistence to disk                     │  │
│  │  - Time-based retention                              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Integration Points                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Compliance   │  │ PCAP         │  │ Attack       │     │
│  │ Checker      │  │ Validator    │  │ Dispatcher   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Monitoring Integration                      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │     MonitoringSystem                                 │  │
│  │  - Includes metrics in status reports                │  │
│  │  - Real-time metrics dashboard                       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Metric Types

### 1. Compliance Metrics

Tracks how well PCAP captures match expected strategies.

**Fields:**
- `domain`: Domain being validated
- `timestamp`: When the check occurred
- `score`: Compliance score achieved
- `max_score`: Maximum possible score
- `percentage`: Compliance percentage (0-100%)
- `issues_count`: Number of compliance issues found
- `expected_attacks`: List of expected attack types
- `detected_attacks`: List of detected attack types
- `mode`: "testing" or "production"

**Example:**
```python
collector.record_compliance(
    domain="example.com",
    score=28,
    max_score=30,
    issues_count=1,
    expected_attacks=["fake", "multisplit", "disorder"],
    detected_attacks=["fake", "multisplit"],
    mode="production"
)
```

### 2. Attack Detection Metrics

Tracks success rate of detecting specific attack types in PCAP files.

**Fields:**
- `attack_type`: Type of attack (fake, split, multisplit, disorder)
- `timestamp`: When the detection occurred
- `total_attempts`: Total detection attempts
- `successful_detections`: Number of successful detections
- `failed_detections`: Number of failed detections
- `detection_rate`: Success rate percentage
- `average_confidence`: Average confidence score (0.0-1.0)

**Example:**
```python
collector.record_attack_detection(
    attack_type="multisplit",
    total_attempts=10,
    successful_detections=9,
    failed_detections=1,
    average_confidence=0.95
)
```

### 3. Strategy Application Metrics

Tracks when strategies are applied and whether they succeed or fail.

**Fields:**
- `domain`: Domain for which strategy was applied
- `timestamp`: When the application occurred
- `strategy_id`: Identifier of the strategy
- `attacks`: List of attacks in the strategy
- `success`: Whether application succeeded
- `error_message`: Error message if failed
- `application_time_ms`: Time taken to apply strategy
- `mode`: "testing" or "production"

**Example:**
```python
collector.record_strategy_application(
    domain="example.com",
    strategy_id="recipe_12345",
    attacks=["fake", "multisplit"],
    success=True,
    error_message=None,
    application_time_ms=15.3,
    mode="production"
)
```

### 4. PCAP Validation Metrics

Tracks PCAP file parsing and validation errors.

**Fields:**
- `pcap_file`: Path to PCAP file
- `timestamp`: When the validation occurred
- `validation_success`: Whether validation succeeded
- `error_type`: Type of error if failed
- `error_message`: Error message if failed
- `packets_analyzed`: Number of packets analyzed
- `streams_found`: Number of TCP streams found
- `clienthello_found`: Whether ClientHello was found
- `validation_time_ms`: Time taken for validation

**Example:**
```python
collector.record_pcap_validation(
    pcap_file="capture.pcap",
    validation_success=True,
    error_type=None,
    error_message=None,
    packets_analyzed=150,
    streams_found=3,
    clienthello_found=True,
    validation_time_ms=45.2
)
```

## Usage

### Basic Usage

```python
from core.metrics.attack_parity_metrics import get_metrics_collector

# Get global collector instance
collector = get_metrics_collector()

# Record metrics
collector.record_compliance(...)
collector.record_attack_detection(...)
collector.record_strategy_application(...)
collector.record_pcap_validation(...)

# Get summary
summary = collector.get_summary(time_window_minutes=60)
print(f"Average compliance: {summary.average_compliance_score:.1f}%")
print(f"Detection rate: {summary.overall_detection_rate:.1f}%")
```

### Viewing Metrics

Use the CLI tool to view metrics:

```bash
# Show summary for last hour
python tools/view_metrics.py summary

# Show summary for last 24 hours
python tools/view_metrics.py summary --window 1440

# Show compliance history
python tools/view_metrics.py compliance --limit 20

# Show compliance for specific domain
python tools/view_metrics.py compliance --domain example.com

# Show detection history
python tools/view_metrics.py detection --limit 20

# Show detection for specific attack
python tools/view_metrics.py detection --attack multisplit

# Show application history
python tools/view_metrics.py application --limit 20

# Show validation history
python tools/view_metrics.py validation --limit 20

# Export all metrics to JSON
python tools/view_metrics.py export metrics_export.json
```

### Integration with Monitoring System

The metrics are automatically integrated into the monitoring system:

```python
from monitoring_system import MonitoringSystem, MonitoringConfig

# Create monitoring system
config = MonitoringConfig()
monitor = MonitoringSystem(config)

# Get status report (includes attack parity metrics)
report = monitor.get_status_report()
print(report["attack_parity_metrics"])
```

## Configuration

### Retention Period

Configure how long metrics are kept in memory:

```python
from core.metrics.attack_parity_metrics import AttackParityMetricsCollector

# Keep metrics for 48 hours
collector = AttackParityMetricsCollector(retention_hours=48)
```

### Auto-Save

Enable or disable automatic saving to disk:

```python
# Disable auto-save
collector = AttackParityMetricsCollector(auto_save=False)

# Manually save when needed
collector._save_metrics()
```

### Custom Save Path

Specify custom path for metrics storage:

```python
collector = AttackParityMetricsCollector(
    save_path="custom/path/metrics.json"
)
```

## Metrics Summary

The `MetricsSummary` provides aggregated statistics over a time window:

```python
summary = collector.get_summary(time_window_minutes=60)

# Compliance metrics
print(f"Total checks: {summary.total_compliance_checks}")
print(f"Average score: {summary.average_compliance_score:.1f}%")
print(f"Perfect compliance: {summary.perfect_compliance_count}")

# Detection metrics
print(f"Overall detection rate: {summary.overall_detection_rate:.1f}%")
for attack, rate in summary.detection_rates_by_attack.items():
    print(f"  {attack}: {rate:.1f}%")

# Application metrics
print(f"Success rate: {summary.application_success_rate:.1f}%")
print(f"Avg time: {summary.average_application_time_ms:.1f}ms")

# Validation metrics
print(f"Validation success rate: {summary.validation_success_rate:.1f}%")
```

## Best Practices

### 1. Record Metrics at Key Points

Record metrics at critical points in the system:

- After compliance checking
- After attack detection
- After strategy application
- After PCAP validation

### 2. Use Appropriate Time Windows

Choose time windows based on your needs:

- **Real-time monitoring**: 5-15 minutes
- **Recent activity**: 60 minutes
- **Daily summary**: 1440 minutes (24 hours)
- **Weekly trends**: 10080 minutes (7 days)

### 3. Monitor Failure Rates

Pay attention to failure metrics:

```python
summary = collector.get_summary(60)

# Alert if compliance drops below 80%
if summary.average_compliance_score < 80:
    alert("Low compliance score!")

# Alert if detection rate drops below 90%
if summary.overall_detection_rate < 90:
    alert("Low detection rate!")

# Alert if application failures increase
if summary.failed_applications > 10:
    alert("High application failure rate!")
```

### 4. Export for Analysis

Regularly export metrics for offline analysis:

```python
# Export daily
collector.export_to_json(f"metrics_{datetime.now().date()}.json")
```

## Troubleshooting

### Metrics Not Being Recorded

1. Check if metrics module is imported correctly
2. Verify METRICS_AVAILABLE flag is True
3. Check logs for metric recording errors

### High Memory Usage

1. Reduce retention period
2. Export and clear old metrics regularly:

```python
collector.export_to_json("backup.json")
collector.clear_all_metrics()
```

### Slow Performance

1. Disable auto-save for high-frequency operations
2. Batch metric recording when possible
3. Use separate thread for metric recording

## API Reference

See `core/metrics/attack_parity_metrics.py` for complete API documentation.

### Key Classes

- `AttackParityMetricsCollector`: Main metrics collector
- `ComplianceMetric`: Compliance score data
- `AttackDetectionMetric`: Detection rate data
- `StrategyApplicationMetric`: Application tracking data
- `PCAPValidationMetric`: Validation error data
- `MetricsSummary`: Aggregated statistics

### Key Functions

- `get_metrics_collector()`: Get global collector instance
- `record_compliance()`: Record compliance metric
- `record_attack_detection()`: Record detection metric
- `record_strategy_application()`: Record application metric
- `record_pcap_validation()`: Record validation metric
- `get_summary()`: Get aggregated summary
- `export_to_json()`: Export all metrics

## Examples

### Example 1: Monitoring Compliance Trends

```python
from core.metrics.attack_parity_metrics import get_metrics_collector
import time

collector = get_metrics_collector()

# Monitor compliance over time
while True:
    summary = collector.get_summary(60)
    print(f"Compliance: {summary.average_compliance_score:.1f}%")
    print(f"Detection: {summary.overall_detection_rate:.1f}%")
    time.sleep(300)  # Check every 5 minutes
```

### Example 2: Alerting on Failures

```python
def check_metrics_health():
    collector = get_metrics_collector()
    summary = collector.get_summary(60)
    
    alerts = []
    
    if summary.average_compliance_score < 80:
        alerts.append(f"Low compliance: {summary.average_compliance_score:.1f}%")
    
    if summary.overall_detection_rate < 90:
        alerts.append(f"Low detection rate: {summary.overall_detection_rate:.1f}%")
    
    if summary.application_success_rate < 95:
        alerts.append(f"High failure rate: {100 - summary.application_success_rate:.1f}%")
    
    return alerts
```

### Example 3: Performance Analysis

```python
def analyze_performance():
    collector = get_metrics_collector()
    
    # Get application history
    history = collector.get_application_history(limit=100)
    
    # Calculate statistics
    times = [m.application_time_ms for m in history if m.success]
    avg_time = sum(times) / len(times) if times else 0
    max_time = max(times) if times else 0
    
    print(f"Average application time: {avg_time:.1f}ms")
    print(f"Maximum application time: {max_time:.1f}ms")
    
    # Identify slow domains
    domain_times = {}
    for m in history:
        if m.success:
            if m.domain not in domain_times:
                domain_times[m.domain] = []
            domain_times[m.domain].append(m.application_time_ms)
    
    for domain, times in domain_times.items():
        avg = sum(times) / len(times)
        if avg > 50:  # Slow threshold
            print(f"Slow domain: {domain} ({avg:.1f}ms)")
```
