# Production Monitoring System

Comprehensive monitoring, alerting, and observability system for the segment-based attack orchestration in production environments.

## Overview

The Production Monitoring System provides real-time monitoring, performance tracking, alerting, and health checking for the Native Attack Orchestration system in production deployments. It ensures system reliability, performance optimization, and rapid issue detection.

## Features

### Core Monitoring Capabilities

- **Real-time Metrics Collection**: Continuous collection of system performance metrics
- **Performance Monitoring**: Track attack execution performance, success rates, and response times
- **Resource Monitoring**: Monitor memory usage, CPU utilization, and system resources
- **Health Checking**: Automated health checks for all system components
- **Anomaly Detection**: Intelligent detection of performance anomalies and deviations

### Alerting System

- **Threshold-based Alerts**: Configurable thresholds for various metrics
- **Alert Severity Levels**: Critical, warning, and info level alerts
- **Alert Cooldowns**: Prevent alert spam with configurable cooldown periods
- **Alert Resolution**: Automatic alert resolution when conditions improve
- **Alert History**: Complete audit trail of all alerts

### Data Management

- **Metrics Storage**: Persistent storage of metrics data with configurable retention
- **Dashboard Data**: Real-time dashboard data updates
- **File-based Storage**: JSON-based storage for metrics and alerts
- **Data Retention**: Configurable retention policies for metrics and alerts

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Production Monitoring System                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ Metrics         │  │ Performance     │  │ Health       │ │
│  │ Collection      │  │ Monitoring      │  │ Checking     │ │
│  │ Loop            │  │ Loop            │  │ Loop         │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Alert           │  │ Dashboard       │                  │
│  │ Processing      │  │ Update          │                  │
│  │ Loop            │  │ Loop            │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ Stats           │  │ Diagnostics     │  │ Performance  │ │
│  │ Collector       │  │ System          │  │ Optimizer    │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ Metrics         │  │ Alerts          │  │ Dashboard    │ │
│  │ Storage         │  │ Storage         │  │ Data         │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### MonitoringConfig

```python
@dataclass
class MonitoringConfig:
    # Monitoring intervals (seconds)
    performance_check_interval: int = 30
    health_check_interval: int = 60
    alert_check_interval: int = 15
    metrics_collection_interval: int = 10
    
    # Alert thresholds
    failure_rate_threshold: float = 0.15  # 15%
    response_time_threshold_ms: float = 200.0
    memory_usage_threshold_mb: float = 100.0
    cpu_usage_threshold_percent: float = 80.0
    
    # Data retention
    metrics_retention_hours: int = 24
    alert_retention_days: int = 7
    
    # Output settings
    monitoring_data_dir: str = "/var/lib/native_attack_orchestration/monitoring"
    enable_real_time_dashboard: bool = True
    enable_prometheus_metrics: bool = False
    
    # Alerting
    enable_email_alerts: bool = False
    enable_webhook_alerts: bool = False
    alert_cooldown_minutes: int = 5
```

### Configuration Examples

#### Production Environment
```python
config = MonitoringConfig(
    monitoring_data_dir="/var/lib/monitoring",
    metrics_collection_interval=10,
    performance_check_interval=30,
    health_check_interval=60,
    
    # Production thresholds
    failure_rate_threshold=0.10,     # 10% failure rate
    response_time_threshold_ms=300.0, # 300ms response time
    memory_usage_threshold_mb=200.0,  # 200MB memory
    cpu_usage_threshold_percent=75.0, # 75% CPU
    
    # Data retention
    metrics_retention_hours=48,      # 48 hours of metrics
    alert_retention_days=14,         # 14 days of alerts
    
    # Enable features
    enable_real_time_dashboard=True,
    enable_prometheus_metrics=True,
    enable_email_alerts=True,
    enable_webhook_alerts=True
)
```

#### Development Environment
```python
config = MonitoringConfig(
    monitoring_data_dir="./dev_monitoring",
    metrics_collection_interval=5,   # More frequent for testing
    performance_check_interval=15,
    health_check_interval=30,
    
    # Relaxed thresholds
    failure_rate_threshold=0.20,     # 20% failure rate
    response_time_threshold_ms=500.0, # 500ms response time
    memory_usage_threshold_mb=500.0,  # 500MB memory
    cpu_usage_threshold_percent=90.0, # 90% CPU
    
    # Shorter retention for development
    metrics_retention_hours=12,
    alert_retention_days=3,
    
    # Disable external integrations
    enable_prometheus_metrics=False,
    enable_email_alerts=False,
    enable_webhook_alerts=False
)
```

## Usage

### Basic Usage

```python
import asyncio
from monitoring.production_monitoring_system import (
    ProductionMonitoringSystem,
    MonitoringConfig
)

async def main():
    # Configure monitoring
    config = MonitoringConfig(
        monitoring_data_dir="./monitoring_data",
        failure_rate_threshold=0.15,
        response_time_threshold_ms=200.0
    )
    
    # Create monitoring system
    monitoring = ProductionMonitoringSystem(config)
    
    try:
        # Start monitoring
        await monitoring.start_monitoring()
        
        # Let it run
        await asyncio.sleep(300)  # 5 minutes
        
        # Check status
        status = monitoring.get_current_status()
        print(f"System Status: {status}")
        
    finally:
        # Stop monitoring
        await monitoring.stop_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
```

### Advanced Usage with Custom Thresholds

```python
async def advanced_monitoring():
    # Configure with strict thresholds
    config = MonitoringConfig(
        monitoring_data_dir="./production_monitoring",
        metrics_collection_interval=5,
        
        # Strict production thresholds
        failure_rate_threshold=0.05,     # 5% failure rate
        response_time_threshold_ms=150.0, # 150ms response time
        memory_usage_threshold_mb=100.0,  # 100MB memory
        cpu_usage_threshold_percent=60.0, # 60% CPU
        
        # Advanced alerting
        alert_cooldown_minutes=5,
        enable_real_time_dashboard=True
    )
    
    monitoring = ProductionMonitoringSystem(config)
    
    try:
        await monitoring.start_monitoring()
        
        # Monitor for extended period
        await asyncio.sleep(1800)  # 30 minutes
        
        # Get detailed analysis
        summary = monitoring.get_metrics_summary(hours=1)
        alerts = monitoring.get_alert_summary()
        
        print(f"Metrics Summary: {summary}")
        print(f"Alert Summary: {alerts}")
        
    finally:
        await monitoring.stop_monitoring()
```

## Metrics

### System Metrics

The monitoring system collects comprehensive metrics:

#### Attack Execution Metrics
- `attacks_per_minute`: Number of attacks executed per minute
- `success_rate`: Percentage of successful attacks (0.0 - 1.0)
- `average_response_time_ms`: Average attack execution time in milliseconds
- `p95_response_time_ms`: 95th percentile response time

#### Segment Metrics
- `segments_per_attack`: Average number of segments per attack
- `segment_execution_success_rate`: Success rate of segment execution
- `timing_accuracy_percent`: Timing accuracy percentage for segments

#### System Resource Metrics
- `memory_usage_mb`: Memory usage in megabytes
- `cpu_usage_percent`: CPU usage percentage

#### Performance Optimizer Metrics
- `cache_hit_rate`: Cache hit rate for performance optimizations
- `optimization_effectiveness`: Effectiveness of performance optimizations

#### Error Metrics
- `error_rate`: Overall error rate (0.0 - 1.0)
- `critical_errors`: Number of critical errors
- `warnings`: Number of warnings

### Metrics Collection

Metrics are collected automatically at configurable intervals and stored in JSON format:

```json
{
  "timestamp": 1640995200.0,
  "attacks_per_minute": 12.5,
  "success_rate": 0.95,
  "average_response_time_ms": 145.2,
  "p95_response_time_ms": 198.7,
  "segments_per_attack": 3.2,
  "segment_execution_success_rate": 0.98,
  "timing_accuracy_percent": 96.5,
  "memory_usage_mb": 85.3,
  "cpu_usage_percent": 42.1,
  "cache_hit_rate": 0.87,
  "optimization_effectiveness": 0.73,
  "error_rate": 0.05,
  "critical_errors": 0,
  "warnings": 2
}
```

## Alerting

### Alert Types

The system generates alerts for various conditions:

#### Performance Alerts
- `high_failure_rate`: When success rate drops below threshold
- `high_response_time`: When response time exceeds threshold
- `performance_anomaly`: When performance deviates significantly from baseline
- `effectiveness_anomaly`: When success rate drops significantly

#### Resource Alerts
- `high_memory_usage`: When memory usage exceeds threshold
- `high_cpu_usage`: When CPU usage exceeds threshold

#### System Health Alerts
- `system_health`: When system components become unhealthy

### Alert Structure

```python
@dataclass
class Alert:
    id: str                    # Unique alert identifier
    type: str                  # Alert type (e.g., 'high_response_time')
    severity: str              # 'critical', 'warning', or 'info'
    title: str                 # Human-readable alert title
    message: str               # Detailed alert message
    timestamp: float           # Alert creation timestamp
    resolved: bool = False     # Whether alert is resolved
    resolved_timestamp: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### Alert Example

```json
{
  "id": "high_response_time_1640995200",
  "type": "high_response_time",
  "severity": "warning",
  "title": "High Response Time",
  "message": "Average response time: 250.5ms",
  "timestamp": 1640995200.0,
  "resolved": false,
  "resolved_timestamp": null,
  "metadata": {
    "response_time_ms": 250.5,
    "threshold_ms": 200.0
  }
}
```

### Alert Resolution

Alerts are automatically resolved when conditions improve:

- **High failure rate**: Resolved when success rate returns above threshold
- **High response time**: Resolved when response time drops below threshold
- **High resource usage**: Resolved when usage drops below threshold

## Health Checking

### Component Health

The system monitors the health of key components:

- **Stats Collector**: Monitors execution statistics collection
- **Diagnostics System**: Monitors diagnostic data collection
- **Performance Optimizer**: Monitors optimization system health

### Health Status

Health status is determined based on component health:

- **healthy**: All components functioning normally
- **degraded**: One component experiencing issues
- **unhealthy**: Multiple components experiencing issues

### Health Check Example

```json
{
  "status": "healthy",
  "components": {
    "stats_collector": "healthy",
    "diagnostics": "healthy",
    "performance_optimizer": "healthy"
  },
  "issues": []
}
```

## Data Storage

### File Structure

The monitoring system stores data in the following structure:

```
monitoring_data_dir/
├── metrics/
│   ├── metrics_1640995200.json
│   ├── metrics_1640995210.json
│   └── ...
├── alerts/
│   ├── alert_high_response_time_1640995200.json
│   ├── alert_high_memory_usage_1640995300.json
│   └── ...
└── dashboard.json
```

### Dashboard Data

Real-time dashboard data is updated regularly:

```json
{
  "timestamp": 1640995200.0,
  "system_status": "healthy",
  "active_alerts_count": 0,
  "critical_alerts_count": 0,
  "current_metrics": {
    "attacks_per_minute": 12.5,
    "success_rate": 0.95,
    "average_response_time_ms": 145.2,
    "memory_usage_mb": 85.3,
    "cpu_usage_percent": 42.1
  },
  "recent_alerts": []
}
```

## API Reference

### ProductionMonitoringSystem

#### Methods

##### `async start_monitoring()`
Start the monitoring system and all monitoring loops.

##### `async stop_monitoring()`
Stop the monitoring system and clean up resources.

##### `get_current_status() -> Dict[str, Any]`
Get current monitoring status including latest metrics and alert counts.

##### `get_metrics_summary(hours: int = 1) -> Dict[str, Any]`
Get metrics summary for the specified time period.

##### `get_alert_summary() -> Dict[str, Any]`
Get summary of current and recent alerts.

#### Internal Methods

##### `async _collect_current_metrics() -> SystemMetrics`
Collect current system metrics from all sources.

##### `async _check_performance_thresholds(metrics: SystemMetrics)`
Check metrics against configured thresholds and generate alerts.

##### `async _check_system_health() -> Dict[str, Any]`
Check the health of all system components.

##### `async _create_alert(alert_type: str, severity: str, title: str, message: str, metadata: Dict[str, Any] = None)`
Create a new alert with cooldown checking.

##### `async _check_alert_resolution()`
Check if active alerts should be resolved based on current metrics.

## Integration

### Prometheus Integration

Enable Prometheus metrics export:

```python
config = MonitoringConfig(
    enable_prometheus_metrics=True
)
```

### External Alerting

Configure external alerting systems:

```python
config = MonitoringConfig(
    enable_email_alerts=True,
    enable_webhook_alerts=True
)
```

### Custom Integrations

Extend the monitoring system with custom integrations:

```python
class CustomMonitoringSystem(ProductionMonitoringSystem):
    async def _process_alert_notifications(self):
        """Custom alert processing."""
        await super()._process_alert_notifications()
        
        # Add custom notification logic
        for alert in self.active_alerts.values():
            if alert.severity == 'critical':
                await self._send_custom_notification(alert)
    
    async def _send_custom_notification(self, alert: Alert):
        """Send custom notification."""
        # Implement custom notification logic
        pass
```

## Best Practices

### Production Deployment

1. **Configure appropriate thresholds** based on your environment
2. **Set up persistent storage** for monitoring data
3. **Enable external alerting** for critical issues
4. **Monitor resource usage** of the monitoring system itself
5. **Regularly review and adjust** thresholds based on performance data

### Performance Optimization

1. **Adjust collection intervals** based on system load
2. **Configure data retention** to balance storage and analysis needs
3. **Use alert cooldowns** to prevent notification spam
4. **Monitor monitoring overhead** to ensure minimal impact

### Troubleshooting

1. **Check log files** for monitoring system errors
2. **Verify component health** using health check endpoints
3. **Review alert history** for patterns and trends
4. **Analyze metrics data** for performance insights

## Examples

See the `examples/production_monitoring_example.py` file for comprehensive usage examples including:

- Basic monitoring setup
- Advanced monitoring with custom thresholds
- Data analysis and reporting
- Deployment monitoring scenarios

## Testing

Run the test suite:

```bash
python -m pytest tests/test_production_monitoring_system.py -v
```

The test suite covers:

- Monitoring system initialization and lifecycle
- Metrics collection and storage
- Alert generation and resolution
- Health checking functionality
- Data persistence and retrieval
- Integration scenarios