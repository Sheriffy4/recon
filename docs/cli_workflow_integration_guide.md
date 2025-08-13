# CLI and Workflow Integration Guide

This guide covers the integration of segment-based attacks with existing CLI and workflow systems, providing enhanced monitoring, automation, and reporting capabilities.

## Overview

The Native Attack Orchestration system integrates seamlessly with existing CLI and workflow infrastructure, extending capabilities to support:

- **Enhanced CLI Interface**: Command-line execution of segment-based attacks
- **Workflow Automation**: Automated execution with monitoring and optimization
- **Advanced Reporting**: Comprehensive analysis and visualization
- **Performance Monitoring**: Real-time statistics and metrics collection

## CLI Integration

### Segment Attack CLI

The `SegmentAttackCLI` provides a comprehensive command-line interface for executing and managing segment-based attacks.

#### Available Commands

```bash
# Execute segment-based attack
python -m core.cli.segment_attack_cli execute <attack_type> --target <ip> [options]

# List available attacks
python -m core.cli.segment_attack_cli list [--detailed]

# Benchmark attack performance
python -m core.cli.segment_attack_cli benchmark <attack_type> [options]

# Validate attack configuration
python -m core.cli.segment_attack_cli validate <attack_type> [options]

# Monitor execution statistics
python -m core.cli.segment_attack_cli monitor [options]
```

#### Supported Attack Types

| Attack Type | Description | Key Parameters |
|-------------|-------------|----------------|
| `tcp-timing` | TCP timing manipulation with variable delays | `delay_ms`, `jitter_ms`, `burst_count` |
| `multisplit` | Multi-segment payload splitting with overlap | `split_count`, `overlap_size`, `delay_between_ms` |
| `faked-disorder` | Fake packet disorder technique (zapret-style) | `split_pos`, `fake_ttl`, `disorder_delay_ms` |
| `payload-obfuscation` | Payload obfuscation with encoding segments | `encoding_type`, `chunk_size`, `obfuscation_level` |
| `urgent-pointer` | TCP urgent pointer manipulation | `urgent_offset`, `urgent_data_size` |
| `window-scaling` | TCP window scaling manipulation | `window_size`, `scale_factor`, `dynamic_scaling` |

#### Usage Examples

##### Basic Attack Execution
```bash
# Execute faked-disorder attack against target
python -m core.cli.segment_attack_cli execute faked-disorder \
    --target 192.168.1.1 \
    --port 80 \
    --params split_pos=3 \
    --params fake_ttl=2 \
    --verbose

# Execute with custom payload
python -m core.cli.segment_attack_cli execute multisplit \
    --target 10.0.0.1 \
    --port 443 \
    --payload-file custom_request.txt \
    --params split_count=5 \
    --params overlap_size=20
```

##### Dry Run Testing
```bash
# Test attack logic without sending packets
python -m core.cli.segment_attack_cli execute tcp-timing \
    --target 127.0.0.1 \
    --params delay_ms=10 \
    --params jitter_ms=5 \
    --dry-run \
    --verbose
```

##### Performance Benchmarking
```bash
# Benchmark attack performance
python -m core.cli.segment_attack_cli benchmark faked-disorder \
    --iterations 100 \
    --target 127.0.0.1 \
    --output benchmark_results.json

# Compare multiple attacks
for attack in tcp-timing multisplit faked-disorder; do
    python -m core.cli.segment_attack_cli benchmark $attack \
        --iterations 50 \
        --output "benchmark_${attack}.json"
done
```

##### Configuration Validation
```bash
# Validate attack parameters
python -m core.cli.segment_attack_cli validate multisplit \
    --params split_count=10 \
    --params overlap_size=50 \
    --params delay_between_ms=5

# Validate with verbose output
python -m core.cli.segment_attack_cli validate payload-obfuscation \
    --params encoding_type=base64 \
    --params chunk_size=32 \
    --verbose
```

#### CLI Output Formats

The CLI supports multiple output formats and verbosity levels:

##### Standard Output
```
✅ Attack Execution Results:
   Attack Type: faked-disorder
   Target: 192.168.1.1:80
   Status: SUCCESS
   Execution Time: 45.23ms
   Technique: fakeddisorder
   Packets Sent: 3
   Bytes Sent: 156

📦 Segments Information:
   Count: 3
   Total Payload Size: 156 bytes
   Options Used:
     ttl: [2]
     delay_ms: [5, 10]
```

##### JSON Output
```bash
# Save results to JSON file
python -m core.cli.segment_attack_cli execute tcp-timing \
    --target 192.168.1.1 \
    --output results.json
```

```json
{
  "attack_type": "tcp-timing",
  "target": "192.168.1.1:80",
  "execution_time_ms": 45.23,
  "status": "SUCCESS",
  "technique_used": "tcp_timing_manipulation",
  "packets_sent": 2,
  "bytes_sent": 120,
  "segments_info": {
    "count": 2,
    "total_payload_size": 120,
    "sequence_offsets": [0, 60],
    "options_summary": {
      "delay_ms": [10, 20]
    }
  },
  "performance_metrics": {
    "cache_hit_rate": 0.85,
    "optimization_applied": true
  }
}
```

## Workflow Integration

### Segment Workflow Integration

The `SegmentWorkflowIntegration` class provides advanced workflow automation capabilities.

#### Execution Modes

##### Single-Shot Mode
Execute attacks once with optional concurrency:

```python
from core.workflow.segment_workflow_integration import (
    SegmentWorkflowIntegration,
    SegmentWorkflowConfig,
    WorkflowExecutionMode
)

config = SegmentWorkflowConfig(
    execution_mode=WorkflowExecutionMode.SINGLE_SHOT,
    max_concurrent_attacks=3,
    enable_performance_optimization=True
)

workflow = SegmentWorkflowIntegration(config)

scenarios = [
    {
        'attack_type': 'faked-disorder',
        'target': '192.168.1.1',
        'port': 80,
        'params': {'split_pos': 3, 'fake_ttl': 2}
    },
    {
        'attack_type': 'multisplit',
        'target': '192.168.1.2',
        'port': 443,
        'params': {'split_count': 5}
    }
]

result = await workflow.execute_workflow(scenarios)
```

##### Continuous Mode
Execute attacks continuously with monitoring:

```python
config = SegmentWorkflowConfig(
    execution_mode=WorkflowExecutionMode.CONTINUOUS,
    execution_timeout_seconds=300,
    enable_closed_loop_optimization=True
)

workflow = SegmentWorkflowIntegration(config)
result = await workflow.execute_workflow(scenarios)
```

##### Adaptive Mode
Execute with real-time optimization and adaptation:

```python
config = SegmentWorkflowConfig(
    execution_mode=WorkflowExecutionMode.ADAPTIVE,
    enable_real_time_feedback=True,
    effectiveness_threshold=0.8,
    performance_threshold_ms=50.0
)

workflow = SegmentWorkflowIntegration(config)
result = await workflow.execute_workflow(scenarios)
```

##### Benchmark Mode
Execute for performance benchmarking:

```python
config = SegmentWorkflowConfig(
    execution_mode=WorkflowExecutionMode.BENCHMARK,
    enable_detailed_monitoring=True
)

workflow = SegmentWorkflowIntegration(config)
result = await workflow.execute_workflow(scenarios)
```

#### Workflow Configuration Options

```python
@dataclass
class SegmentWorkflowConfig:
    # Execution settings
    execution_mode: WorkflowExecutionMode = WorkflowExecutionMode.SINGLE_SHOT
    max_concurrent_attacks: int = 5
    execution_timeout_seconds: int = 300
    retry_attempts: int = 3
    
    # Performance optimization
    enable_performance_optimization: bool = True
    optimization_config: OptimizationConfig = field(default_factory=lambda: OptimizationConfig())
    
    # Monitoring and statistics
    enable_detailed_monitoring: bool = True
    statistics_collection_interval: int = 10
    enable_real_time_feedback: bool = True
    
    # Workflow integration
    enable_closed_loop_optimization: bool = True
    effectiveness_threshold: float = 0.7
    performance_threshold_ms: float = 100.0
    
    # Reporting
    enable_workflow_reporting: bool = True
    report_output_directory: str = "workflow_reports"
    save_execution_logs: bool = True
```

#### Progress Monitoring

```python
def progress_callback(progress_data):
    print(f"Progress: {progress_data['scenario_index']}/{progress_data['total_scenarios']}")
    print(f"Current result: {progress_data['current_result']['status']}")

result = await workflow.execute_workflow(scenarios, progress_callback=progress_callback)
```

#### Workflow Results

```python
@dataclass
class WorkflowExecutionResult:
    workflow_id: str
    execution_mode: WorkflowExecutionMode
    start_time: float
    end_time: float
    total_duration: float
    
    # Execution statistics
    attacks_executed: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    success_rate: float = 0.0
    
    # Performance metrics
    average_execution_time_ms: float = 0.0
    total_segments_executed: int = 0
    total_bytes_transmitted: int = 0
    
    # Effectiveness metrics
    average_effectiveness_score: float = 0.0
    effectiveness_scores: List[float] = field(default_factory=list)
    
    # Optimization results
    optimization_applied: bool = False
    performance_improvements: Dict[str, float] = field(default_factory=dict)
    
    # Issues and recommendations
    issues_encountered: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
```

### Convenience Functions

#### Single Attack Execution
```python
from core.workflow.segment_workflow_integration import execute_single_attack_workflow

result = await execute_single_attack_workflow(
    attack_type='faked-disorder',
    target='192.168.1.1',
    port=80,
    params={'split_pos': 3, 'fake_ttl': 2}
)
```

#### Benchmark Execution
```python
from core.workflow.segment_workflow_integration import execute_benchmark_workflow

result = await execute_benchmark_workflow(
    attack_types=['tcp-timing', 'multisplit', 'faked-disorder'],
    target='127.0.0.1',
    iterations=50
)
```

#### Adaptive Execution
```python
from core.workflow.segment_workflow_integration import execute_adaptive_workflow

result = await execute_adaptive_workflow(
    attack_scenarios=scenarios,
    effectiveness_threshold=0.8
)
```

## Reporting Integration

### Segment Reporting Integration

The `SegmentReportingIntegration` class provides comprehensive reporting capabilities.

#### Report Generation

```python
from core.reporting.segment_reporting_integration import (
    SegmentReportingIntegration,
    SegmentReportConfig
)

config = SegmentReportConfig(
    output_directory="reports",
    report_format="html",
    include_detailed_statistics=True,
    generate_charts=True
)

reporter = SegmentReportingIntegration(config)
result = await reporter.generate_comprehensive_report("daily_report")
```

#### Report Formats

##### HTML Reports
- Interactive web-based reports
- Executive summary with key metrics
- Detailed performance analysis
- Attack type breakdown
- Recommendations and insights

##### JSON Reports
- Machine-readable format
- Complete data export
- API integration friendly
- Programmatic analysis support

##### PDF Reports
- Professional presentation format
- Executive summaries
- Print-friendly layouts
- Requires additional dependencies

#### Report Configuration

```python
@dataclass
class SegmentReportConfig:
    # Report generation settings
    include_detailed_statistics: bool = True
    include_performance_metrics: bool = True
    include_effectiveness_analysis: bool = True
    include_segment_breakdown: bool = True
    include_timing_analysis: bool = True
    
    # Visualization settings
    generate_charts: bool = True
    chart_format: str = "png"  # png, svg, pdf
    include_timeline_charts: bool = True
    include_performance_charts: bool = True
    
    # Output settings
    output_directory: str = "segment_reports"
    report_format: str = "html"  # html, json, pdf
    include_raw_data: bool = True
    compress_output: bool = False
    
    # Filtering and aggregation
    time_window_hours: Optional[int] = None
    attack_type_filter: Optional[List[str]] = None
    minimum_effectiveness_threshold: float = 0.0
```

#### Convenience Report Functions

##### Daily Reports
```python
from core.reporting.segment_reporting_integration import generate_daily_segment_report

result = await generate_daily_segment_report(output_dir="daily_reports")
```

##### Performance Analysis
```python
from core.reporting.segment_reporting_integration import generate_performance_analysis_report

result = await generate_performance_analysis_report(
    attack_types=['tcp-timing', 'multisplit'],
    output_dir="performance_reports"
)
```

##### Effectiveness Benchmarks
```python
from core.reporting.segment_reporting_integration import generate_effectiveness_benchmark_report

result = await generate_effectiveness_benchmark_report(
    effectiveness_threshold=0.8,
    output_dir="benchmark_reports"
)
```

## Integration with Existing Systems

### CLI Integration

The segment-based CLI integrates with existing command-line workflows:

```bash
# Integration with existing scripts
#!/bin/bash

# Execute multiple attacks in sequence
attacks=("tcp-timing" "multisplit" "faked-disorder")
target="192.168.1.1"

for attack in "${attacks[@]}"; do
    echo "Executing $attack attack..."
    python -m core.cli.segment_attack_cli execute $attack \
        --target $target \
        --output "results_${attack}.json" \
        --stats
done

# Generate combined report
python -c "
from core.reporting.segment_reporting_integration import generate_daily_segment_report
import asyncio
asyncio.run(generate_daily_segment_report())
"
```

### Workflow System Integration

Integration with existing workflow systems:

```python
# Integration with existing workflow manager
class ExistingWorkflowManager:
    def __init__(self):
        self.segment_workflow = SegmentWorkflowIntegration(
            SegmentWorkflowConfig(
                enable_performance_optimization=True,
                enable_workflow_reporting=True
            )
        )
    
    async def execute_bypass_workflow(self, targets, attack_configs):
        # Convert existing configs to segment scenarios
        scenarios = []
        for target in targets:
            for config in attack_configs:
                scenarios.append({
                    'attack_type': config['type'],
                    'target': target['ip'],
                    'port': target['port'],
                    'params': config['params']
                })
        
        # Execute using segment workflow
        result = await self.segment_workflow.execute_workflow(scenarios)
        
        # Integrate results with existing reporting
        await self.update_existing_reports(result)
        
        return result
```

### Monitoring Integration

Integration with existing monitoring systems:

```python
# Integration with monitoring systems
class MonitoringIntegration:
    def __init__(self, monitoring_client):
        self.monitoring_client = monitoring_client
        self.stats_collector = SegmentExecutionStatsCollector()
    
    async def collect_and_send_metrics(self):
        # Collect segment execution statistics
        stats = self.stats_collector.get_execution_summary()
        
        # Convert to monitoring system format
        metrics = {
            'segment_attacks_executed': len(stats.get('completed_executions', [])),
            'segment_success_rate': self.calculate_success_rate(stats),
            'average_execution_time': self.calculate_avg_time(stats),
            'segments_per_attack': self.calculate_segments_per_attack(stats)
        }
        
        # Send to monitoring system
        await self.monitoring_client.send_metrics(metrics)
```

## Best Practices

### CLI Usage

1. **Use Dry Run for Testing**
   ```bash
   # Always test with dry run first
   python -m core.cli.segment_attack_cli execute faked-disorder \
       --target 192.168.1.1 \
       --dry-run \
       --verbose
   ```

2. **Save Results for Analysis**
   ```bash
   # Save results for later analysis
   python -m core.cli.segment_attack_cli execute multisplit \
       --target 192.168.1.1 \
       --output results.json \
       --stats
   ```

3. **Use Validation Before Execution**
   ```bash
   # Validate configuration first
   python -m core.cli.segment_attack_cli validate tcp-timing \
       --params delay_ms=10 \
       --params jitter_ms=5
   ```

### Workflow Configuration

1. **Start with Single-Shot Mode**
   ```python
   # Begin with simple single-shot execution
   config = SegmentWorkflowConfig(
       execution_mode=WorkflowExecutionMode.SINGLE_SHOT,
       enable_performance_optimization=True
   )
   ```

2. **Enable Monitoring for Production**
   ```python
   # Enable comprehensive monitoring for production
   config = SegmentWorkflowConfig(
       enable_detailed_monitoring=True,
       enable_workflow_reporting=True,
       save_execution_logs=True
   )
   ```

3. **Use Adaptive Mode for Optimization**
   ```python
   # Use adaptive mode for automatic optimization
   config = SegmentWorkflowConfig(
       execution_mode=WorkflowExecutionMode.ADAPTIVE,
       enable_real_time_feedback=True,
       enable_closed_loop_optimization=True
   )
   ```

### Reporting Configuration

1. **Generate Regular Reports**
   ```python
   # Schedule daily reports
   import asyncio
   from core.reporting.segment_reporting_integration import generate_daily_segment_report
   
   async def daily_report_job():
       await generate_daily_segment_report(output_dir="daily_reports")
   
   # Run daily at midnight
   asyncio.run(daily_report_job())
   ```

2. **Use Appropriate Report Formats**
   ```python
   # HTML for human consumption
   html_config = SegmentReportConfig(report_format="html", generate_charts=True)
   
   # JSON for programmatic analysis
   json_config = SegmentReportConfig(report_format="json", include_raw_data=True)
   ```

3. **Filter Reports for Relevance**
   ```python
   # Filter by attack types
   config = SegmentReportConfig(
       attack_type_filter=['tcp-timing', 'multisplit'],
       minimum_effectiveness_threshold=0.7
   )
   ```

## Troubleshooting

### Common CLI Issues

1. **Attack Not Found**
   ```bash
   # List available attacks
   python -m core.cli.segment_attack_cli list --detailed
   ```

2. **Parameter Validation Errors**
   ```bash
   # Validate parameters before execution
   python -m core.cli.segment_attack_cli validate attack_type --params key=value
   ```

3. **Performance Issues**
   ```bash
   # Enable optimization
   python -m core.cli.segment_attack_cli execute attack_type --optimize
   ```

### Workflow Issues

1. **Execution Timeouts**
   ```python
   # Increase timeout
   config = SegmentWorkflowConfig(execution_timeout_seconds=600)
   ```

2. **Memory Issues**
   ```python
   # Reduce concurrency
   config = SegmentWorkflowConfig(max_concurrent_attacks=2)
   ```

3. **Optimization Problems**
   ```python
   # Disable optimization if causing issues
   config = SegmentWorkflowConfig(enable_performance_optimization=False)
   ```

### Reporting Issues

1. **Chart Generation Failures**
   ```python
   # Disable charts if matplotlib unavailable
   config = SegmentReportConfig(generate_charts=False)
   ```

2. **Large Report Files**
   ```python
   # Exclude raw data for smaller files
   config = SegmentReportConfig(include_raw_data=False, compress_output=True)
   ```

3. **Missing Data**
   ```python
   # Check time window settings
   config = SegmentReportConfig(time_window_hours=24)
   ```

## Advanced Usage

### Custom Attack Integration

```python
# Integrate custom attacks with CLI
from core.cli.segment_attack_cli import SegmentAttackCLI

class CustomSegmentAttackCLI(SegmentAttackCLI):
    def __init__(self):
        super().__init__()
        
        # Add custom attacks
        self.segment_attacks['custom-attack'] = {
            'factory': create_custom_attack,
            'description': 'Custom segment-based attack',
            'params': ['custom_param1', 'custom_param2']
        }
```

### Workflow Extensions

```python
# Extend workflow with custom logic
class CustomWorkflowIntegration(SegmentWorkflowIntegration):
    async def _execute_single_scenario(self, scenario, result):
        # Add custom pre-processing
        scenario = await self.preprocess_scenario(scenario)
        
        # Execute with parent logic
        execution_result = await super()._execute_single_scenario(scenario, result)
        
        # Add custom post-processing
        await self.postprocess_result(execution_result)
        
        return execution_result
```

### Custom Reporting

```python
# Custom report generation
class CustomReportingIntegration(SegmentReportingIntegration):
    async def generate_custom_report(self, custom_params):
        # Collect custom data
        report_data = await self._collect_custom_data(custom_params)
        
        # Generate custom format
        return await self._generate_custom_format(report_data)
```

This comprehensive integration enables seamless adoption of segment-based attacks within existing CLI and workflow systems while providing enhanced monitoring, automation, and reporting capabilities.