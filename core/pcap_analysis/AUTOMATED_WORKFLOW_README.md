# Automated PCAP Comparison Workflow

This document describes the automated PCAP comparison workflow system that implements task 18 from the recon-zapret PCAP analysis specification.

## Overview

The automated workflow system provides comprehensive automation for comparing recon and zapret PCAP files, detecting strategy differences, applying fixes, and validating results. It addresses requirements 6.1, 6.2, 6.3, 6.4, and 6.5 from the specification.

## Key Features

- **Automated PCAP Comparison**: Automatically compares recon_x.pcap and zapret_x.pcap files
- **Strategy Difference Detection**: Identifies differences in DPI bypass strategies
- **Automated Fix Application**: Generates and applies code fixes based on analysis
- **Success Validation**: Validates fixes against target domains
- **Batch Processing**: Processes multiple PCAP pairs simultaneously
- **Scheduling**: Supports periodic execution of workflows
- **Integration**: Seamlessly integrates with existing recon components

## Architecture

### Core Components

1. **AutomatedWorkflow**: Main orchestrator for workflow execution
2. **WorkflowConfigManager**: Manages configuration presets and templates
3. **WorkflowScheduler**: Handles scheduled and batch execution
4. **WorkflowIntegration**: High-level integration with recon components

### Workflow Phases

1. **PCAP Analysis**: Compare and analyze PCAP files
2. **Strategy Detection**: Identify strategy differences
3. **Root Cause Analysis**: Determine failure causes
4. **Fix Generation**: Create automated fixes
5. **Validation**: Test fixes against target domains
6. **Reporting**: Generate comprehensive reports

## Usage

### Command Line Interface

```bash
# Quick analysis
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap

# Full analysis with custom domains
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --full --domains x.com twitter.com

# Safe analysis with backups
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --safe

# Batch processing
python automated_pcap_workflow.py --batch pcap_directory/

# Schedule daily analysis
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --schedule daily --hour 2
```

### Python API

```python
from core.pcap_analysis.workflow_integration import run_full_analysis

# Run full analysis
result = await run_full_analysis('recon_x.pcap', 'zapret_x.pcap', ['x.com'])

print(f"Success: {result.success}")
print(f"Fixes applied: {len(result.fixes_applied)}")
```

### Configuration Presets

- **quick**: Fast analysis without fixes or validation
- **full**: Complete analysis with fixes and validation
- **safe**: Safe testing with backups and rollbacks
- **performance**: Performance testing with multiple domains
- **debug**: Debug mode with detailed analysis only

## Configuration

### Basic Configuration

```python
from core.pcap_analysis.automated_workflow import WorkflowConfig

config = WorkflowConfig(
    recon_pcap_path='recon_x.pcap',
    zapret_pcap_path='zapret_x.pcap',
    target_domains=['x.com', 'twitter.com'],
    output_dir='workflow_results',
    enable_auto_fix=True,
    enable_validation=True
)
```

### Advanced Configuration

```python
config = WorkflowConfig(
    recon_pcap_path='recon_x.pcap',
    zapret_pcap_path='zapret_x.pcap',
    target_domains=['x.com'],
    output_dir='advanced_results',
    enable_auto_fix=True,
    enable_validation=True,
    max_fix_attempts=3,
    validation_timeout=300,
    parallel_validation=True,
    backup_before_fix=True,
    rollback_on_failure=True
)
```

## Scheduling

### Daily Scheduling

```python
from core.pcap_analysis.workflow_scheduler import WorkflowScheduler

scheduler = WorkflowScheduler()

# Create daily job at 2 AM
daily_job = scheduler.create_daily_job("Daily Analysis", config, hour=2)
scheduler.add_scheduled_job(daily_job)

await scheduler.start_scheduler()
```

### Interval Scheduling

```python
# Run every 60 minutes
interval_job = scheduler.create_interval_job("Hourly Check", config, 60)
scheduler.add_scheduled_job(interval_job)
```

## Batch Processing

### Directory-based Batch Processing

```python
from core.pcap_analysis.workflow_integration import WorkflowIntegration

integration = WorkflowIntegration()

# Process all PCAP pairs in directory
results = await integration.run_batch_analysis(
    'pcap_directory/',
    target_domains=['x.com', 'twitter.com'],
    max_concurrent=3
)
```

### Custom Batch Jobs

```python
from core.pcap_analysis.workflow_scheduler import BatchJob

batch_job = BatchJob(
    id='custom_batch',
    name='Custom Batch Analysis',
    pcap_pairs=[
        ('recon_x.pcap', 'zapret_x.pcap'),
        ('recon_twitter.pcap', 'zapret_twitter.pcap')
    ],
    base_config=config,
    parallel_execution=True,
    max_concurrent=2
)

results = await scheduler.run_batch_job(batch_job.id)
```

## Integration

### Recon Component Integration

The workflow automatically integrates with existing recon components:

- **Strategy Management**: Updates strategy configurations based on analysis
- **RST Analysis**: Integrates with enhanced_find_rst_triggers.py
- **Attack Systems**: Updates attack implementations with fixes
- **Historical Data**: Correlates with recon_summary.json

### External System Integration

```python
integration_config = {
    'recon_integration': True,
    'auto_apply_fixes': True,
    'notifications': True
}

integration = WorkflowIntegration(integration_config)
```

## Output and Reporting

### Workflow Results

```python
class WorkflowResult:
    success: bool
    execution_time: float
    comparison_result: Optional[Any]
    strategy_differences: Optional[Any]
    fixes_applied: List[str]
    validation_results: Dict[str, Any]
    error_details: Optional[str]
    recommendations: List[str]
```

### Integration Reports

```python
# Generate comprehensive report
report = await integration.generate_integration_report()

print(f"Total workflows: {report['summary']['total_workflows']}")
print(f"Success rate: {report['summary']['success_rate']:.1%}")
print(f"Fixes applied: {report['summary']['total_fixes_applied']}")
```

### Output Files

The workflow generates several output files:

- `pcap_comparison_result.json`: Detailed PCAP comparison
- `strategy_differences.json`: Strategy analysis results
- `root_cause_analysis.json`: Root cause findings
- `applied_fixes.json`: List of applied fixes
- `validation_results.json`: Domain validation results
- `workflow_result_<timestamp>.json`: Complete workflow result
- `latest_result.json`: Most recent workflow result

## Error Handling

### Graceful Degradation

The workflow handles errors gracefully:

- **PCAP Parsing Errors**: Continues with partial data
- **Strategy Analysis Failures**: Uses fallback analysis
- **Fix Application Errors**: Rolls back changes if configured
- **Validation Timeouts**: Reports partial results

### Rollback Mechanism

```python
config = WorkflowConfig(
    # ... other settings ...
    backup_before_fix=True,
    rollback_on_failure=True
)
```

## Performance Optimization

### Parallel Processing

- **Concurrent Validation**: Test multiple domains simultaneously
- **Batch Processing**: Process multiple PCAP pairs in parallel
- **Async Operations**: Non-blocking workflow execution

### Memory Management

- **Streaming Processing**: Handle large PCAP files efficiently
- **Caching**: Cache analysis results for repeated operations
- **Resource Cleanup**: Automatic cleanup of temporary files

## Testing

### Running Tests

```bash
python test_automated_pcap_workflow.py
```

### Test Coverage

- Unit tests for all core components
- Integration tests for workflow execution
- End-to-end tests with mock PCAP data
- Error handling and edge case tests

## Troubleshooting

### Common Issues

1. **PCAP File Not Found**
   - Verify file paths are correct
   - Check file permissions

2. **Validation Timeouts**
   - Increase validation_timeout setting
   - Check network connectivity

3. **Fix Application Failures**
   - Enable backup_before_fix
   - Check file write permissions

4. **Memory Issues with Large PCAPs**
   - Use streaming processing
   - Reduce concurrent operations

### Debug Mode

```bash
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --verbose
```

### Log Analysis

Logs are written to the console and optionally to files:

```bash
python automated_pcap_workflow.py recon_x.pcap zapret_x.pcap --log-file workflow.log
```

## Best Practices

### Configuration

- Use presets for common scenarios
- Enable backups for production use
- Set appropriate timeouts for your environment

### Scheduling

- Schedule during low-traffic periods
- Use safe presets for automated execution
- Monitor scheduled job success rates

### Batch Processing

- Limit concurrent operations based on system resources
- Use parallel processing for independent operations
- Monitor memory usage with large batches

### Integration

- Test fixes in safe environment first
- Monitor validation results regularly
- Keep historical data for trend analysis

## Future Enhancements

- Machine learning for pattern recognition
- Advanced visualization of results
- Real-time monitoring dashboard
- Cloud deployment support
- API endpoints for external integration

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review log files for error details
3. Run tests to verify system integrity
4. Consult the specification documents for requirements

## Files

- `automated_workflow.py`: Main workflow orchestrator
- `workflow_cli.py`: Command-line interface
- `workflow_config_manager.py`: Configuration management
- `workflow_scheduler.py`: Scheduling and batch processing
- `workflow_integration.py`: High-level integration
- `automated_pcap_workflow.py`: Main entry point script
- `test_automated_pcap_workflow.py`: Comprehensive test suite