# CLI Validation Output - Quick Start Guide

## Overview

The enhanced CLI validation output provides clear, color-coded validation reports with multiple output modes.

## Quick Start

### 1. Run Demo

```bash
python demo_cli_validation_output.py
```

This will show you all the different output modes and features.

### 2. Run Tests

```bash
python test_cli_validation_output.py
```

Verify that all features are working correctly.

### 3. Basic Usage

```python
from core.cli_validation_orchestrator import CLIValidationOrchestrator

# Create orchestrator
orchestrator = CLIValidationOrchestrator()

# Create validation report
report = orchestrator.create_validation_report(
    pcap_validation=your_pcap_result,
    strategy_validation=your_strategy_result
)

# Display output
output = orchestrator.format_validation_output(report)
print(output)
```

## Output Modes

### 1. Colored Output (Default)

```python
output = orchestrator.format_validation_output(report, use_colors=True)
print(output)
```

**Features:**
- ✓ Green for success
- ✗ Red for failures
- ⚠ Yellow for warnings
- Clear visual hierarchy

### 2. Plain Text (CI/CD)

```python
output = orchestrator.format_validation_output(report, use_colors=False)
print(output)
```

**Use for:**
- CI/CD pipelines
- Log files
- Environments without color support

### 3. Verbose Mode

```python
output = orchestrator.format_validation_output(
    report, 
    use_colors=True, 
    verbose=True
)
print(output)
```

**Shows:**
- Full error/warning lists
- Detailed validation information
- Additional debugging data

### 4. Rich Output

```python
from rich.console import Console

console = Console()
orchestrator.format_validation_output_rich(report, console)
```

**Features:**
- Professional tables
- Enhanced formatting
- Best for interactive use

### 5. JSON Report

```python
json_path = orchestrator.save_validation_report_json(report)
print(f"Report saved to: {json_path}")
```

**Use for:**
- Automated processing
- Integration with other tools
- Historical tracking

## Common Scenarios

### Scenario 1: Quick Validation Check

```python
orchestrator = CLIValidationOrchestrator()

# Validate PCAP
pcap_result = orchestrator.validate_pcap(Path("test.pcap"))

# Create and display report
report = orchestrator.create_validation_report(pcap_validation=pcap_result)
print(orchestrator.format_validation_output(report))
```

### Scenario 2: Full Validation with Baseline

```python
orchestrator = CLIValidationOrchestrator()

# Validate everything
pcap_result = orchestrator.validate_pcap(Path("test.pcap"))
strategy_result = orchestrator.validate_strategy({"type": "fake", "ttl": 8})
baseline_result = orchestrator.compare_with_baseline(current_results)

# Create comprehensive report
report = orchestrator.create_validation_report(
    pcap_validation=pcap_result,
    strategy_validation=strategy_result,
    baseline_comparison=baseline_result
)

# Display with rich output
from rich.console import Console
console = Console()
orchestrator.format_validation_output_rich(report, console)

# Save JSON report
orchestrator.save_validation_report_json(report)
```

### Scenario 3: CI/CD Integration

```python
import sys

orchestrator = CLIValidationOrchestrator()

# Run validation
report = orchestrator.create_validation_report(
    pcap_validation=pcap_result,
    strategy_validation=strategy_result
)

# Display without colors
output = orchestrator.format_validation_output(report, use_colors=False)
print(output)

# Save JSON for processing
json_path = orchestrator.save_validation_report_json(report)

# Exit with error code if validation failed
all_passed = True
if report.pcap_validation and not report.pcap_validation.passed:
    all_passed = False
if report.strategy_validation and not report.strategy_validation.passed:
    all_passed = False

sys.exit(0 if all_passed else 1)
```

## Output Sections

### 1. Header
- Report title
- Timestamp
- Overall status

### 2. PCAP Validation
- Status (PASSED/FAILED)
- File path
- Packet count
- Issues and warnings

### 3. Strategy Validation
- Status (PASSED/FAILED)
- Strategy type
- Errors and warnings
- Validation details

### 4. Baseline Comparison
- Baseline name
- Total tests
- Regressions
- Improvements
- Unchanged tests

### 5. Summary
- Quick overview
- Key metrics
- Action items

## Customization

### Custom Output Directory

```python
orchestrator = CLIValidationOrchestrator(
    output_dir=Path("my_reports")
)
```

### Custom Baseline Directory

```python
orchestrator = CLIValidationOrchestrator(
    baselines_dir=Path("my_baselines")
)
```

## Tips

1. **Use Rich Output for Interactive Sessions**
   - Better visual formatting
   - Easier to read
   - Professional appearance

2. **Use Plain Text for CI/CD**
   - No color codes in logs
   - Better for automated processing
   - Consistent output

3. **Use Verbose Mode for Debugging**
   - See all details
   - Full error messages
   - Additional context

4. **Save JSON Reports for History**
   - Track validation over time
   - Automated analysis
   - Integration with other tools

5. **Check Overall Status First**
   - Quick pass/fail check
   - Highlighted at top
   - Easy to spot

## Troubleshooting

### Colors Not Showing

```python
# Make sure colors are enabled
output = orchestrator.format_validation_output(report, use_colors=True)
```

### Rich Library Not Available

```python
# Install rich
pip install rich

# Or use plain text output
output = orchestrator.format_validation_output(report)
```

### JSON Report Not Saving

```python
# Check output directory exists
orchestrator.output_dir.mkdir(parents=True, exist_ok=True)

# Or specify custom path
json_path = orchestrator.save_validation_report_json(
    report,
    output_path=Path("my_report.json")
)
```

## Examples

See `demo_cli_validation_output.py` for complete examples of:
- Plain text output with colors
- Verbose output
- JSON report generation
- Rich library output
- Output without colors
- Success and failure cases

## Next Steps

1. Run the demo: `python demo_cli_validation_output.py`
2. Run the tests: `python test_cli_validation_output.py`
3. Integrate into your CLI workflow
4. Customize as needed

## Support

For issues or questions:
1. Check the completion report: `TASK_6.5_CLI_VALIDATION_OUTPUT_COMPLETE.md`
2. Review the demo script: `demo_cli_validation_output.py`
3. Run the test suite: `test_cli_validation_output.py`

---

**Quick Reference:**

```python
# Basic usage
orchestrator = CLIValidationOrchestrator()
report = orchestrator.create_validation_report(...)
print(orchestrator.format_validation_output(report))

# Verbose
print(orchestrator.format_validation_output(report, verbose=True))

# No colors
print(orchestrator.format_validation_output(report, use_colors=False))

# Rich output
orchestrator.format_validation_output_rich(report)

# Save JSON
orchestrator.save_validation_report_json(report)
```
