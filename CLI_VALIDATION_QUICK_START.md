# CLI Validation Quick Start Guide

This guide shows you how to use the validation features integrated into the CLI.

## Overview

The CLI now supports comprehensive validation features:

- **Strategy Validation:** Validate generated strategies before testing
- **PCAP Validation:** Validate captured packet files
- **Baseline Comparison:** Compare results with previous runs
- **Baseline Saving:** Save results for future comparison

## Quick Start

### 1. Basic Validation

Enable validation during normal operation:

```bash
python cli.py -t example.com --validate
```

This will:
- Validate generated strategies
- Validate captured PCAP files
- Display validation results in output

### 2. Validate a PCAP File

Validate a specific PCAP file:

```bash
python cli.py --validate-pcap output.pcap
```

This will:
- Validate packet count, sequence numbers, checksums, TTL, TCP flags
- Display detailed validation report
- Save report to `validation_results/pcap_validation_*.json`
- Exit with code 0 (pass) or 1 (fail)

### 3. Save a Baseline

Save test results as a baseline for future comparison:

```bash
python cli.py -t example.com --validate --save-baseline my_baseline
```

This will:
- Run tests with validation enabled
- Save results to `baselines/my_baseline_*.json`
- Display confirmation message

### 4. Compare with Baseline

Compare current results with a saved baseline:

```bash
python cli.py -t example.com --validate --validate-baseline my_baseline
```

This will:
- Run tests with validation enabled
- Compare results with saved baseline
- Display regressions and improvements
- Highlight any failures prominently

### 5. Full Validation Workflow

Complete workflow with baseline tracking:

```bash
# Step 1: Initial run - save baseline
python cli.py -t example.com --validate --save-baseline initial_run

# Step 2: Make changes to code/config

# Step 3: Test run - compare with baseline
python cli.py -t example.com --validate --validate-baseline initial_run

# Step 4: If tests pass, save new baseline
python cli.py -t example.com --validate --save-baseline updated_run
```

## Command-Line Flags

### --validate

Enable validation mode for strategies and PCAP files.

```bash
python cli.py -t example.com --validate
```

**What it does:**
- Validates generated strategies before testing
- Validates captured PCAP files after testing
- Adds validation results to final report

### --validate-pcap FILE

Validate a specific PCAP file and exit.

```bash
python cli.py --validate-pcap output.pcap
```

**What it does:**
- Validates packet structure and content
- Checks sequence numbers, checksums, TTL, TCP flags
- Displays detailed validation report
- Exits with appropriate code

### --validate-baseline NAME

Compare current results with a saved baseline.

```bash
python cli.py -t example.com --validate --validate-baseline baseline_name
```

**What it does:**
- Loads specified baseline from `baselines/` directory
- Compares current results with baseline
- Detects regressions (pass→fail)
- Detects improvements (fail→pass)
- Displays detailed comparison report

**Note:** Requires `--validate` flag to be enabled.

### --save-baseline NAME

Save current results as a new baseline.

```bash
python cli.py -t example.com --validate --save-baseline baseline_name
```

**What it does:**
- Saves current test results to `baselines/` directory
- Creates timestamped baseline file
- Displays confirmation message
- Adds baseline path to final report

**Note:** Requires `--validate` flag to be enabled.

## Output Examples

### Strategy Validation Output

```
[VALIDATION] Validating generated strategies...

Strategy Validation Summary:
  Total strategies: 10
  Valid strategies: 9
  Validation errors: 1
  Validation warnings: 2

✓ Proceeding with 9 validated strategies
```

### PCAP Validation Output

```
[VALIDATION] Validating captured PCAP file...

✓ PCAP validation PASSED
  Packets: 42
  Issues: 0
  Warnings: 1

  Detailed report: validation_results/pcap_validation_20251006_122057.json
```

### Baseline Comparison Output

```
[VALIDATION] Comparing with baseline: initial_run

======================================================================
BASELINE COMPARISON RESULTS
======================================================================
Baseline: initial_run
Baseline Date: 2025-10-06T10:30:00
Current Date: 2025-10-06T12:20:57
Total Tests: 25
Regressions: 0
Improvements: 3
Unchanged: 22

✓ No regressions detected

✓ IMPROVEMENTS:
  [IMPROVEMENT] fake_disorder: Now passing (was failing)
  [IMPROVEMENT] multisplit: Validation improved
  [IMPROVEMENT] sequence_overlap: Execution time reduced by 30%
======================================================================
```

### Regression Detection Output

```
[VALIDATION] Comparing with baseline: previous_run

⚠ REGRESSIONS DETECTED:
  [HIGH] fake_disorder: Test now failing (was passing)
    Details: Packet validation failed - checksum mismatch
  [MEDIUM] multisplit: Execution time increased by 50%
    Details: Performance degradation detected
```

## Validation Reports

All validation operations generate detailed JSON reports:

### PCAP Validation Report

Location: `validation_results/pcap_validation_*.json`

```json
{
  "timestamp": "2025-10-06T12:20:57",
  "pcap_file": "output.pcap",
  "passed": true,
  "packet_count": 42,
  "issues": [],
  "warnings": ["TCP window size unusual"],
  "details": {
    "sequence_validation": "passed",
    "checksum_validation": "passed",
    "ttl_validation": "passed"
  }
}
```

### Baseline Comparison Report

Location: `validation_results/baseline_comparison_*.json`

```json
{
  "baseline_name": "initial_run",
  "baseline_timestamp": "2025-10-06T10:30:00",
  "current_timestamp": "2025-10-06T12:20:57",
  "total_tests": 25,
  "regressions": [],
  "improvements": [
    {
      "attack_name": "fake_disorder",
      "description": "Now passing (was failing)",
      "severity": "info"
    }
  ],
  "unchanged": 22
}
```

## Best Practices

### 1. Always Use --validate for Important Tests

```bash
python cli.py -t production-site.com --validate
```

Ensures strategies and PCAP files are validated before trusting results.

### 2. Save Baselines After Successful Runs

```bash
python cli.py -t example.com --validate --save-baseline working_config
```

Allows you to detect regressions in future runs.

### 3. Compare with Baseline Before Deployment

```bash
python cli.py -t example.com --validate --validate-baseline production_baseline
```

Ensures no regressions before deploying changes.

### 4. Use Descriptive Baseline Names

```bash
--save-baseline v1.0_initial
--save-baseline v1.1_after_fix
--save-baseline production_2025_10_06
```

Makes it easy to identify and compare specific versions.

### 5. Validate PCAP Files Separately

```bash
python cli.py --validate-pcap suspicious_traffic.pcap
```

Useful for debugging or analyzing specific packet captures.

## Troubleshooting

### Validation Modules Not Available

```
[!] Strategy validation skipped: Required modules not available
```

**Solution:** Ensure all dependencies are installed:
```bash
pip install scapy
```

### Baseline Not Found

```
Error: Baseline 'my_baseline' not found
```

**Solution:** Check baseline name and ensure it exists:
```bash
ls baselines/
```

### PCAP File Not Found

```
Error: PCAP file not found: output.pcap
```

**Solution:** Verify file path and ensure PCAP was captured:
```bash
ls -la *.pcap
```

### Validation Fails

```
✗ PCAP validation FAILED
  Errors: 5
```

**Solution:** Check detailed report for specific issues:
```bash
cat validation_results/pcap_validation_*.json
```

## Advanced Usage

### Combine Multiple Flags

```bash
python cli.py -t example.com \
  --validate \
  --save-baseline new_run \
  --validate-baseline old_run \
  --pcap output.pcap
```

This will:
1. Enable validation
2. Compare with old baseline
3. Save new baseline
4. Validate captured PCAP

### Use with Other CLI Features

```bash
python cli.py -t example.com \
  --validate \
  --count 20 \
  --pcap output.pcap \
  --save-baseline comprehensive_test
```

Combines validation with strategy count and PCAP capture.

### Automated Testing

```bash
#!/bin/bash
# Automated validation script

# Run tests with validation
python cli.py -t example.com --validate --save-baseline auto_$(date +%Y%m%d)

# Check exit code
if [ $? -eq 0 ]; then
    echo "Tests passed"
else
    echo "Tests failed"
    exit 1
fi
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Validation Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run validation tests
        run: |
          python cli.py -t test-site.com --validate --save-baseline ci_run
      
      - name: Compare with baseline
        run: |
          python cli.py -t test-site.com --validate --validate-baseline production
      
      - name: Upload validation reports
        uses: actions/upload-artifact@v2
        with:
          name: validation-reports
          path: validation_results/
```

## Summary

The CLI validation features provide:

✅ **Strategy Validation** - Ensure strategies are valid before testing  
✅ **PCAP Validation** - Verify packet captures are correct  
✅ **Baseline Comparison** - Detect regressions automatically  
✅ **Baseline Saving** - Track results over time  
✅ **Detailed Reports** - JSON reports for all validations  
✅ **CI/CD Integration** - Easy to integrate into automated workflows  

Start using validation today to ensure reliable and consistent results!

## Getting Help

For more information:

- See `python cli.py --help` for all available flags
- Check `docs/VALIDATION_PRODUCTION_USER_GUIDE.md` for detailed documentation
- Review `TASK6_CLI_VALIDATION_INTEGRATION_COMPLETE.md` for implementation details
- Run `python test_cli_validation_integration.py` to verify integration

---

**Quick Reference:**

```bash
# Enable validation
--validate

# Validate PCAP file
--validate-pcap FILE

# Compare with baseline
--validate-baseline NAME

# Save baseline
--save-baseline NAME
```
